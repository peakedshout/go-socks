package server

import (
	"context"
	"github.com/peakedshout/go-CFC/loger"
	"github.com/peakedshout/go-CFC/tool"
	"github.com/peakedshout/go-socks/share"
	"net"
	"sort"
	"time"
)

type SocksServer struct {
	taddr *net.TCPAddr

	tcpLn *net.TCPListener

	connMap *share.ConnMap

	config *SocksServerConfig

	*tool.CloseWaiter
}
type SocksServerConfig struct {
	TlnAddr string

	SocksAuthCb   SocksAuthCb
	RelayConfig   *SocksRelayConfig        //relay config
	VersionSwitch share.SocksVersionSwitch //Supported version
	CMDSwitch     share.SocksCMDSwitch     //Supported operations
	ConnTimeout   time.Duration            //this is the lifetime to complete the configuration
	DialTimeout   time.Duration            //This is the time to dial
	BindTimeout   time.Duration            //default 5s
}
type SocksRelayConfig struct {
	Addr         string
	RawKey       string
	KeepEncrypt  bool
	RelayTimeout time.Duration

	key tool.Key
}

// SocksAuthCb
//	priority determines which validation method is preferred;
//	if the validation method is the same, the one with the smaller code is preferred
type SocksAuthCb struct {
	Socks4UserIdAuth func(share.Socks4UserId) byte

	Socks5AuthNOAUTHPriority   int8
	Socks5AuthNOAUTH           bool
	Socks5AuthGSSAPIPriority   int8
	Socks5AuthGSSAPI           func(conn net.Conn) bool
	Socks5AuthPASSWORDPriority int8
	Socks5AuthPASSWORD         func(share.Socks5AuthPassword) bool
	Socks5AuthIANAPriority     [125]int8
	Socks5AuthIANA             [125]func(conn net.Conn) bool
	Socks5AuthPRIVATEPriority  [127]int8
	Socks5AuthPRIVATE          [127]func(conn net.Conn) bool

	socks5AuthPriority []byte
}

func NewDefaultSocksServer(addr string) (*SocksServer, error) {
	config := &SocksServerConfig{
		TlnAddr:     addr,
		SocksAuthCb: SocksAuthCb{Socks5AuthNOAUTH: true},
		RelayConfig: nil,
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: true,
			SwitchSocksVersion5: true,
		},
		CMDSwitch:   share.DefaultSocksCMDSwitch,
		ConnTimeout: 0,
		DialTimeout: 0,
	}
	return NewSocksServer(config)
}

func NewSocksServer(config *SocksServerConfig) (*SocksServer, error) {
	if !config.VersionSwitch.SwitchSocksVersion4 && !config.VersionSwitch.SwitchSocksVersion5 {
		err := share.ErrMeaninglessServiceVersion
		loger.SetLogDebug(err)
		return nil, err
	}
	if !config.CMDSwitch.SwitchCMDCONNECT && !config.CMDSwitch.SwitchCMDBIND && !config.CMDSwitch.SwitchCMDUDPASSOCIATE {
		err := share.ErrMeaninglessServiceCmd
		loger.SetLogDebug(err)
		return nil, err
	}
	if config.RelayConfig != nil {
		if len(config.RelayConfig.RawKey) != 32 {
			err := tool.ErrKeyIsNot32Bytes
			loger.SetLogDebug(err)
			return nil, err
		}
		config.RelayConfig.key = tool.NewKey(config.RelayConfig.RawKey)
	}
	if config.BindTimeout == 0 {
		config.BindTimeout = 5 * time.Second
	}
	ss := &SocksServer{
		taddr:       nil,
		tcpLn:       nil,
		connMap:     share.NewConnMap(),
		config:      config,
		CloseWaiter: tool.NewCloseWaiter(),
	}
	ss.AddCloseFn(func() {
		if ss.tcpLn != nil {
			ss.tcpLn.Close()
		}
		ss.connMap.Disable()
		ss.connMap.RangeConn(func(conn net.Conn) bool {
			conn.Close()
			return true
		})
	})

	err := ss.handleSock5AuthPriority()
	if err != nil {
		loger.SetLogDebug(err)
		return nil, err
	}
	go ss.handleTcpLn()

	return ss, nil
}

func (ss *SocksServer) handleTcpLn() error {
	tladdr, err := net.ResolveTCPAddr("", ss.config.TlnAddr)
	if err != nil {
		loger.SetLogDebug(err)
		return err
	}
	ss.taddr = tladdr
	tln, err := net.ListenTCP("tcp", ss.taddr)
	if err != nil {
		loger.SetLogDebug(err)
		return err
	}
	ss.tcpLn = tln
	go func() {
		for {
			conn, err := ss.tcpLn.Accept()
			if err != nil {
				loger.SetLogDebug(err)
				return
			}
			go ss.handleTcpConn(conn)
		}
	}()
	return nil
}
func (ss *SocksServer) handleTcpConn(conn net.Conn) {
	defer conn.Close()

	if !ss.connMap.SetConn(conn) {
		return
	}
	defer ss.connMap.DelConn(conn.RemoteAddr())
	c := &Conn{
		Conn:         conn,
		copyConn:     nil,
		reader:       nil,
		key:          tool.Key{},
		keepEncrypt:  false,
		networkSpeed: tool.NewNetworkSpeedTicker(),
		ctx:          nil,
		ctxCancel:    nil,
		ss:           ss,
	}
	if ss.config.ConnTimeout != 0 {
		c.SetDeadline(time.Now().Add(ss.config.ConnTimeout))
	}
	c.ctx, c.ctxCancel = context.WithCancel(context.Background())
	defer c.Close()
	err := c.handleData()
	if err != nil {
		loger.SetLogDebug(err)
		return
	}
	c.SetDeadline(time.Time{})

	err = c.readToCopy()
	if err != nil {
		loger.SetLogInfo(err)
		return
	}
}

func (ss *SocksServer) handleSock5AuthPriority() error {
	if !ss.config.VersionSwitch.SwitchSocksVersion5 {
		return nil
	}
	type s struct {
		priority int8
		code     byte
	}
	var sl []s
	if ss.config.SocksAuthCb.Socks5AuthNOAUTH {
		sl = append(sl, s{priority: ss.config.SocksAuthCb.Socks5AuthNOAUTHPriority, code: share.Socks5METHODCodeNOAUTH})
	}
	if ss.config.SocksAuthCb.Socks5AuthGSSAPI != nil {
		sl = append(sl, s{priority: ss.config.SocksAuthCb.Socks5AuthGSSAPIPriority, code: share.Socks5METHODCodeGSSAPI})
	}
	if ss.config.SocksAuthCb.Socks5AuthPASSWORD != nil {
		sl = append(sl, s{priority: ss.config.SocksAuthCb.Socks5AuthPASSWORDPriority, code: share.Socks5METHODCodePASSWORD})
	}
	for i, one := range ss.config.SocksAuthCb.Socks5AuthIANA {
		if one != nil {
			sl = append(sl, s{priority: ss.config.SocksAuthCb.Socks5AuthIANAPriority[i], code: byte(share.Socks5METHODCodeIANA + i)})
		}
	}
	for i, one := range ss.config.SocksAuthCb.Socks5AuthPRIVATE {
		if one != nil {
			sl = append(sl, s{priority: ss.config.SocksAuthCb.Socks5AuthPRIVATEPriority[i], code: byte(share.Socks5METHODCodePRIVATE + i)})
		}
	}
	if len(sl) == 0 {
		return share.ErrSocks5NeedMETHODSAuth
	}
	sort.Slice(sl, func(i, j int) bool {
		return sl[i].priority < sl[j].priority
	})
	for _, one := range sl {
		ss.config.SocksAuthCb.socks5AuthPriority = append(ss.config.SocksAuthCb.socks5AuthPriority, one.code)
	}
	return nil
}
