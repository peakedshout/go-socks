package relay

import (
	"bufio"
	"context"
	"github.com/peakedshout/go-CFC/loger"
	"github.com/peakedshout/go-CFC/tool"
	"github.com/peakedshout/go-socks/share"
	"net"
	"time"
)

type ServerConfig struct {
	Addr        string
	RawKey      string
	CMDSwitch   share.SocksCMDSwitch
	ConnTimeout time.Duration
	DialTimeout time.Duration
	BindTimeout time.Duration //default 5s
}

type Server struct {
	addr   net.Addr
	ln     net.Listener
	key    tool.Key
	config *ServerConfig

	connMap *share.ConnMap

	*tool.CloseWaiter
}

func NewDefaultServer(addr, rawKey string) (*Server, error) {
	config := &ServerConfig{
		Addr:        addr,
		RawKey:      rawKey,
		CMDSwitch:   share.DefaultSocksCMDSwitch,
		ConnTimeout: 0,
		DialTimeout: 0,
	}
	return NewServer(config)
}

func NewServer(config *ServerConfig) (*Server, error) {
	if config.BindTimeout == 0 {
		config.BindTimeout = 5 * time.Second
	}
	laddr, err := net.ResolveTCPAddr("", config.Addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return nil, err
	}
	s := &Server{
		addr:        laddr,
		ln:          ln,
		key:         tool.NewKey(config.RawKey),
		config:      config,
		connMap:     share.NewConnMap(),
		CloseWaiter: tool.NewCloseWaiter(),
	}
	s.AddCloseFn(func() {
		s.ln.Close()
		s.connMap.Disable()
		s.connMap.RangeConn(func(conn net.Conn) bool {
			conn.Close()
			return true
		})
	})
	go s.listenTcp()

	return s, nil
}
func (s *Server) listenTcp() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			s.Close(err)
			return
		}
		go s.handleCMDConn(conn)
	}
}

func (s *Server) handleCMDConn(conn net.Conn) {
	c := &Conn{
		Conn:         conn,
		reader:       nil,
		key:          s.key,
		copyConn:     nil,
		networkSpeed: tool.NewNetworkSpeedTicker(),
		keepEncrypt:  false,
		ctx:          nil,
		ctxCancel:    nil,
		s:            s,
	}
	if s.config.ConnTimeout != 0 {
		c.SetDeadline(time.Now().Add(s.config.ConnTimeout))
	}
	c.reader = bufio.NewReader(c)
	c.ctx, c.ctxCancel = context.WithCancel(context.Background())
	defer c.Close()
	if !s.connMap.SetConn(c) {
		return
	}
	defer s.connMap.DelConn(c.RemoteAddr())
	err := c.readCMD()
	if err != nil {
		loger.SetLogInfo(err)
		return
	}
	c.SetDeadline(time.Time{})

	if c.copyConn != nil {
		err = c.readToCopy()
		if err != nil {
			loger.SetLogInfo(err)
			return
		}
	}
	if c.udpConn != nil {
		err = c.readToUdp()
		if err != nil {
			loger.SetLogInfo(err)
			return
		}
	}
}

type Conn struct {
	net.Conn
	reader   *bufio.Reader
	key      tool.Key
	copyConn *share.CopyConn
	udpConn  *share.UdpConn

	networkSpeed tool.NetworkSpeedTicker

	keepEncrypt bool

	ctx       context.Context
	ctxCancel context.CancelFunc

	s *Server
}

func (c *Conn) readCMD() (err error) {
	cMsg, err := c.key.ReadCMsg(c.reader, nil, nil)
	if err != nil {
		loger.SetLogDebug(err)
		return err
	}
	var data any
	defer func() {
		if err != nil {
			c.writeCMsg(cMsg.Header, cMsg.Id, 400, err)
		} else {
			err = c.writeCMsg(cMsg.Header, cMsg.Id, 200, data)
			if err != nil {
				loger.SetLogDebug(err)
			}
		}
	}()
	switch cMsg.Header {
	case share.HeaderCMDCONNECT:
		if !c.s.config.CMDSwitch.SwitchCMDCONNECT {
			err = share.ErrCmdNotSupport
			loger.SetLogDebug(err)
			return
		}
		var info share.CMDInfo
		err := cMsg.Unmarshal(&info)
		if err != nil {
			loger.SetLogDebug(err)
			return err
		}
		c.keepEncrypt = info.KeepEncrypt
		dr := net.Dialer{Timeout: c.s.config.DialTimeout}
		conn, err := dr.DialContext(c.ctx, "tcp", info.Addr)
		if err != nil {
			loger.SetLogDebug(err)
			return err
		}
		c.copyConn = share.NewCopyConn(conn)
		go c.readFromCopy()
	case share.HeaderCMDBIND:
		if !c.s.config.CMDSwitch.SwitchCMDBIND {
			err = share.ErrCmdNotSupport
			loger.SetLogDebug(err)
			return
		}
		err = c.listenBindConn(cMsg)
		if err != nil {
			loger.SetLogDebug(err)
			return
		}
		select {
		case <-c.ctx.Done():
		case <-time.After(c.s.config.BindTimeout):
			err = share.ErrTimeout
			loger.SetLogDebug(err)
			return err
		}
		if c.copyConn == nil {
			return net.ErrClosed
		}
		go c.readFromCopy()
		data = share.CMDInfo{Addr: c.copyConn.RemoteAddr().String()}
	case share.HeaderCMDUDPASSOCIATE:
		if !c.s.config.CMDSwitch.SwitchCMDUDPASSOCIATE {
			err = share.ErrCmdNotSupport
			loger.SetLogDebug(err)
			return
		}
		err := c.listenUdpConn(cMsg)
		if err != nil {
			loger.SetLogDebug(err)
			return err
		}
		data = share.CMDInfo{Addr: c.udpConn.LocalAddr().String(), KeepEncrypt: true}
	case share.HeaderPing:
	default:
		return share.ErrHeaderInvalid
	}
	return nil
}

func (c *Conn) listenBindConn(cMsg tool.ConnMsg) error {
	var info share.CMDInfo
	err := cMsg.Unmarshal(&info)
	if err != nil {
		loger.SetLogTrace(err)
		return err
	}
	c.keepEncrypt = info.KeepEncrypt
	lner := net.ListenConfig{}
	ln, err := lner.Listen(c.ctx, "tcp", "")
	if err != nil {
		return err
	}
	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				loger.SetLogTrace(err)
				return
			}
			if conn.RemoteAddr().String() != info.Addr {
				conn.Close()
			} else {
				c.copyConn = share.NewCopyConn(conn)
				c.ctxCancel()
				break
			}
		}
	}()
	return c.writeCMsg(cMsg.Header, cMsg.Id, 200, share.CMDInfo{Addr: ln.Addr().String()})
}
func (c *Conn) listenUdpConn(cMsg tool.ConnMsg) error {
	lner := net.ListenConfig{}
	pconn, err := lner.ListenPacket(c.ctx, "udp", "")
	if err != nil {
		loger.SetLogTrace(err)
		return err
	}
	c.udpConn = share.NewUdpConn(pconn, nil)
	go func() {
		defer c.udpConn.Close()
		for {
			buf := make([]byte, share.DefaultBufferSize)
			n, addr, err := c.udpConn.ReadFrom(buf)
			if err != nil {
				loger.SetLogTrace(err)
				return
			}
			err = c.writeCMsg(share.HeaderPacket, "", 200, share.UdpPacket{
				Addr: addr.(*net.UDPAddr),
				Data: buf[:n],
			})
			if err != nil {
				loger.SetLogTrace(err)
				return
			}
		}
	}()
	return nil
}

func (c *Conn) readToCopy() error {
	for {
		var b []byte
		if c.keepEncrypt {
			bs, err := c.readCMsgStream()
			if err != nil {
				loger.SetLogDebug(err)
				return err
			}
			b = bs
		} else {
			buf := make([]byte, share.DefaultBufferSize)
			n, err := c.Read(buf)
			if err != nil {
				loger.SetLogDebug(err)
				return err
			}
			b = buf[:n]
		}
		_, err := c.copyConn.Write(b)
		if err != nil {
			loger.SetLogDebug(err)
			return err
		}
	}
}
func (c *Conn) readToUdp() error {
	for {
		bs, err := c.readCMsgPacket()
		if err != nil {
			loger.SetLogDebug(err)
			return err
		}
		_, err = c.udpConn.WriteTo(bs.Data, bs.Addr)
		if err != nil {
			loger.SetLogDebug(err)
			return err
		}
	}
}

func (c *Conn) readFromCopy() error {
	for {
		buf := make([]byte, share.DefaultBufferSize)
		n, err := c.copyConn.Read(buf)
		if err != nil {
			loger.SetLogDebug(err)
			return err
		}
		if c.keepEncrypt {
			err = c.writeCMsg(share.HeaderStream, "", 200, buf[:n])
			if err != nil {
				loger.SetLogDebug(err)
				return err
			}
		} else {
			_, err = c.Write(buf[:n])
			if err != nil {
				loger.SetLogDebug(err)
				return err
			}
		}
	}
}

func (c *Conn) writeCMsg(header string, id string, code int, data interface{}) error {
	bs := c.key.SetMsg(header, id, code, data)
	for _, one := range bs {
		_, err := c.Write(one)
		if err != nil {
			return err
		}
	}
	return nil
}
func (c *Conn) readCMsgStream() ([]byte, error) {
	cMsg, err := c.key.ReadCMsg(c.reader, nil, nil)
	if err != nil {
		return nil, err
	}
	err = cMsg.CheckConnMsgHeaderAndCode(share.HeaderStream, 200)
	if err != nil {
		return nil, err
	}
	var b []byte
	err = cMsg.Unmarshal(&b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
func (c *Conn) readCMsgPacket() (packet *share.UdpPacket, err error) {
	cMsg, err := c.key.ReadCMsg(c.reader, nil, nil)
	if err != nil {
		return nil, err
	}
	err = cMsg.CheckConnMsgHeaderAndCode(share.HeaderPacket, 200)
	if err != nil {
		return nil, err
	}
	var info share.UdpPacket
	err = cMsg.Unmarshal(&info)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if err != nil {
		return 0, err
	}
	c.networkSpeed.Upload.Set(n)
	return n, err
}
func (c *Conn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err != nil {
		return 0, err
	}
	c.networkSpeed.Download.Set(n)
	return n, err
}
func (c *Conn) Close() error {
	c.ctxCancel()
	if c.copyConn != nil {
		c.copyConn.Close()
	}
	if c.udpConn != nil {
		c.udpConn.Close()
	}
	return c.Conn.Close()
}
