package socks

import (
	"bytes"
	"net"
	"time"
)

type ServerSimplifyConfig struct {
	SwitchSocksVersion4   bool
	SwitchSocksVersion5   bool
	SwitchCMDCONNECT      bool
	SwitchCMDBIND         bool
	SwitchCMDUDPASSOCIATE bool
	Socks5Auth            *SimplifySocks5Auth
	Socks4Auth            *SimplifySocks4Auth
}

func (ssc ServerSimplifyConfig) Build() *ServerConfig {
	return &ServerConfig{
		VersionSwitch: VersionSwitch{
			SwitchSocksVersion4: ssc.SwitchSocksVersion4,
			SwitchSocksVersion5: ssc.SwitchSocksVersion5,
		},
		CMDConfig: CMDConfig{
			SwitchCMDCONNECT:      ssc.SwitchCMDCONNECT,
			SwitchCMDBIND:         ssc.SwitchCMDBIND,
			SwitchCMDUDPASSOCIATE: ssc.SwitchCMDUDPASSOCIATE,
		},
		Socks5AuthCb: ssc.Socks5Auth.build(),
		Socks4AuthCb: ssc.Socks4Auth.build(),
	}
}

type SimplifySocks5Auth struct {
	User, Password string //socks5
}

func (ss5a *SimplifySocks5Auth) build() S5AuthCb {
	if ss5a == nil {
		return S5AuthCb{Socks5AuthNOAUTH: DefaultAuthConnCb}
	} else {
		return S5AuthCb{Socks5AuthPASSWORD: DefaultAuthPASSWORDCb(func(auth S5AuthPassword) bool {
			return auth.IsEqual(ss5a.User, ss5a.Password)
		})}
	}
}

type SimplifySocks4Auth struct {
	UserId string // socks4
}

func (ss4a *SimplifySocks4Auth) build() S4AuthCb {
	if ss4a == nil {
		return S4AuthCb{Socks4UserIdAuth: nil}
	} else {
		return S4AuthCb{Socks4UserIdAuth: func(conn net.Conn, id S4UserId) (net.Conn, S4IdAuthCode) {
			return id.IsEqual3(conn, S4UserId(ss4a.UserId))
		}}
	}
}

type ServerConfig struct {
	VersionSwitch VersionSwitch //Supported version
	CMDConfig     CMDConfig     //Supported operations

	Socks5AuthCb S5AuthCb
	Socks4AuthCb S4AuthCb
	ConnTimeout  time.Duration //this is the lifetime to complete the configuration
	DialTimeout  time.Duration //This is the time to dial
	BindTimeout  time.Duration //default 5s
	UdpTimeout   time.Duration //default 30s
}

type CMDConfig struct {
	SwitchCMDCONNECT          bool
	CMDCONNECTHandler         CMDCONNECTHandler
	SwitchCMDBIND             bool
	CMDBINDHandler            CMDBINDHandler
	SwitchCMDUDPASSOCIATE     bool
	CMDCMDUDPASSOCIATEHandler CMDCMDUDPASSOCIATEHandler
	UDPDataHandler            UDPDataHandler
}

type VersionSwitch struct {
	SwitchSocksVersion4 bool
	SwitchSocksVersion5 bool
}

type S4AuthCb struct {
	Socks4UserIdAuth func(net.Conn, S4UserId) (net.Conn, S4IdAuthCode)
}

type S4UserId []byte

func (s4uid S4UserId) IsEqual(uid S4UserId) bool {
	return bytes.Equal(s4uid, uid)
}

func (s4uid S4UserId) IsEqual2(uid S4UserId) S4IdAuthCode {
	if bytes.Equal(s4uid, uid) {
		return CodeGranted
	} else {
		return CodeRejectedDifferentUserId
	}
}

func (s4uid S4UserId) IsEqual3(conn net.Conn, uid S4UserId) (net.Conn, S4IdAuthCode) {
	if s4uid.IsEqual2(uid) == CodeGranted {
		return conn, CodeGranted
	} else {
		return nil, CodeRejectedDifferentUserId
	}
}

type S4IdAuthCode byte

const (
	CodeGranted                 S4IdAuthCode = socks4RespCodeGranted                 //request granted
	CodeRejectedFailed          S4IdAuthCode = socks4RespCodeRejectedFailed          //request rejected or failed
	CodeRejectedClientIdentd    S4IdAuthCode = socks4RespCodeRejectedClientIdentd    //request rejected becasue SOCKS server cannot connect to identd on the client
	CodeRejectedDifferentUserId S4IdAuthCode = socks4RespCodeRejectedDifferentUserId //request rejected because the client program and identd report different user-ids

)

// S5AuthCb
//
//	priority determines which validation method is preferred;
//	if the validation method is the same, the one with the smaller code is preferred
type S5AuthCb struct {
	Socks5AuthNOAUTHPriority   int8
	Socks5AuthNOAUTH           func(conn net.Conn) net.Conn
	Socks5AuthGSSAPIPriority   int8
	Socks5AuthGSSAPI           func(conn net.Conn) net.Conn
	Socks5AuthPASSWORDPriority int8
	Socks5AuthPASSWORD         func(conn net.Conn, auth S5AuthPassword) net.Conn
	Socks5AuthIANAPriority     [125]int8
	Socks5AuthIANA             [125]func(conn net.Conn) net.Conn
	Socks5AuthPRIVATEPriority  [127]int8
	Socks5AuthPRIVATE          [127]func(conn net.Conn) net.Conn

	socks5AuthPriority []byte
}

type S5AuthPassword struct {
	User, Password string
	Cb             func(conn net.Conn) net.Conn
}

func (s5ap S5AuthPassword) IsEqual(u, p string) bool {
	return s5ap.User == u && s5ap.Password == p
}

func (s5ap S5AuthPassword) IsEqual2(conn net.Conn, u, p string) net.Conn {
	if s5ap.IsEqual(u, p) {
		return conn
	} else {
		return nil
	}
}

var DefaultSocksCMDConfig = CMDConfig{
	SwitchCMDCONNECT:      true,
	SwitchCMDBIND:         true,
	SwitchCMDUDPASSOCIATE: true,
}

var DefaultSocksVersionSwitch = VersionSwitch{
	SwitchSocksVersion4: true,
	SwitchSocksVersion5: true,
}

var DefaultAuthConnCb = func(conn net.Conn) net.Conn { return conn }

func DefaultAuthPASSWORDCb(fn func(auth S5AuthPassword) bool) func(conn net.Conn, auth S5AuthPassword) net.Conn {
	return func(conn net.Conn, auth S5AuthPassword) net.Conn {
		if fn(auth) {
			return conn
		}
		return nil
	}
}

type BINDAddrCb func(addr net.Addr) error

type UDPDataHandler interface {
	Encode(b []byte) ([]byte, error)
	Decode(b []byte) ([]byte, error)
}
