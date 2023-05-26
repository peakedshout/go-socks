package share

import (
	"bytes"
)

type SocksCMDSwitch struct {
	SwitchCMDCONNECT      bool
	SwitchCMDBIND         bool
	SwitchCMDUDPASSOCIATE bool
}

type SocksVersionSwitch struct {
	SwitchSocksVersion4 bool
	SwitchSocksVersion5 bool
}

type Socks4UserId []byte

func (s4uid Socks4UserId) IsEqual(uid Socks4UserId) bool {
	return bytes.Equal(s4uid, uid)
}
func (s4uid Socks4UserId) IsEqual2(uid Socks4UserId) byte {
	if bytes.Equal(s4uid, uid) {
		return Socks4RespCodeGranted
	} else {
		return Socks4RespCodeRejectedDifferentUserId
	}
}

type Socks5AuthPassword struct {
	User, Password string
}

func (s5ap Socks5AuthPassword) IsEqual(u, p string) bool {
	return s5ap.User == u && s5ap.Password == p
}

var DefaultSocksCMDSwitch = SocksCMDSwitch{
	SwitchCMDCONNECT:      true,
	SwitchCMDBIND:         true,
	SwitchCMDUDPASSOCIATE: true,
}

var DefaultSocksVersionSwitch = SocksVersionSwitch{
	SwitchSocksVersion4: true,
	SwitchSocksVersion5: true,
}
