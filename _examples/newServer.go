package _examples

import (
	socks "github.com/peakedshout/go-socks"
	"github.com/peakedshout/go-socks/server"
	"github.com/peakedshout/go-socks/share"
)

func newServer() {
	// If you're just using CONNECT and don't need authentication,
	// it's the fastest, and it supports CONNECT for socks4 and socks5
	s, _ := socks.ListenSocksDefault(":12345")
	s.Wait()

	// If you want to customize the configuration, create a config to fill in what you need
	// Like this, you support socks5 CONNECT/BIND and whether the user is user/password
	config := &server.SocksServerConfig{
		TlnAddr: ":23333",
		SocksAuthCb: server.SocksAuthCb{
			Socks5AuthPASSWORD: func(password share.Socks5AuthPassword) bool {
				return password.IsEqual("user", "password")
			},
		},
		RelayConfig: nil,
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: false,
			SwitchSocksVersion5: true,
		},
		CMDSwitch: share.SocksCMDSwitch{
			SwitchCMDCONNECT:      true,
			SwitchCMDBIND:         true,
			SwitchCMDUDPASSOCIATE: false,
		},
		ConnTimeout: 0,
		DialTimeout: 0,
		BindTimeout: 0,
	}

	// And then run it
	s2, _ := socks.ListenSocks(config)
	s2.Close(nil)

}
