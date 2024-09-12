package _examples

import (
	"github.com/peakedshout/go-socks"
	"net"
)

func newServer() {
	// If you're just using CONNECT and don't need authentication,
	// it's the fastest, and it supports CONNECT for socks4 and socks5
	_ = socks.ListenSocksDefault("tcp", ":12345")

	// If you want to customize the configuration, create a config to fill in what you need
	// Like this, you support socks5 CONNECT/BIND and whether the user is user/password
	_ = socks.ListenAndServe("tcp", ":12345", socks.ServerSimplifyConfig{
		SwitchSocksVersion4:   true,
		SwitchSocksVersion5:   true,
		SwitchCMDCONNECT:      true,
		SwitchCMDBIND:         true,
		SwitchCMDUDPASSOCIATE: true,
		Socks5Auth: &socks.SimplifySocks5Auth{
			User:     "user",
			Password: "password",
		},
		Socks4Auth: &socks.SimplifySocks4Auth{UserId: "123456789"},
	}.Build())

	// If you want more advanced customization, then you need to fill in the configuration yourself
	cfg := &socks.ServerConfig{
		VersionSwitch: socks.VersionSwitch{
			SwitchSocksVersion4: true, // socks4/4a
			SwitchSocksVersion5: true, // socks5
		},
		CMDConfig: socks.CMDConfig{
			SwitchCMDCONNECT:          false, // socks4/4a/5 CMDCONNECT
			CMDCONNECTHandler:         nil,   // if nil, use default handler
			SwitchCMDBIND:             false, // socks4/4a/5 BIND
			CMDBINDHandler:            nil,   // if nil, use default handler
			SwitchCMDUDPASSOCIATE:     false, // socks5 UDPASSOCIATE
			CMDCMDUDPASSOCIATEHandler: nil,   // if nil, use default handler
			UDPDataHandler:            nil,   // if nil, use default handler
		},
		Socks5AuthCb: socks.S5AuthCb{
			Socks5AuthNOAUTHPriority:   0,
			Socks5AuthNOAUTH:           socks.DefaultAuthConnCb,
			Socks5AuthGSSAPIPriority:   0,
			Socks5AuthGSSAPI:           nil,
			Socks5AuthPASSWORDPriority: 0,
			Socks5AuthPASSWORD:         nil,
			Socks5AuthIANAPriority:     [125]int8{},
			Socks5AuthIANA:             [125]func(conn net.Conn) net.Conn{},
			Socks5AuthPRIVATEPriority:  [127]int8{},
			Socks5AuthPRIVATE:          [127]func(conn net.Conn) net.Conn{},
		},
		Socks4AuthCb: socks.S4AuthCb{
			Socks4UserIdAuth: nil,
		},
		ConnTimeout: 0,
		DialTimeout: 0,
		BindTimeout: 0,
		UdpTimeout:  0,
	}
	server, _ := socks.NewServer(cfg)
	defer server.Close()
	// Of course, the server itself can serve multiple addresses
	go server.ListenAndServe("tcp", "0.0.0.0:12345")
	_ = server.ListenAndServe("tcp", "0.0.0.0:12346")
}
