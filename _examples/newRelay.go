package _examples

import (
	"github.com/peakedshout/go-CFC/tool"
	socks "github.com/peakedshout/go-socks"
	"github.com/peakedshout/go-socks/server"
)

func newRelay() {
	// Note that this is private to the library, don't use it if you mind

	// In general, use the default has had enough schooling, it has built up the CONNECT/BIND/UDPASSOCIATE agent
	// If you need to customize, you can use socks.ListenRelayServer
	// Note that rawKey must be a 32-bit byte
	k := tool.NewId(1)
	rs, _ := socks.ListenRelayServerDefault("127.0.0.1:18000", k)
	defer rs.Close(nil)

	// At the same time, set the RelayConfig value in the socsk server config, like so:
	config := &server.SocksServerConfig{
		RelayConfig: &server.SocksRelayConfig{
			Addr:         "127.0.0.1:18000",
			RawKey:       k,
			KeepEncrypt:  false, //If you want to continue symmetrically encrypted channels, select true, which is enforced in UDPASSOCIATE mode
			RelayTimeout: 0,
		},
	}
	// And then run it
	s2, _ := socks.ListenSocks(config)
	s2.Close(nil)
}
