package _examples

import (
	"context"
	"github.com/peakedshout/go-socks"
	"net"
)

func newRelay() {
	// If you want to do some relay service with this, then we'll show you a callback implementation
	// Because it is a callback implementation, this library is very powerful and free.
	// Or check out some implementations of handler_relay.go
	_ = socks.ListenAndServe("tcp", ":12345", &socks.ServerConfig{
		VersionSwitch: socks.VersionSwitch{},
		CMDConfig: socks.CMDConfig{
			SwitchCMDCONNECT: true,
			CMDCONNECTHandler: func(ctx context.Context, addr string) (net.Conn, error) {
				// relay conn , like it:
				dial, err := net.Dial("tcp", "123.45.67.89:1011") // relay server
				if err != nil {
					return nil, err
				}
				// handle something ...
				return dial, nil
			},
			SwitchCMDBIND: true,
			CMDBINDHandler: func(ctx context.Context, ch chan<- net.Conn, raddr string) (laddr net.Addr, err error) {
				// relay conn , like it:
				dial, err := net.Dial("tcp", "123.45.67.89:1011") // relay server
				if err != nil {
					return nil, err
				}
				// handle something ...
				ch <- dial
				addr := new(net.Addr) // relay addr
				return *addr, nil
			},
			SwitchCMDUDPASSOCIATE: true,
			CMDCMDUDPASSOCIATEHandler: func(ctx context.Context, addr net.Addr) (net.PacketConn, error) {
				// todo
				return nil, nil
			},
			UDPDataHandler: nil,
		},
		Socks5AuthCb: socks.S5AuthCb{
			Socks5AuthNOAUTH: socks.DefaultAuthConnCb,
		},
	})
}
