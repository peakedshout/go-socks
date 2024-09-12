package _examples

import (
	"github.com/peakedshout/go-socks"
	"net"
)

func clientCONNECT() {
	// if socks server is 127.0.0.1:17999

	// This will create a CONNECT for socks4. If the server has a valid userid, you will need to fill it in
	sd, _ := socks.SOCKS4CONNECT("tcp", "127.0.0.1:17999", socks.S4UserId{123, 223}, nil)
	c, _ := sd.Dial("tcp", "123.45.67.89.10111")
	defer c.Close()

	// Note that socks5 needs to validate the user step, if the server does not, then the auth should be filled like this instead of nil
	sd2, _ := socks.SOCKS5CONNECT("tcp", "127.0.0.1:17999", &socks.S5Auth{
		Socks5AuthNOAUTH: socks.DefaultAuthConnCb,
	}, nil)
	c2, _ := sd2.Dial("tcp", "123.45.67.89.10111")
	c2.Close()
}

func clientBIND() {
	// if socks server is 127.0.0.1:17999

	// bindCb will tell you the address the server is listening on, and you should use that address to establish a connection using the address in dial called addr
	// If a non-nil err is returned in a fallback, subsequent steps will stop
	sd, _ := socks.SOCKS4BIND("tcp", "127.0.0.1:17999", socks.S4UserId{123, 223}, nil, func(addr net.Addr) error {
		return nil
	})
	// Note that if the addr used here does not match the actual request to the server listening address, it will be ignored
	c, _ := sd.Dial("tcp", "123.45.67.89.10111")
	defer c.Close()

	// The logic of socks5 is the same as socks4
	sd2, _ := socks.SOCKS5BIND("tcp", "127.0.0.1:17999", &socks.S5Auth{
		Socks5AuthNOAUTH: socks.DefaultAuthConnCb,
	}, nil, func(addr net.Addr) error {
		return nil
	})
	c2, _ := sd2.Dial("tcp", "123.45.67.89.10111")
	defer c2.Close()
}

func clientUDPASSOCIATE() {
	// if socks server is 127.0.0.1:17999

	// UDPASSOCIATE is available only to socks5, and it will obtain net.PacketConn
	sd, _ := socks.SOCKS5UDPASSOCIATE("tcp", "127.0.0.1:17999", &socks.S5Auth{
		Socks5AuthNOAUTH: socks.DefaultAuthConnCb,
	}, nil, nil, nil)
	// Note that addr is the port address to be used by the registration client itself
	// If you're not sure what this means, check out: https://github.com/peakedshout/go-pandorasbox/tree/master/xnet/proxy/socks
	c, _ := sd.ListenPacket("udp", ":8888")
	defer c.Close()
}
