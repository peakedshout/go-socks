package _examples

import (
	socks "github.com/peakedshout/go-socks"
	"github.com/peakedshout/go-socks/client"
	"github.com/peakedshout/go-socks/share"
	"net"
)

func clientCONNECT() {
	// if socks server is 127.0.0.1:17999

	// This will create a CONNECT for socks4. If the server has a valid userid, you will need to fill it in
	sd, _ := socks.Socks4CONNECT("127.0.0.1:17999", share.Socks4UserId{123, 223}, nil)
	c, _ := sd.Dial("tcp", "123.45.67.89.10111")
	defer c.Close()

	// Note that socks5 needs to validate the user step, if the server does not, then the auth should be filled like this instead of nil
	sd2, _ := socks.Socks5CONNECT("127.0.0.1:17999", &client.Socks5Auth{
		Socks5AuthNOAUTH: true,
	}, nil)
	c2, _ := sd2.Dial("tcp", "123.45.67.89.10111")
	c2.Close()
}

func clientBIND() {
	// if socks server is 127.0.0.1:17999

	// bindCb will tell you the address the server is listening on, and you should use that address to establish a connection using the address in dial called addr
	// If a non-nil err is returned in a fallback, subsequent steps will stop
	sd, _ := socks.Socks4BIND("127.0.0.1:17999", share.Socks4UserId{123, 223}, nil, func(addr net.Addr) error {
		return nil
	})
	// Note that if the addr used here does not match the actual request to the server listening address, it will be ignored
	c, _ := sd.Dial("tcp", "123.45.67.89.10111")
	defer c.Close()

	// The logic of socks5 is the same as socks4
	sd2, _ := socks.Socks5BIND("127.0.0.1:17999", &client.Socks5Auth{
		Socks5AuthNOAUTH: true,
	}, nil, func(addr net.Addr) error {
		return nil
	})
	c2, _ := sd2.Dial("tcp", "123.45.67.89.10111")
	defer c2.Close()
}

func clientUDPASSOCIATE() {
	// if socks server is 127.0.0.1:17999

	// UDPASSOCIATE is available only to socks5, and it will obtain net.PacketConn
	sd, _ := socks.Socks5UDPASSOCIATE("127.0.0.1:17999", &client.Socks5Auth{
		Socks5AuthNOAUTH: true,
	}, nil, nil)
	// Note that addr is the port address to be used by the registration client itself
	c, _ := sd.DialUDP("udp", ":8888")
	defer c.Close()
}
