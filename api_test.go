package go_socks

import (
	"errors"
	"fmt"
	"github.com/peakedshout/go-CFC/tool"
	"github.com/peakedshout/go-socks/client"
	"github.com/peakedshout/go-socks/server"
	"github.com/peakedshout/go-socks/share"
	"golang.org/x/net/proxy"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

func randPort() int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(10000) + 9999
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func newTcpServer() net.Listener {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: 0,
		Zone: "",
	})
	checkErr(err)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn2 net.Conn) {
				defer conn2.Close()
				io.Copy(conn2, conn2)
			}(conn)
		}
	}()
	return ln
}

func newUdpServer() net.PacketConn {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: 0,
		Zone: "",
	})
	checkErr(err)
	go func() {
		for {
			buf := make([]byte, 4096)
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			conn.WriteTo(buf[:n], addr)
		}
	}()
	return conn
}

func TestProxySocks5(t *testing.T) {
	ln := newTcpServer()
	defer ln.Close()
	s, err := ListenSocksDefault("127.0.0.1:17999")
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)
	dr, err := proxy.SOCKS5("tcp", "127.0.0.1:17999", nil, nil)
	checkErr(err)
	c, err := dr.Dial("tcp", ln.Addr().String())
	checkErr(err)
	defer c.Close()
	data := "Hello world!"
	_, err = c.Write([]byte(data))
	checkErr(err)
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	checkErr(err)
	if data != string(buf[:n]) {
		panic("data is bad")
	}
}

func TestListenSocks(t *testing.T) {
	s, err := ListenSocksDefault(":12345")
	if err != nil {
		panic(err)
	}
	go func() {
		time.Sleep(3 * time.Second)
		s.Close(errors.New("123"))
	}()

	err = s.Wait()
	fmt.Println(err)
}

func TestSocks4ConnCONNECT(t *testing.T) {
	ln := newTcpServer()
	defer ln.Close()
	s, err := ListenSocksDefault("127.0.0.1:17999")
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)
	sd, err := Socks4CONNECT("127.0.0.1:17999", share.Socks4UserId{123, 223}, nil)
	checkErr(err)
	c, err := sd.Dial("tcp", ln.Addr().String())
	checkErr(err)
	defer c.Close()
	data := "Hello world!"
	_, err = c.Write([]byte(data))
	checkErr(err)
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	checkErr(err)
	if data != string(buf[:n]) {
		panic("data is bad")
	}
}

func TestSocks5CONNECT(t *testing.T) {
	ln := newTcpServer()
	defer ln.Close()
	s, err := ListenSocksDefault("127.0.0.1:17999")
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)
	sd, err := Socks5CONNECT("127.0.0.1:17999", &client.Socks5Auth{
		Socks5AuthNOAUTH: true,
	}, nil)
	checkErr(err)
	c, err := sd.Dial("tcp", ln.Addr().String())
	checkErr(err)
	defer c.Close()
	data := "Hello world!"
	_, err = c.Write([]byte(data))
	checkErr(err)
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	checkErr(err)
	if data != string(buf[:n]) {
		panic("data is bad")
	}
}

func TestSocks4BIND(t *testing.T) {
	taddr := &net.TCPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: randPort(),
		Zone: "",
	}
	dr := net.Dialer{LocalAddr: taddr}

	config := &server.SocksServerConfig{
		TlnAddr: "127.0.0.1:17999",
		SocksAuthCb: server.SocksAuthCb{
			Socks4UserIdAuth:         nil,
			Socks5AuthNOAUTHPriority: 0,
			Socks5AuthNOAUTH:         true,
		},
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: true,
			SwitchSocksVersion5: true,
		},
		CMDSwitch: share.SocksCMDSwitch{
			SwitchCMDCONNECT:      true,
			SwitchCMDBIND:         true,
			SwitchCMDUDPASSOCIATE: true,
		},
	}
	wg := sync.WaitGroup{}
	data := "Hello world!"
	s, err := ListenSocks(config)
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)
	sd, err := Socks4BIND("127.0.0.1:17999", share.Socks4UserId{123, 223}, nil, func(addr net.Addr) error {
		go func() {
			wg.Add(1)
			conn, err := dr.Dial("tcp", addr.String())
			checkErr(err)
			defer conn.Close()
			conn.Write([]byte(data))
			time.Sleep(1 * time.Second)
			wg.Done()
		}()
		return nil
	})
	checkErr(err)
	c, err := sd.Dial("tcp", taddr.String())
	checkErr(err)
	defer c.Close()
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	checkErr(err)
	if data != string(buf[:n]) {
		panic("data is bad")
	}
	wg.Wait()
}

func TestSocks5BIND(t *testing.T) {
	taddr := &net.TCPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: randPort(),
		Zone: "",
	}
	dr := net.Dialer{LocalAddr: taddr}

	config := &server.SocksServerConfig{
		TlnAddr: "127.0.0.1:17999",
		SocksAuthCb: server.SocksAuthCb{
			Socks4UserIdAuth:         nil,
			Socks5AuthNOAUTHPriority: 0,
			Socks5AuthNOAUTH:         true,
		},
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: true,
			SwitchSocksVersion5: true,
		},
		CMDSwitch: share.SocksCMDSwitch{
			SwitchCMDCONNECT:      true,
			SwitchCMDBIND:         true,
			SwitchCMDUDPASSOCIATE: true,
		},
	}
	wg := sync.WaitGroup{}
	data := "Hello world!"
	s, err := ListenSocks(config)
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)
	sd, err := Socks5BIND("127.0.0.1:17999", &client.Socks5Auth{
		Socks5AuthNOAUTH: true,
	}, nil, func(addr net.Addr) error {
		go func() {
			wg.Add(1)
			conn, err := dr.Dial("tcp", addr.String())
			checkErr(err)
			defer conn.Close()
			conn.Write([]byte(data))
			time.Sleep(1 * time.Second)
			wg.Done()
		}()
		return nil
	})
	checkErr(err)
	c, err := sd.Dial("tcp", taddr.String())
	checkErr(err)
	defer c.Close()
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	checkErr(err)
	if data != string(buf[:n]) {
		panic("data is bad")
	}
	wg.Wait()
}

func TestSocks5UDPASSOCIATE(t *testing.T) {
	ln := newUdpServer()
	defer ln.Close()

	config := &server.SocksServerConfig{
		TlnAddr: "127.0.0.1:17999",
		SocksAuthCb: server.SocksAuthCb{
			Socks4UserIdAuth:         nil,
			Socks5AuthNOAUTHPriority: 0,
			Socks5AuthNOAUTH:         true,
		},
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: true,
			SwitchSocksVersion5: true,
		},
		CMDSwitch: share.SocksCMDSwitch{
			SwitchCMDCONNECT:      true,
			SwitchCMDBIND:         true,
			SwitchCMDUDPASSOCIATE: true,
		},
	}
	s, err := ListenSocks(config)
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)
	data := "Hello world!"

	sd, err := Socks5UDPASSOCIATE("127.0.0.1:17999", &client.Socks5Auth{
		Socks5AuthNOAUTH: true,
	}, nil, nil)
	checkErr(err)
	c, err := sd.DialUDP("udp", ":8888")
	checkErr(err)
	defer c.Close()
	_, err = c.WriteTo([]byte(data), ln.LocalAddr())
	checkErr(err)
	buf := make([]byte, 4096)
	n, addr, err := c.ReadFrom(buf)
	checkErr(err)
	if data != string(buf[:n]) || addr.String() != ln.LocalAddr().String() {
		panic("data is bad")
	}

}

func TestSocks4UserId(t *testing.T) {
	ln := newTcpServer()
	defer ln.Close()
	config := &server.SocksServerConfig{
		TlnAddr: "127.0.0.1:17999",
		SocksAuthCb: server.SocksAuthCb{
			Socks4UserIdAuth: func(id share.Socks4UserId) byte {
				return id.IsEqual2(share.Socks4UserId{123, 223})
			},
			Socks5AuthNOAUTHPriority: 0,
			Socks5AuthNOAUTH:         true,
		},
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: true,
			SwitchSocksVersion5: true,
		},
		CMDSwitch: share.SocksCMDSwitch{
			SwitchCMDCONNECT:      true,
			SwitchCMDBIND:         true,
			SwitchCMDUDPASSOCIATE: true,
		},
	}
	s, err := ListenSocks(config)
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)
	sd, err := Socks4CONNECT("127.0.0.1:17999", share.Socks4UserId{123, 223}, nil)
	checkErr(err)
	c, err := sd.Dial("tcp", ln.Addr().String())
	checkErr(err)
	defer c.Close()
	data := "Hello world!"
	_, err = c.Write([]byte(data))
	checkErr(err)
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	checkErr(err)
	if data != string(buf[:n]) {
		panic("data is bad")
	}
}

func TestSocks5Auth(t *testing.T) {
	ln := newTcpServer()
	defer ln.Close()
	config := &server.SocksServerConfig{
		TlnAddr: "127.0.0.1:17999",
		SocksAuthCb: server.SocksAuthCb{
			Socks4UserIdAuth: nil,
			Socks5AuthPASSWORD: func(password share.Socks5AuthPassword) bool {
				return password.IsEqual("123", "456")
			},
		},
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: true,
			SwitchSocksVersion5: true,
		},
		CMDSwitch: share.SocksCMDSwitch{
			SwitchCMDCONNECT:      true,
			SwitchCMDBIND:         true,
			SwitchCMDUDPASSOCIATE: true,
		},
	}
	s, err := ListenSocks(config)
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)
	sd, err := Socks5CONNECT("127.0.0.1:17999", &client.Socks5Auth{
		Socks5AuthPASSWORD: &share.Socks5AuthPassword{
			User:     "123",
			Password: "456",
		},
	}, nil)
	checkErr(err)
	c, err := sd.Dial("tcp", ln.Addr().String())
	checkErr(err)
	defer c.Close()
	data := "Hello world!"
	_, err = c.Write([]byte(data))
	checkErr(err)
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	checkErr(err)
	if data != string(buf[:n]) {
		panic("data is bad")
	}
}

func TestSocks5Auth2(t *testing.T) {
	ln := newTcpServer()
	defer ln.Close()
	config := &server.SocksServerConfig{
		TlnAddr: "127.0.0.1:17999",
		SocksAuthCb: server.SocksAuthCb{
			Socks4UserIdAuth: nil,
			Socks5AuthPASSWORD: func(password share.Socks5AuthPassword) bool {
				return password.IsEqual("123", "456")
			},
		},
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: true,
			SwitchSocksVersion5: true,
		},
		CMDSwitch: share.SocksCMDSwitch{
			SwitchCMDCONNECT:      true,
			SwitchCMDBIND:         true,
			SwitchCMDUDPASSOCIATE: true,
		},
	}
	s, err := ListenSocks(config)
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)
	dr, err := proxy.SOCKS5("tcp", "127.0.0.1:17999", &proxy.Auth{
		User:     "123",
		Password: "456",
	}, nil)
	checkErr(err)
	c, err := dr.Dial("tcp", ln.Addr().String())
	checkErr(err)
	defer c.Close()
	data := "Hello world!"
	_, err = c.Write([]byte(data))
	checkErr(err)
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	checkErr(err)
	if data != string(buf[:n]) {
		panic("data is bad")
	}
}

func TestSocks5RelayCONNECT(t *testing.T) {
	k := tool.NewId(1)
	rs, err := ListenRelayServerDefault("127.0.0.1:18000", k)
	checkErr(err)
	defer rs.Close(nil)
	ln := newTcpServer()
	defer ln.Close()
	config := &server.SocksServerConfig{
		TlnAddr: "127.0.0.1:17999",
		SocksAuthCb: server.SocksAuthCb{
			Socks4UserIdAuth: nil,
			Socks5AuthPASSWORD: func(password share.Socks5AuthPassword) bool {
				return password.IsEqual("123", "456")
			},
		},
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: true,
			SwitchSocksVersion5: true,
		},
		CMDSwitch: share.SocksCMDSwitch{
			SwitchCMDCONNECT:      true,
			SwitchCMDBIND:         true,
			SwitchCMDUDPASSOCIATE: true,
		},
		RelayConfig: &server.SocksRelayConfig{
			Addr:         "127.0.0.1:18000",
			RawKey:       k,
			KeepEncrypt:  true,
			RelayTimeout: 0,
		},
	}
	s, err := ListenSocks(config)
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)

	sd, err := Socks5CONNECT("127.0.0.1:17999", &client.Socks5Auth{
		Socks5AuthPASSWORD: &share.Socks5AuthPassword{
			User:     "123",
			Password: "456",
		},
	}, nil)
	checkErr(err)
	c, err := sd.Dial("tcp", ln.Addr().String())
	checkErr(err)
	defer c.Close()
	data := "Hello world!"
	_, err = c.Write([]byte(data))
	checkErr(err)
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	checkErr(err)
	if data != string(buf[:n]) {
		panic("data is bad")
	}
}

func TestSocks5RelayBIND(t *testing.T) {
	k := tool.NewId(1)
	rs, err := ListenRelayServerDefault("127.0.0.1:18000", k)
	checkErr(err)
	defer rs.Close(nil)
	taddr := &net.TCPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: randPort(),
		Zone: "",
	}
	dr := net.Dialer{LocalAddr: taddr}
	data := "Hello world!"
	wg := sync.WaitGroup{}

	config := &server.SocksServerConfig{
		TlnAddr: "127.0.0.1:17999",
		SocksAuthCb: server.SocksAuthCb{
			Socks4UserIdAuth: nil,
			Socks5AuthPASSWORD: func(password share.Socks5AuthPassword) bool {
				return password.IsEqual("123", "456")
			},
		},
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: true,
			SwitchSocksVersion5: true,
		},
		CMDSwitch: share.SocksCMDSwitch{
			SwitchCMDCONNECT:      true,
			SwitchCMDBIND:         true,
			SwitchCMDUDPASSOCIATE: true,
		},
		RelayConfig: &server.SocksRelayConfig{
			Addr:         "127.0.0.1:18000",
			RawKey:       k,
			KeepEncrypt:  true,
			RelayTimeout: 0,
		},
	}
	s, err := ListenSocks(config)
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)
	sd, err := Socks5BIND("127.0.0.1:17999", &client.Socks5Auth{
		Socks5AuthPASSWORD: &share.Socks5AuthPassword{
			User:     "123",
			Password: "456",
		},
	}, nil, func(addr net.Addr) error {
		go func() {
			wg.Add(1)
			conn, err := dr.Dial("tcp", addr.String())
			checkErr(err)
			defer conn.Close()
			time.Sleep(1 * time.Second)
			conn.Write([]byte(data))
			wg.Done()
		}()
		return nil
	})
	checkErr(err)
	c, err := sd.Dial("tcp", taddr.String())
	checkErr(err)
	defer c.Close()
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	checkErr(err)
	if data != string(buf[:n]) {
		panic("data is bad")
	}
	wg.Wait()
}

func TestSocks5RelayUDPASSOCIATE(t *testing.T) {
	ln := newUdpServer()
	defer ln.Close()

	k := tool.NewId(1)
	rs, err := ListenRelayServerDefault("127.0.0.1:18000", k)
	checkErr(err)
	defer rs.Close(nil)
	config := &server.SocksServerConfig{
		TlnAddr: "127.0.0.1:17999",
		SocksAuthCb: server.SocksAuthCb{
			Socks4UserIdAuth: nil,
			Socks5AuthPASSWORD: func(password share.Socks5AuthPassword) bool {
				return password.IsEqual("123", "456")
			},
		},
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: true,
			SwitchSocksVersion5: true,
		},
		CMDSwitch: share.SocksCMDSwitch{
			SwitchCMDCONNECT:      true,
			SwitchCMDBIND:         true,
			SwitchCMDUDPASSOCIATE: true,
		},
		RelayConfig: &server.SocksRelayConfig{
			Addr:         "127.0.0.1:18000",
			RawKey:       k,
			KeepEncrypt:  true,
			RelayTimeout: 0,
		},
	}
	s, err := ListenSocks(config)
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)
	data := "Hello world!"

	sd, err := Socks5UDPASSOCIATE("127.0.0.1:17999", &client.Socks5Auth{
		Socks5AuthPASSWORD: &share.Socks5AuthPassword{
			User:     "123",
			Password: "456",
		},
	}, nil, nil)
	checkErr(err)
	c, err := sd.DialUDP("udp", ":8888")
	checkErr(err)
	defer c.Close()
	_, err = c.WriteTo([]byte(data), ln.LocalAddr())
	checkErr(err)
	buf := make([]byte, 4096)
	n, addr, err := c.ReadFrom(buf)
	checkErr(err)
	if data != string(buf[:n]) || addr.String() != ln.LocalAddr().String() {
		panic("data is bad")
	}
}

func TestSocks4RelayCONNECT(t *testing.T) {
	k := tool.NewId(1)
	rs, err := ListenRelayServerDefault("127.0.0.1:18000", k)
	checkErr(err)
	defer rs.Close(nil)
	ln := newTcpServer()
	defer ln.Close()
	config := &server.SocksServerConfig{
		TlnAddr: "127.0.0.1:17999",
		SocksAuthCb: server.SocksAuthCb{
			Socks4UserIdAuth: func(id share.Socks4UserId) byte {
				return id.IsEqual2(share.Socks4UserId{123, 223})
			},
			Socks5AuthPASSWORD: func(password share.Socks5AuthPassword) bool {
				return password.IsEqual("123", "456")
			},
		},
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: true,
			SwitchSocksVersion5: true,
		},
		CMDSwitch: share.SocksCMDSwitch{
			SwitchCMDCONNECT:      true,
			SwitchCMDBIND:         true,
			SwitchCMDUDPASSOCIATE: true,
		},
		RelayConfig: &server.SocksRelayConfig{
			Addr:         "127.0.0.1:18000",
			RawKey:       k,
			KeepEncrypt:  true,
			RelayTimeout: 0,
		},
	}
	s, err := ListenSocks(config)
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)

	sd, err := Socks4CONNECT("127.0.0.1:17999", share.Socks4UserId{123, 223}, nil)
	checkErr(err)
	c, err := sd.Dial("tcp", ln.Addr().String())
	checkErr(err)
	defer c.Close()
	data := "Hello world!"
	_, err = c.Write([]byte(data))
	checkErr(err)
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	checkErr(err)
	if data != string(buf[:n]) {
		panic("data is bad")
	}
}

func TestSocks4RelayBIND(t *testing.T) {
	k := tool.NewId(1)
	rs, err := ListenRelayServerDefault("127.0.0.1:18000", k)
	checkErr(err)
	defer rs.Close(nil)
	taddr := &net.TCPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: randPort(),
		Zone: "",
	}
	dr := net.Dialer{LocalAddr: taddr}
	data := "Hello world!"
	wg := sync.WaitGroup{}
	config := &server.SocksServerConfig{
		TlnAddr: "127.0.0.1:17999",
		SocksAuthCb: server.SocksAuthCb{
			Socks4UserIdAuth: func(id share.Socks4UserId) byte {
				return id.IsEqual2(share.Socks4UserId{123, 223})
			},
			Socks5AuthPASSWORD: func(password share.Socks5AuthPassword) bool {
				return password.IsEqual("123", "456")
			},
		},
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: true,
			SwitchSocksVersion5: true,
		},
		CMDSwitch: share.SocksCMDSwitch{
			SwitchCMDCONNECT:      true,
			SwitchCMDBIND:         true,
			SwitchCMDUDPASSOCIATE: true,
		},
		RelayConfig: &server.SocksRelayConfig{
			Addr:         "127.0.0.1:18000",
			RawKey:       k,
			KeepEncrypt:  true,
			RelayTimeout: 0,
		},
	}
	s, err := ListenSocks(config)
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)

	sd, err := Socks4BIND("127.0.0.1:17999", share.Socks4UserId{123, 223}, nil, func(addr net.Addr) error {
		go func() {
			wg.Add(1)
			conn, err := dr.Dial("tcp", addr.String())
			checkErr(err)
			defer conn.Close()
			time.Sleep(1 * time.Second)
			conn.Write([]byte(data))
			wg.Done()
		}()
		return nil
	})
	checkErr(err)
	c, err := sd.Dial("tcp", taddr.String())
	checkErr(err)
	defer c.Close()
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	checkErr(err)
	if data != string(buf[:n]) {
		panic("data is bad")
	}
	wg.Wait()
}

func TestSocks5RelayCONNECT2(t *testing.T) {
	k := tool.NewId(1)
	rs, err := ListenRelayServerDefault("127.0.0.1:18000", k)
	checkErr(err)
	defer rs.Close(nil)
	ln := newTcpServer()
	defer ln.Close()
	config := &server.SocksServerConfig{
		TlnAddr: "127.0.0.1:17999",
		SocksAuthCb: server.SocksAuthCb{
			Socks4UserIdAuth: nil,
			Socks5AuthPASSWORD: func(password share.Socks5AuthPassword) bool {
				return password.IsEqual("123", "456")
			},
		},
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: true,
			SwitchSocksVersion5: true,
		},
		CMDSwitch: share.SocksCMDSwitch{
			SwitchCMDCONNECT:      true,
			SwitchCMDBIND:         true,
			SwitchCMDUDPASSOCIATE: true,
		},
		RelayConfig: &server.SocksRelayConfig{
			Addr:         "127.0.0.1:18000",
			RawKey:       k,
			KeepEncrypt:  false,
			RelayTimeout: 0,
		},
	}
	s, err := ListenSocks(config)
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)

	sd, err := Socks5CONNECT("127.0.0.1:17999", &client.Socks5Auth{
		Socks5AuthPASSWORD: &share.Socks5AuthPassword{
			User:     "123",
			Password: "456",
		},
	}, nil)
	checkErr(err)
	c, err := sd.Dial("tcp", ln.Addr().String())
	checkErr(err)
	defer c.Close()
	data := "Hello world!"
	_, err = c.Write([]byte(data))
	checkErr(err)
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	checkErr(err)
	if data != string(buf[:n]) {
		panic("data is bad")
	}
}

func TestSocks5RelayBIND2(t *testing.T) {
	k := tool.NewId(1)
	rs, err := ListenRelayServerDefault("127.0.0.1:18000", k)
	checkErr(err)
	defer rs.Close(nil)
	taddr := &net.TCPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: randPort(),
		Zone: "",
	}
	dr := net.Dialer{LocalAddr: taddr}
	data := "Hello world!"
	wg := sync.WaitGroup{}

	config := &server.SocksServerConfig{
		TlnAddr: "127.0.0.1:17999",
		SocksAuthCb: server.SocksAuthCb{
			Socks4UserIdAuth: nil,
			Socks5AuthPASSWORD: func(password share.Socks5AuthPassword) bool {
				return password.IsEqual("123", "456")
			},
		},
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: true,
			SwitchSocksVersion5: true,
		},
		CMDSwitch: share.SocksCMDSwitch{
			SwitchCMDCONNECT:      true,
			SwitchCMDBIND:         true,
			SwitchCMDUDPASSOCIATE: true,
		},
		RelayConfig: &server.SocksRelayConfig{
			Addr:         "127.0.0.1:18000",
			RawKey:       k,
			KeepEncrypt:  false,
			RelayTimeout: 0,
		},
	}
	s, err := ListenSocks(config)
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)
	sd, err := Socks5BIND("127.0.0.1:17999", &client.Socks5Auth{
		Socks5AuthPASSWORD: &share.Socks5AuthPassword{
			User:     "123",
			Password: "456",
		},
	}, nil, func(addr net.Addr) error {
		go func() {
			wg.Add(1)
			conn, err := dr.Dial("tcp", addr.String())
			checkErr(err)
			defer conn.Close()
			time.Sleep(1 * time.Second)
			conn.Write([]byte(data))
			wg.Done()
		}()
		return nil
	})
	checkErr(err)
	c, err := sd.Dial("tcp", taddr.String())
	checkErr(err)
	defer c.Close()
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	checkErr(err)
	if data != string(buf[:n]) {
		panic("data is bad")
	}
	wg.Wait()
}

func TestSocks5RelayUDPASSOCIATE2(t *testing.T) {
	ln := newUdpServer()
	defer ln.Close()

	k := tool.NewId(1)
	rs, err := ListenRelayServerDefault("127.0.0.1:18000", k)
	checkErr(err)
	defer rs.Close(nil)
	config := &server.SocksServerConfig{
		TlnAddr: "127.0.0.1:17999",
		SocksAuthCb: server.SocksAuthCb{
			Socks4UserIdAuth: nil,
			Socks5AuthPASSWORD: func(password share.Socks5AuthPassword) bool {
				return password.IsEqual("123", "456")
			},
		},
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: true,
			SwitchSocksVersion5: true,
		},
		CMDSwitch: share.SocksCMDSwitch{
			SwitchCMDCONNECT:      true,
			SwitchCMDBIND:         true,
			SwitchCMDUDPASSOCIATE: true,
		},
		RelayConfig: &server.SocksRelayConfig{
			Addr:         "127.0.0.1:18000",
			RawKey:       k,
			KeepEncrypt:  false,
			RelayTimeout: 0,
		},
	}
	s, err := ListenSocks(config)
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)
	data := "Hello world!"

	sd, err := Socks5UDPASSOCIATE("127.0.0.1:17999", &client.Socks5Auth{
		Socks5AuthPASSWORD: &share.Socks5AuthPassword{
			User:     "123",
			Password: "456",
		},
	}, nil, nil)
	checkErr(err)
	c, err := sd.DialUDP("udp", ":8888")
	checkErr(err)
	defer c.Close()
	_, err = c.WriteTo([]byte(data), ln.LocalAddr())
	checkErr(err)
	buf := make([]byte, 4096)
	n, addr, err := c.ReadFrom(buf)
	checkErr(err)
	if data != string(buf[:n]) || addr.String() != ln.LocalAddr().String() {
		panic("data is bad")
	}
}

func TestSocks4RelayCONNECT2(t *testing.T) {
	k := tool.NewId(1)
	rs, err := ListenRelayServerDefault("127.0.0.1:18000", k)
	checkErr(err)
	defer rs.Close(nil)
	ln := newTcpServer()
	defer ln.Close()
	config := &server.SocksServerConfig{
		TlnAddr: "127.0.0.1:17999",
		SocksAuthCb: server.SocksAuthCb{
			Socks4UserIdAuth: func(id share.Socks4UserId) byte {
				return id.IsEqual2(share.Socks4UserId{123, 223})
			},
			Socks5AuthPASSWORD: func(password share.Socks5AuthPassword) bool {
				return password.IsEqual("123", "456")
			},
		},
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: true,
			SwitchSocksVersion5: true,
		},
		CMDSwitch: share.SocksCMDSwitch{
			SwitchCMDCONNECT:      true,
			SwitchCMDBIND:         true,
			SwitchCMDUDPASSOCIATE: true,
		},
		RelayConfig: &server.SocksRelayConfig{
			Addr:         "127.0.0.1:18000",
			RawKey:       k,
			KeepEncrypt:  false,
			RelayTimeout: 0,
		},
	}
	s, err := ListenSocks(config)
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)

	sd, err := Socks4CONNECT("127.0.0.1:17999", share.Socks4UserId{123, 223}, nil)
	checkErr(err)
	c, err := sd.Dial("tcp", ln.Addr().String())
	checkErr(err)
	defer c.Close()
	data := "Hello world!"
	_, err = c.Write([]byte(data))
	checkErr(err)
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	checkErr(err)
	if data != string(buf[:n]) {
		panic("data is bad")
	}
}

func TestSocks4RelayBIND2(t *testing.T) {
	k := tool.NewId(1)
	rs, err := ListenRelayServerDefault("127.0.0.1:18000", k)
	checkErr(err)
	defer rs.Close(nil)
	taddr := &net.TCPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: randPort(),
		Zone: "",
	}
	dr := net.Dialer{LocalAddr: taddr}
	data := "Hello world!"
	wg := sync.WaitGroup{}
	config := &server.SocksServerConfig{
		TlnAddr: "127.0.0.1:17999",
		SocksAuthCb: server.SocksAuthCb{
			Socks4UserIdAuth: func(id share.Socks4UserId) byte {
				return id.IsEqual2(share.Socks4UserId{123, 223})
			},
			Socks5AuthPASSWORD: func(password share.Socks5AuthPassword) bool {
				return password.IsEqual("123", "456")
			},
		},
		VersionSwitch: share.SocksVersionSwitch{
			SwitchSocksVersion4: true,
			SwitchSocksVersion5: true,
		},
		CMDSwitch: share.SocksCMDSwitch{
			SwitchCMDCONNECT:      true,
			SwitchCMDBIND:         true,
			SwitchCMDUDPASSOCIATE: true,
		},
		RelayConfig: &server.SocksRelayConfig{
			Addr:         "127.0.0.1:18000",
			RawKey:       k,
			KeepEncrypt:  false,
			RelayTimeout: 0,
		},
	}
	s, err := ListenSocks(config)
	checkErr(err)
	defer s.Close(nil)
	time.Sleep(1 * time.Second)

	sd, err := Socks4BIND("127.0.0.1:17999", share.Socks4UserId{123, 223}, nil, func(addr net.Addr) error {
		go func() {
			wg.Add(1)
			conn, err := dr.Dial("tcp", addr.String())
			checkErr(err)
			defer conn.Close()
			time.Sleep(1 * time.Second)
			conn.Write([]byte(data))
			wg.Done()
		}()
		return nil
	})
	checkErr(err)
	c, err := sd.Dial("tcp", taddr.String())
	checkErr(err)
	defer c.Close()
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	checkErr(err)
	if data != string(buf[:n]) {
		panic("data is bad")
	}
	wg.Wait()
}
