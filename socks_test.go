package socks

import (
	"context"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func echoUdpPacketListener(addr ...string) (net.PacketConn, error) {
	ctx := context.Background()

	laddr := "127.0.0.1:"
	if len(addr) != 0 {
		laddr = addr[0]
	}

	lc := net.ListenConfig{}
	packetConn, err := lc.ListenPacket(ctx, "udp", laddr)
	if err != nil {
		return nil, err
	}
	nctx, cl := context.WithCancel(ctx)

	go func() {
		waitFunc(nctx, func() {
			_ = packetConn.Close()
		})
		defer cl()
		buf := make([]byte, 32*1024)
		for {
			n, addr, err := packetConn.ReadFrom(buf)
			if err != nil {
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			_, err = packetConn.WriteTo(data, addr)
			if err != nil {
				return
			}
		}
	}()

	return packetConn, nil
}

func echoTcpListener(addr ...string) (net.Listener, error) {
	ctx := context.Background()

	laddr := "127.0.0.1:"
	if len(addr) != 0 {
		laddr = addr[0]
	}

	lc := net.ListenConfig{}
	listen, err := lc.Listen(ctx, "tcp", laddr)
	if err != nil {
		return nil, err
	}

	nctx, cl := context.WithCancel(ctx)

	go func() {
		waitFunc(nctx, func() {
			_ = listen.Close()
		})
		defer cl()
		for {
			conn, err := listen.Accept()
			if err != nil {
				return
			}
			go func(ctx context.Context, conn net.Conn) {
				nctx, cl := context.WithCancel(ctx)
				defer cl()
				waitFunc(nctx, func() {
					_ = conn.Close()
				})
				_, _ = io.Copy(conn, conn)
			}(nctx, conn)
		}
	}()

	return listen, nil
}

func echoHttp(addr ...string) (*http.Server, string, error) {
	ctx := context.Background()

	laddr := "127.0.0.1:"
	if len(addr) != 0 {
		laddr = addr[0]
	}

	lc := net.ListenConfig{}
	listen, err := lc.Listen(ctx, "tcp", laddr)
	if err != nil {
		return nil, "", err
	}

	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		for k := range writer.Header() {
			writer.Header().Del(k)
		}
		for k, v := range request.Header {
			for _, s := range v {
				writer.Header().Add(k, s)
			}
		}
		body := request.Body
		if body != nil {
			all, err := io.ReadAll(body)
			if err != nil {
				_, _ = writer.Write([]byte(err.Error()))
				writer.WriteHeader(http.StatusInternalServerError)
			} else {
				_, err := writer.Write(all)
				if err != nil {
					_, _ = writer.Write([]byte(err.Error()))
					writer.WriteHeader(http.StatusInternalServerError)
				}
			}
		}
	})}

	nctx, cl := context.WithCancel(ctx)
	go func() {
		waitFunc(nctx, func() {
			_ = server.Close()
		})
		defer cl()
		_ = server.Serve(listen)
	}()

	return server, fmt.Sprintf("http://%s", listen.Addr().String()), nil
}

func testLPConn(t *testing.T) net.PacketConn {
	listener, err := echoUdpPacketListener()
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func testListen(t *testing.T) net.Listener {
	listener, err := echoTcpListener()
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func testConn(t *testing.T, conn net.Conn, data string) {
	_, err := conn.Write([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(data))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatal(err)
	}
	if data != string(buf) {
		t.Fatal("test failed")
	}
}

func testPConn(t *testing.T, pconn net.PacketConn, addr net.Addr, data string) {
	_, err := pconn.WriteTo([]byte(data), addr)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 255+len(data))
	n, raddr, err := pconn.ReadFrom(buf)
	if err != nil {
		fmt.Println(addr)
		t.Fatal(err)
	}
	if raddr.String() != addr.String() || data != string(buf[:n]) {
		t.Fatal("test failed")
	}
}

func newData(n int) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	l := make([]byte, n)
	for i := range l {
		l[i] = byte(r.Intn(256))
	}
	return string(l)
}

func TestNewServer(t *testing.T) {
	cfg := &ServerConfig{
		VersionSwitch: DefaultSocksVersionSwitch,
		CMDConfig:     DefaultSocksCMDConfig,
		Socks5AuthCb: S5AuthCb{
			Socks5AuthNOAUTH: DefaultAuthConnCb,
			Socks5AuthPASSWORD: func(conn net.Conn, auth S5AuthPassword) net.Conn {
				return auth.IsEqual2(conn, "test", "test123")
			},
		},
		Socks4AuthCb: S4AuthCb{Socks4UserIdAuth: func(conn net.Conn, id S4UserId) (net.Conn, S4IdAuthCode) {
			return id.IsEqual3(conn, S4UserId{1, 2, 3, 4, 5, 6})
		}},
	}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		time.Sleep(3 * time.Second)
		_ = server.Close()
	}()
	err = server.ListenAndServe("tcp", "127.0.0.1:4440")
	if err != nil {
		return
	}
}

func TestSOCKS5(t *testing.T) {
	cfg := &ServerConfig{
		VersionSwitch: DefaultSocksVersionSwitch,
		CMDConfig:     DefaultSocksCMDConfig,
		Socks5AuthCb: S5AuthCb{
			Socks5AuthNOAUTH: DefaultAuthConnCb,
			Socks5AuthPASSWORD: func(conn net.Conn, auth S5AuthPassword) net.Conn {
				return auth.IsEqual2(conn, "test", "test123")
			},
		},
		Socks4AuthCb: S4AuthCb{Socks4UserIdAuth: func(conn net.Conn, id S4UserId) (net.Conn, S4IdAuthCode) {
			return id.IsEqual3(conn, S4UserId{1, 2, 3, 4, 5, 6})
		}},
	}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	go func() {
		_ = server.Serve(listen)
	}()
	time.Sleep(1 * time.Second)
	dr, err := proxy.SOCKS5(listen.Addr().Network(), listen.Addr().String(), &proxy.Auth{
		User:     "test",
		Password: "test123",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln := testListen(t)
	defer ln.Close()
	conn, err := dr.Dial(ln.Addr().Network(), ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 3; i++ {
		testConn(t, conn, newData(4096))
	}
}

func TestSOCKS5CONNCT(t *testing.T) {
	cfg := &ServerConfig{
		VersionSwitch: DefaultSocksVersionSwitch,
		CMDConfig:     DefaultSocksCMDConfig,
		Socks5AuthCb: S5AuthCb{
			Socks5AuthNOAUTH: DefaultAuthConnCb,
			Socks5AuthPASSWORD: func(conn net.Conn, auth S5AuthPassword) net.Conn {
				return auth.IsEqual2(conn, "test", "test123")
			},
		},
		Socks4AuthCb: S4AuthCb{Socks4UserIdAuth: func(conn net.Conn, id S4UserId) (net.Conn, S4IdAuthCode) {
			return id.IsEqual3(conn, S4UserId{1, 2, 3, 4, 5, 6})
		}},
	}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	go func() {
		_ = server.Serve(listen)
	}()
	time.Sleep(1 * time.Second)
	dr, err := SOCKS5CONNECTP(listen.Addr().Network(), listen.Addr().String(), &S5AuthPassword{
		User:     "test",
		Password: "test123",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln := testListen(t)
	defer ln.Close()
	conn, err := dr.Dial(ln.Addr().Network(), ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 3; i++ {
		testConn(t, conn, newData(4096))
	}
}

func TestSOCKS4CONNECT(t *testing.T) {
	cfg := &ServerConfig{
		VersionSwitch: DefaultSocksVersionSwitch,
		CMDConfig:     DefaultSocksCMDConfig,
		Socks5AuthCb: S5AuthCb{
			Socks5AuthNOAUTH: DefaultAuthConnCb,
			Socks5AuthPASSWORD: func(conn net.Conn, auth S5AuthPassword) net.Conn {
				return auth.IsEqual2(conn, "test", "test123")
			},
		},
		Socks4AuthCb: S4AuthCb{Socks4UserIdAuth: func(conn net.Conn, id S4UserId) (net.Conn, S4IdAuthCode) {
			return id.IsEqual3(conn, S4UserId{1, 2, 3, 4, 5, 6})
		}},
	}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	go func() {
		_ = server.Serve(listen)
	}()
	time.Sleep(1 * time.Second)
	dr, err := SOCKS4CONNECT(listen.Addr().Network(), listen.Addr().String(), S4UserId{1, 2, 3, 4, 5, 6}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln := testListen(t)
	defer ln.Close()
	conn, err := dr.Dial(ln.Addr().Network(), ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 3; i++ {
		testConn(t, conn, newData(4096))
	}
}

func TestSOCKS5BIND(t *testing.T) {
	cfg := &ServerConfig{
		VersionSwitch: DefaultSocksVersionSwitch,
		CMDConfig:     DefaultSocksCMDConfig,
		Socks5AuthCb: S5AuthCb{
			Socks5AuthNOAUTH: DefaultAuthConnCb,
			Socks5AuthPASSWORD: func(conn net.Conn, auth S5AuthPassword) net.Conn {
				return auth.IsEqual2(conn, "test", "test123")
			},
		},
		Socks4AuthCb: S4AuthCb{Socks4UserIdAuth: func(conn net.Conn, id S4UserId) (net.Conn, S4IdAuthCode) {
			return id.IsEqual3(conn, S4UserId{1, 2, 3, 4, 5, 6})
		}},
	}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	go func() {
		_ = server.Serve(listen)
	}()
	time.Sleep(1 * time.Second)
	dx := net.Dialer{LocalAddr: &net.TCPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: rand.Intn(10000) + 10000,
		Zone: "",
	}}
	dr, err := SOCKS5BINDP(listen.Addr().Network(), listen.Addr().String(), &S5AuthPassword{
		User:     "test",
		Password: "test123",
	}, nil, func(addr net.Addr) error {
		conn, err := dx.Dial(addr.Network(), addr.String())
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			io.Copy(conn, conn)
		}()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dr.Dial(dx.LocalAddr.Network(), dx.LocalAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 3; i++ {
		testConn(t, conn, newData(4096))
	}
}

func TestSOCKS4BIND(t *testing.T) {
	cfg := &ServerConfig{
		VersionSwitch: DefaultSocksVersionSwitch,
		CMDConfig:     DefaultSocksCMDConfig,
		Socks5AuthCb: S5AuthCb{
			Socks5AuthNOAUTH: DefaultAuthConnCb,
			Socks5AuthPASSWORD: func(conn net.Conn, auth S5AuthPassword) net.Conn {
				return auth.IsEqual2(conn, "test", "test123")
			},
		},
		Socks4AuthCb: S4AuthCb{Socks4UserIdAuth: func(conn net.Conn, id S4UserId) (net.Conn, S4IdAuthCode) {
			return id.IsEqual3(conn, S4UserId{1, 2, 3, 4, 5, 6})
		}},
	}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	go func() {
		_ = server.Serve(listen)
	}()
	time.Sleep(1 * time.Second)
	dx := net.Dialer{LocalAddr: &net.TCPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: rand.Intn(10000) + 10000,
		Zone: "",
	}}
	dr, err := SOCKS4BIND(listen.Addr().Network(), listen.Addr().String(), S4UserId{1, 2, 3, 4, 5, 6}, nil, func(addr net.Addr) error {
		conn, err := dx.Dial(addr.Network(), addr.String())
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			io.Copy(conn, conn)
		}()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dr.Dial(dx.LocalAddr.Network(), dx.LocalAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 3; i++ {
		testConn(t, conn, newData(4096))
	}
}

func TestSOCKS5UDPASSOCIATEP(t *testing.T) {
	cfg := &ServerConfig{
		VersionSwitch: DefaultSocksVersionSwitch,
		CMDConfig:     DefaultSocksCMDConfig,
		Socks5AuthCb: S5AuthCb{
			Socks5AuthNOAUTH: DefaultAuthConnCb,
			Socks5AuthPASSWORD: func(conn net.Conn, auth S5AuthPassword) net.Conn {
				return auth.IsEqual2(conn, "test", "test123")
			},
		},
		Socks4AuthCb: S4AuthCb{Socks4UserIdAuth: func(conn net.Conn, id S4UserId) (net.Conn, S4IdAuthCode) {
			return id.IsEqual3(conn, S4UserId{1, 2, 3, 4, 5, 6})
		}},
	}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	go func() {
		_ = server.Serve(listen)
	}()
	time.Sleep(1 * time.Second)
	pConn := testLPConn(t)
	defer pConn.Close()
	ucfg, err := SOCKS5UDPASSOCIATEP(listen.Addr().Network(), listen.Addr().String(), &S5AuthPassword{
		User:     "test",
		Password: "test123",
	}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	pConn2, err := ucfg.ListenPacket("udp", "0:12133")
	if err != nil {
		t.Fatal(err)
	}
	defer pConn2.Close()
	for i := 0; i < 3; i++ {
		testPConn(t, pConn2, pConn.LocalAddr(), newData(4096))
	}
}

func TestDNS(t *testing.T) {
	cfg := &ServerConfig{
		VersionSwitch: DefaultSocksVersionSwitch,
		CMDConfig:     DefaultSocksCMDConfig,
		Socks5AuthCb: S5AuthCb{
			Socks5AuthNOAUTH: DefaultAuthConnCb,
			Socks5AuthPASSWORD: func(conn net.Conn, auth S5AuthPassword) net.Conn {
				return auth.IsEqual2(conn, "test", "test123")
			},
		},
		Socks4AuthCb: S4AuthCb{Socks4UserIdAuth: func(conn net.Conn, id S4UserId) (net.Conn, S4IdAuthCode) {
			return id.IsEqual3(conn, S4UserId{1, 2, 3, 4, 5, 6})
		}},
	}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	listen, err := net.Listen("tcp", ":9978")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	go server.Serve(listen)

	time.Sleep(1 * time.Second)

	pconn, err := SOCKS5UDPASSOCIATEP(listen.Addr().Network(), listen.Addr().String(), nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	xconn, err := pconn.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer xconn.Close()
	m := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: 0,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName("www.google.com."),
				Type:  dnsmessage.TypeALL,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	m.ID = 3
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	udpAddr, _ := net.ResolveUDPAddr("", "8.8.8.8:53")
	_, err = xconn.WriteTo(b, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _, err := xconn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	var m1 dnsmessage.Message
	err = m1.Unpack(buf[:n])
	fmt.Println(m1.GoString())

	xconn2, err := pconn.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer xconn2.Close()

	m.ID = 4
	b, err = m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	_, err = xconn2.WriteTo(b, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	n, _, err = xconn2.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	err = m1.Unpack(buf[:n])
	fmt.Println(m1.GoString())
}

func TestHttp(t *testing.T) {
	echoHttp, httpAddr, err := echoHttp()
	if err != nil {
		t.Fatal(echoHttp)
	}
	defer echoHttp.Close()

	cfg := &ServerConfig{
		VersionSwitch: DefaultSocksVersionSwitch,
		CMDConfig:     DefaultSocksCMDConfig,
		Socks5AuthCb: S5AuthCb{
			Socks5AuthNOAUTH: nil,
			Socks5AuthPASSWORD: func(conn net.Conn, auth S5AuthPassword) net.Conn {
				return auth.IsEqual2(conn, "test", "test123")
			},
		},
		Socks4AuthCb: S4AuthCb{Socks4UserIdAuth: func(conn net.Conn, id S4UserId) (net.Conn, S4IdAuthCode) {
			return id.IsEqual3(conn, S4UserId{1, 2, 3, 4, 5, 6})
		}},
	}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	go func() {
		_ = server.Serve(listen)
	}()
	time.Sleep(1 * time.Second)

	parse, err := url.Parse(fmt.Sprintf("socks5://test:test123@%s", listen.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}

	c := http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(parse)}}
	resp, err := c.Get(httpAddr)
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

func testRelayServer(t *testing.T) net.Listener {
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer listen.Close()
		for {
			conn, err := listen.Accept()
			if err != nil {
				return
			}
			go func(conn2 net.Conn) {
				defer conn2.Close()
				_ = RelayServe(conn2)
			}(conn)
		}
	}()
	return listen
}

func TestSOCKS5CONNECTRelay(t *testing.T) {
	relay := testRelayServer(t)
	defer relay.Close()

	cfg := &ServerConfig{
		VersionSwitch: DefaultSocksVersionSwitch,
		CMDConfig:     DefaultSocksCMDConfig,
		Socks5AuthCb: S5AuthCb{
			Socks5AuthNOAUTH: DefaultAuthConnCb,
			Socks5AuthPASSWORD: func(conn net.Conn, auth S5AuthPassword) net.Conn {
				return auth.IsEqual2(conn, "test", "test123")
			},
		},
		Socks4AuthCb: S4AuthCb{Socks4UserIdAuth: func(conn net.Conn, id S4UserId) (net.Conn, S4IdAuthCode) {
			return id.IsEqual3(conn, S4UserId{1, 2, 3, 4, 5, 6})
		}},
	}
	cfg.CMDConfig.CMDCONNECTHandler = RelayCMDCONNECTHandler(func(ctx context.Context) (net.Conn, error) {
		dr := net.Dialer{}
		return dr.DialContext(ctx, relay.Addr().Network(), relay.Addr().String())
	})
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	go func() {
		_ = server.Serve(listen)
	}()
	time.Sleep(1 * time.Second)
	dr, err := SOCKS5CONNECTP(listen.Addr().Network(), listen.Addr().String(), &S5AuthPassword{
		User:     "test",
		Password: "test123",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln := testListen(t)
	defer ln.Close()
	conn, err := dr.Dial(ln.Addr().Network(), ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 3; i++ {
		testConn(t, conn, newData(4096))
	}
}

func TestSOCKS4CONNECTRelay(t *testing.T) {
	relay := testRelayServer(t)
	defer relay.Close()

	cfg := &ServerConfig{
		VersionSwitch: DefaultSocksVersionSwitch,
		CMDConfig:     DefaultSocksCMDConfig,
		Socks5AuthCb: S5AuthCb{
			Socks5AuthNOAUTH: DefaultAuthConnCb,
			Socks5AuthPASSWORD: func(conn net.Conn, auth S5AuthPassword) net.Conn {
				return auth.IsEqual2(conn, "test", "test123")
			},
		},
		Socks4AuthCb: S4AuthCb{Socks4UserIdAuth: func(conn net.Conn, id S4UserId) (net.Conn, S4IdAuthCode) {
			return id.IsEqual3(conn, S4UserId{1, 2, 3, 4, 5, 6})
		}},
	}
	cfg.CMDConfig.CMDCONNECTHandler = RelayCMDCONNECTHandler(func(ctx context.Context) (net.Conn, error) {
		dr := net.Dialer{}
		return dr.DialContext(ctx, relay.Addr().Network(), relay.Addr().String())
	})
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	go func() {
		_ = server.Serve(listen)
	}()
	time.Sleep(1 * time.Second)
	dr, err := SOCKS4CONNECT(listen.Addr().Network(), listen.Addr().String(), S4UserId{1, 2, 3, 4, 5, 6}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln := testListen(t)
	defer ln.Close()
	conn, err := dr.Dial(ln.Addr().Network(), ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 3; i++ {
		testConn(t, conn, newData(4096))
	}
}

func TestSOCKS5BINDRelay(t *testing.T) {
	relay := testRelayServer(t)
	defer relay.Close()

	cfg := &ServerConfig{
		VersionSwitch: DefaultSocksVersionSwitch,
		CMDConfig:     DefaultSocksCMDConfig,
		Socks5AuthCb: S5AuthCb{
			Socks5AuthNOAUTH: DefaultAuthConnCb,
			Socks5AuthPASSWORD: func(conn net.Conn, auth S5AuthPassword) net.Conn {
				return auth.IsEqual2(conn, "test", "test123")
			},
		},
		Socks4AuthCb: S4AuthCb{Socks4UserIdAuth: func(conn net.Conn, id S4UserId) (net.Conn, S4IdAuthCode) {
			return id.IsEqual3(conn, S4UserId{1, 2, 3, 4, 5, 6})
		}},
	}
	cfg.CMDConfig.CMDBINDHandler = RelayCMDBINDHandler(func(ctx context.Context) (net.Conn, error) {
		dr := net.Dialer{}
		return dr.DialContext(ctx, relay.Addr().Network(), relay.Addr().String())
	})
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	go func() {
		_ = server.Serve(listen)
	}()
	time.Sleep(1 * time.Second)
	dx := net.Dialer{LocalAddr: &net.TCPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: rand.Intn(10000) + 10000,
		Zone: "",
	}}
	dr, err := SOCKS5BINDP(listen.Addr().Network(), listen.Addr().String(), &S5AuthPassword{
		User:     "test",
		Password: "test123",
	}, nil, func(addr net.Addr) error {
		conn, err := dx.Dial(addr.Network(), addr.String())
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			io.Copy(conn, conn)
		}()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dr.Dial(dx.LocalAddr.Network(), dx.LocalAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 3; i++ {
		testConn(t, conn, newData(4096))
	}
}

func TestSOCKS4BINDRelay(t *testing.T) {
	relay := testRelayServer(t)
	defer relay.Close()

	cfg := &ServerConfig{
		VersionSwitch: DefaultSocksVersionSwitch,
		CMDConfig:     DefaultSocksCMDConfig,
		Socks5AuthCb: S5AuthCb{
			Socks5AuthNOAUTH: DefaultAuthConnCb,
			Socks5AuthPASSWORD: func(conn net.Conn, auth S5AuthPassword) net.Conn {
				return auth.IsEqual2(conn, "test", "test123")
			},
		},
		Socks4AuthCb: S4AuthCb{Socks4UserIdAuth: func(conn net.Conn, id S4UserId) (net.Conn, S4IdAuthCode) {
			return id.IsEqual3(conn, S4UserId{1, 2, 3, 4, 5, 6})
		}},
	}
	cfg.CMDConfig.CMDBINDHandler = RelayCMDBINDHandler(func(ctx context.Context) (net.Conn, error) {
		dr := net.Dialer{}
		return dr.DialContext(ctx, relay.Addr().Network(), relay.Addr().String())
	})
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	go func() {
		_ = server.Serve(listen)
	}()
	time.Sleep(1 * time.Second)
	dx := net.Dialer{LocalAddr: &net.TCPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: rand.Intn(10000) + 10000,
		Zone: "",
	}}
	dr, err := SOCKS4BIND(listen.Addr().Network(), listen.Addr().String(), S4UserId{1, 2, 3, 4, 5, 6}, nil, func(addr net.Addr) error {
		conn, err := dx.Dial(addr.Network(), addr.String())
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			io.Copy(conn, conn)
		}()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dr.Dial(dx.LocalAddr.Network(), dx.LocalAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 3; i++ {
		testConn(t, conn, newData(4096))
	}
}
