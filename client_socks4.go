package socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
)

type socks4Config struct {
	proxyNetwork string
	proxyAddress string

	forward Dialer
	userId  S4UserId
	cd      byte

	bindCb BINDAddrCb
}

func newSocks4Config(network string, address string, cd byte, userId S4UserId, forward Dialer, bindCb BINDAddrCb) (*socks4Config, error) {
	return &socks4Config{
		proxyNetwork: network,
		proxyAddress: address,
		forward:      forward,
		userId:       userId,
		cd:           cd,
		bindCb:       bindCb,
	}, nil
}

func (s4d *socks4Config) Dial(network string, addr string) (c net.Conn, err error) {
	return s4d.DialContext(context.Background(), network, addr)
}

func (s4d *socks4Config) DialContext(ctx context.Context, network string, addr string) (c net.Conn, err error) {
	err = s4d.checkSocks4CD(socks4CDCONNECT, socks4CDBIND)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var conn net.Conn
	if s4d.forward != nil {
		conn, err = s4d.forward.DialContext(ctx, s4d.proxyNetwork, s4d.proxyAddress)
		if err != nil {
			return nil, err
		}
	} else {
		dr := net.Dialer{}
		conn, err = dr.DialContext(ctx, s4d.proxyNetwork, s4d.proxyAddress)
		if err != nil {
			return nil, err
		}
	}
	err = s4d.dialSocks4(ctx, conn, network, addr)
	if err != nil || ctx.Err() != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (s4d *socks4Config) dialSocks4(ctx context.Context, conn net.Conn, network string, addr string) error {
	xctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-xctx.Done():
		}
	}()
	err := s4d.networkCheck(network)
	if err != nil {
		return err
	}
	b, err := s4d.getSocks4Bytes(s4d.cd, s4d.userId, addr)
	if err != nil {
		return err
	}
	_, err = conn.Write(b)
	if err != nil {
		return err
	}
	buf := make([]byte, 8)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return err
	}
	cd, raddr, err := s4d.readSocks4Resp(buf)
	if err != nil {
		return err
	}
	err = getSocks4RespErr(cd)
	if err != nil {
		return err
	}
	if s4d.cd == socks4CDBIND {
		xaddr := raddr.(*net.TCPAddr)
		if xaddr.IP.IsUnspecified() {
			xaddr.IP = conn.RemoteAddr().(*net.TCPAddr).IP
		}
		if s4d.bindCb != nil {
			err = s4d.bindCb(xaddr)
			if err != nil {
				return err
			}
		}
		buf = make([]byte, 8)
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			return err
		}
		cd, _, err = s4d.readSocks4Resp(buf)
		if err != nil {
			return err
		}
		err = getSocks4RespErr(cd)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s4d *socks4Config) networkCheck(network string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return nil
	default:
		return ErrNetworkNotSupport
	}
}

func (s4d *socks4Config) readSocks4Resp(b []byte) (cd byte, addr net.Addr, err error) {
	if b[0] != 0x00 {
		return 0, nil, ErrSocksMessageParsingFailure
	}
	cd = b[1]
	addr = &net.TCPAddr{
		IP:   b[4:8],
		Port: int(binary.BigEndian.Uint16(b[2:4])),
		Zone: "",
	}
	return cd, addr, err
}

func (s4d *socks4Config) getSocks4Bytes(cd byte, userId S4UserId, addr string) ([]byte, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	p, _ := strconv.Atoi(port)
	if p < 0 || p > 65535 {
		return nil, ErrAddrInvalid(addr, "port invalid")
	}
	var ab []byte
	var ab2 []byte
	if ip == nil {
		xaddr := &net.TCPAddr{
			IP:   []byte{0x00, 0x00, 0x00, 0x01},
			Port: p,
			Zone: "",
		}
		ab = getSocks4AddrBytes(xaddr)
		ab2 = []byte(host)
		ab2 = append(ab2, socks4ByteNull)
	} else {
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, ErrSocks4NotSupportIPv6
		}
		xaddr := &net.TCPAddr{
			IP:   ip4,
			Port: p,
			Zone: "",
		}
		ab = getSocks4AddrBytes(xaddr)
	}
	data := new(bytes.Buffer)
	data.Write([]byte{socksVersion4, cd})
	data.Write(ab)
	data.Write(userId)
	data.Write([]byte{socks4ByteNull})
	data.Write(ab2)
	return data.Bytes(), nil
}

func (s4d *socks4Config) checkSocks4CD(cd ...byte) error {
	for _, b := range cd {
		if s4d.cd == b {
			return nil
		}
	}
	return ErrSocks4CDNotSupport
}
