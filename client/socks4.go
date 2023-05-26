package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/peakedshout/go-socks/share"
	"io"
	"net"
	"strconv"
)

type Socks4Dialer struct {
	addr           string
	ctx            context.Context
	userId         share.Socks4UserId
	forward        SocksDialer
	forwardContext SocksContextDialer
	cd             byte

	bindCb AddrCb
}

func (s4d *Socks4Dialer) DialContext(ctx context.Context, network string, addr string) (c net.Conn, err error) {
	if ctx != nil {
		s4d.ctx = ctx
	} else {
		s4d.ctx = context.Background()
	}
	var conn net.Conn
	if s4d.forwardContext != nil {
		conn, err = s4d.forwardContext.DialContext(s4d.ctx, network, s4d.addr)
		if err != nil {
			return nil, err
		}
	} else if s4d.forward != nil {
		conn, err = s4d.forward.Dial(network, s4d.addr)
		if err != nil {
			return nil, err
		}
	} else {
		dr := net.Dialer{}
		conn, err = dr.DialContext(s4d.ctx, network, s4d.addr)
		if err != nil {
			return nil, err
		}
	}
	err = s4d.dialSocks4(conn, addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
func (s4d *Socks4Dialer) Dial(network string, addr string) (c net.Conn, err error) {
	return s4d.DialContext(nil, network, addr)
}

func (s4d *Socks4Dialer) dialSocks4(conn net.Conn, addr string) error {
	b, err := getSocks4Bytes(s4d.cd, s4d.userId, addr)
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
	cd, raddr, err := readSocks4Resp(buf)
	if err != nil {
		return err
	}
	err = share.GetSocks4RespErr(cd)
	if err != nil {
		return err
	}
	if s4d.cd == share.Socks4CDBIND {
		xaddr := raddr.(*net.TCPAddr)
		if xaddr.IP.IsUnspecified() {
			xaddr.IP = conn.RemoteAddr().(*net.TCPAddr).IP
		}
		err = s4d.bindCb(xaddr)
		if err != nil {
			return err
		}
		buf = make([]byte, 8)
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			return err
		}
		cd, _, err = readSocks4Resp(buf)
		if err != nil {
			return err
		}
		err = share.GetSocks4RespErr(cd)
		if err != nil {
			return err
		}
	}
	return nil
}

func readSocks4Resp(b []byte) (cd byte, addr net.Addr, err error) {
	if b[0] != 0x00 {
		return 0, nil, share.ErrSocksMessageParsingFailure
	}
	cd = b[1]
	addr = &net.TCPAddr{
		IP:   b[4:8],
		Port: int(binary.BigEndian.Uint16(b[2:4])),
		Zone: "",
	}
	return cd, addr, err
}

func getSocks4Bytes(cd byte, userId share.Socks4UserId, addr string) ([]byte, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	p, _ := strconv.Atoi(port)
	if p < 0 || p > 65535 {
		return nil, share.ErrAddrInvalid(addr, "port invalid")
	}
	var ab []byte
	var ab2 []byte
	if ip == nil {
		xaddr := &net.TCPAddr{
			IP:   []byte{0x00, 0x00, 0x00, 0x01},
			Port: p,
			Zone: "",
		}
		ab = share.GetSocks4AddrBytes(xaddr)
		ab2 = []byte(host)
		ab2 = append(ab2, share.Socks4ByteNull)
	} else {
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, share.ErrSocks4NotSupportIPv6
		}
		xaddr := &net.TCPAddr{
			IP:   ip4,
			Port: p,
			Zone: "",
		}
		ab = share.GetSocks4AddrBytes(xaddr)
	}
	data := new(bytes.Buffer)
	data.Write([]byte{share.SocksVersion4, cd})
	data.Write(ab)
	data.Write(userId)
	data.Write([]byte{share.Socks4ByteNull})
	data.Write(ab2)
	return data.Bytes(), nil
}
