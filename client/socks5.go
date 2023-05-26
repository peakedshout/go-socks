package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/peakedshout/go-socks/share"
	"io"
	"net"
	"strconv"
)

type Socks5Auth struct {
	Socks5AuthNOAUTH   bool
	Socks5AuthGSSAPI   func(conn net.Conn) bool
	Socks5AuthPASSWORD *share.Socks5AuthPassword
	Socks5AuthIANA     [125]func(conn net.Conn) bool
	Socks5AuthPRIVATE  [127]func(conn net.Conn) bool
}

type Socks5Dialer struct {
	addr           string
	ctx            context.Context
	auth           *Socks5Auth
	forward        SocksDialer
	forwardContext SocksContextDialer

	uforward        SocksUdpDialer
	uforwardContext SocksUdpContextDialer

	cmd byte

	bindCb AddrCb
}

func (s5d *Socks5Dialer) DialUDPContext(ctx context.Context, network string, addr string) (pc net.PacketConn, err error) {
	laddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, err
	}
	conn, err := s5d.dialSocks5(ctx, "tcp")
	if err != nil {
		return nil, err
	}
	err = s5d.authSocks5(conn)
	if err != nil {
		return nil, err
	}
	pc, err = s5d.udpSocks5(conn, network, laddr)
	if err != nil {
		return nil, err
	}
	return pc, nil
}

func (s5d *Socks5Dialer) DialUDP(network string, addr string) (pc net.PacketConn, err error) {
	return s5d.DialUDPContext(nil, network, addr)
}

func (s5d *Socks5Dialer) DialContext(ctx context.Context, network string, addr string) (c net.Conn, err error) {
	conn, err := s5d.dialSocks5(ctx, network)
	if err != nil {
		return nil, err
	}
	err = s5d.authSocks5(conn)
	if err != nil {
		return nil, err
	}
	err = s5d.cmdSocks5(conn, addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
func (s5d *Socks5Dialer) Dial(network string, addr string) (c net.Conn, err error) {
	return s5d.DialContext(nil, network, addr)
}

func (s5d *Socks5Dialer) udpSocks5(conn net.Conn, network string, laddr *net.UDPAddr) (net.PacketConn, error) {
	b, err := getSocks5CMDBytes(s5d.cmd, laddr.String())
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(b)
	if err != nil {
		return nil, err
	}
	rep, raddr, err := s5d.readSocks5CMDResp(conn)
	if err != nil {
		return nil, err
	}
	err = share.GetSocks5RespErr(rep)
	if err != nil {
		return nil, err
	}
	var uconn net.PacketConn
	if s5d.uforwardContext != nil {
		uconn, err = s5d.uforwardContext.DialUDPContext(s5d.ctx, network, raddr)
		if err != nil {
			return nil, err
		}
	} else if s5d.uforward != nil {
		uconn, err = s5d.uforward.DialUDP(network, raddr)
		if err != nil {
			return nil, err
		}
	} else {
		lner := &net.ListenConfig{}
		uconn, err = lner.ListenPacket(s5d.ctx, network, laddr.String())
		if err != nil {
			return nil, err
		}
	}
	xaddr, _ := net.ResolveUDPAddr("", raddr)
	if xaddr.IP.IsUnspecified() {
		xaddr.IP = conn.RemoteAddr().(*net.TCPAddr).IP
	}
	pc := &Socks5PacketConn{
		PacketConn: uconn,
		lifeConn:   conn,
		socksAddr:  xaddr,
	}
	go pc.keepLife()
	return pc, nil
}

func (s5d *Socks5Dialer) cmdSocks5(conn net.Conn, addr string) error {
	b, err := getSocks5CMDBytes(s5d.cmd, addr)
	if err != nil {
		return err
	}
	_, err = conn.Write(b)
	if err != nil {
		return err
	}
	rep, raddr, err := s5d.readSocks5CMDResp(conn)
	if err != nil {
		return err
	}
	err = share.GetSocks5RespErr(rep)
	if err != nil {
		return err
	}
	if s5d.cmd == share.Socks5CMDBIND {
		xaddr, err := net.ResolveTCPAddr("", raddr)
		if xaddr.IP.IsUnspecified() {
			xaddr.IP = conn.RemoteAddr().(*net.TCPAddr).IP
		}
		err = s5d.bindCb(xaddr)
		if err != nil {
			return err
		}
		rep, _, err = s5d.readSocks5CMDResp(conn)
		if err != nil {
			return err
		}
		err = share.GetSocks5RespErr(rep)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s5d *Socks5Dialer) dialSocks5(ctx context.Context, network string) (conn net.Conn, err error) {
	if ctx != nil {
		s5d.ctx = ctx
	} else {
		s5d.ctx = context.Background()
	}
	if s5d.forwardContext != nil {
		conn, err = s5d.forwardContext.DialContext(s5d.ctx, network, s5d.addr)
		if err != nil {
			return nil, err
		}
	} else if s5d.forward != nil {
		conn, err = s5d.forward.Dial(network, s5d.addr)
		if err != nil {
			return nil, err
		}
	} else {
		dr := net.Dialer{}
		conn, err = dr.DialContext(s5d.ctx, network, s5d.addr)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

func (s5d *Socks5Dialer) authSocks5(conn net.Conn) error {
	b, err := s5d.getSocks5AuthBytes()
	if err != nil {
		return err
	}
	_, err = conn.Write(b)
	if err != nil {
		return err
	}
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return err
	}
	if buf[0] != share.SocksVersion5 {
		return share.ErrSocksMessageParsingFailure
	}
	if buf[1] == share.Socks5METHODCodeNOAUTH {
		return nil
	} else if buf[1] == share.Socks5METHODCodeGSSAPI {
		if s5d.auth.Socks5AuthGSSAPI(conn) {
			return nil
		} else {
			err = share.ErrSocks5AuthRejected
			return err
		}
	} else if buf[1] == share.Socks5METHODCodePASSWORD {
		s, err := s5d.authSocks5Password(conn)
		if err != nil {
			return err
		}
		if s {
			return nil
		} else {
			err = share.ErrSocks5AuthRejected
			return err
		}
	} else if buf[1] >= share.Socks5METHODCodeIANA && buf[1] < share.Socks5METHODCodePRIVATE {
		if s5d.auth.Socks5AuthIANA[int(buf[1]-share.Socks5METHODCodeIANA)](conn) {
			return nil
		} else {
			err = share.ErrSocks5AuthRejected
			return err
		}
	} else if buf[1] >= share.Socks5METHODCodePRIVATE && buf[1] < share.Socks5RETHODCodeRejected {
		if s5d.auth.Socks5AuthPRIVATE[int(buf[1]-share.Socks5METHODCodePRIVATE)](conn) {
			return nil
		} else {
			err = share.ErrSocks5AuthRejected
			return err
		}
	} else {
		return share.ErrSocks5NOACCEPTABLEMETHODS
	}
}

func (s5d *Socks5Dialer) authSocks5Password(conn net.Conn) (bool, error) {
	bs := new(bytes.Buffer)
	bs.Write([]byte{share.Socks5AuthPasswordVER})
	bs.Write([]byte{byte(len(s5d.auth.Socks5AuthPASSWORD.User))})
	bs.Write([]byte(s5d.auth.Socks5AuthPASSWORD.User))
	bs.Write([]byte{byte(len(s5d.auth.Socks5AuthPASSWORD.Password))})
	bs.Write([]byte(s5d.auth.Socks5AuthPASSWORD.Password))
	_, err := conn.Write(bs.Bytes())
	if err != nil {
		return false, err
	}
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return false, err
	}
	if buf[0] != share.Socks5AuthPasswordVER {
		return false, share.ErrSocksMessageParsingFailure
	}
	switch buf[1] {
	case share.Socks5AuthRespPasswordSuccess:
		return true, nil
	case share.Socks5AuthRespPasswordFailure:
		return false, nil
	default:
		return false, share.ErrSocksMessageParsingFailure
	}
}

func (s5d *Socks5Dialer) getSocks5AuthBytes() ([]byte, error) {
	if s5d.auth == nil {
		return nil, share.ErrSocks5NeedMETHODSAuth
	}
	bs := new(bytes.Buffer)
	bs.Write([]byte{share.SocksVersion5, 0x00})
	var l byte = 0x00
	if s5d.auth.Socks5AuthNOAUTH {
		bs.Write([]byte{share.Socks5METHODCodeNOAUTH})
		l++
	}
	if s5d.auth.Socks5AuthGSSAPI != nil {
		bs.Write([]byte{share.Socks5METHODCodeGSSAPI})
		l++
	}
	if s5d.auth.Socks5AuthPASSWORD != nil {
		bs.Write([]byte{share.Socks5METHODCodePASSWORD})
		l++
	}
	for i, one := range s5d.auth.Socks5AuthIANA {
		if one != nil {
			bs.Write([]byte{byte(share.Socks5METHODCodeIANA + i)})
			l++
		}
	}
	for i, one := range s5d.auth.Socks5AuthPRIVATE {
		if one != nil {
			bs.Write([]byte{byte(share.Socks5METHODCodePRIVATE + i)})
			l++
		}
	}
	b := bs.Bytes()
	b[1] = l
	return b, nil
}

func (s5d *Socks5Dialer) readSocks5CMDResp(conn net.Conn) (rep byte, addr string, err error) {
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return 0, "", err
	}
	if buf[0] != share.SocksVersion5 || buf[2] != 0x00 {
		return 0, "", share.ErrSocksMessageParsingFailure
	}
	rep = buf[1]
	switch buf[3] {
	case share.Socks5AddrTypeIPv4:
		buf = make([]byte, 256)
		_, err = io.ReadFull(conn, buf[:4+2])
		if err != nil {
			return 0, "", err
		}
		addr = fmt.Sprintf("%s:%d", net.IP(buf[:4]).String(), binary.BigEndian.Uint16(buf[4:4+2]))
		return rep, addr, nil
	case share.Socks5AddrTypeIPv6:
		buf = make([]byte, 256)
		_, err = io.ReadFull(conn, buf[:16+2])
		if err != nil {
			return 0, "", err
		}
		addr = fmt.Sprintf("[%s]:%d", net.IP(buf[:16]).String(), binary.BigEndian.Uint16(buf[16:16+2]))
		return rep, addr, nil
	default:
		return 0, "", share.ErrSocksMessageParsingFailure
	}
}

func getSocks5CMDBytes(cmd byte, addr string) ([]byte, error) {
	bs := new(bytes.Buffer)
	bs.Write([]byte{share.SocksVersion5, cmd, 0x00})
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = net.IP{0, 0, 0, 0}.String()
	}
	ip := net.ParseIP(host)
	p, _ := strconv.Atoi(port)
	if p < 0 || p > 65535 {
		return nil, share.ErrAddrInvalid(addr, "port invalid")
	}
	var atyp byte = 0x00
	if ip == nil {
		if len(host) > 255 {
			return nil, share.ErrAddrInvalid(addr, "host invalid")
		}
		bs.Write([]byte{share.Socks5AddrTypeDomain, byte(len(host))})
		bs.Write([]byte(host))
		bs.Write(binary.BigEndian.AppendUint16([]byte{}, uint16(p)))
	} else {
		xaddr := &net.TCPAddr{
			IP:   ip,
			Port: p,
			Zone: "",
		}
		ad := share.GetSocks5AddrBytes(xaddr)
		switch len(ad) {
		case 4 + 2:
			atyp = share.Socks5AddrTypeIPv4
		case 16 + 2:
			atyp = share.Socks5AddrTypeIPv6
		}
		bs.Write([]byte{atyp})
		bs.Write(ad)
	}
	return bs.Bytes(), nil
}

type Socks5PacketConn struct {
	net.PacketConn
	lifeConn  net.Conn //By definition, it is the life of the control udp conn
	socksAddr net.Addr
}

func (s5pc *Socks5PacketConn) keepLife() error {
	defer s5pc.Close()
	for {
		_, err := s5pc.lifeConn.Read(make([]byte, share.DefaultBufferSize))
		if err != nil {
			return err
		}
	}
}

func (s5pc *Socks5PacketConn) Close() error {
	s5pc.lifeConn.Close()
	return s5pc.PacketConn.Close()
}
func (s5pc *Socks5PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	b := share.MarshalSocks5UDPASSOCIATEData(p, addr)
	return s5pc.PacketConn.WriteTo(b, s5pc.socksAddr)
}
func (s5pc *Socks5PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := make([]byte, share.DefaultBufferSize)
	for {
		n1, raddr, err := s5pc.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		//Packets that do not need to come to other addresses
		if raddr.String() != s5pc.socksAddr.String() {
			continue
		} else {
			data, xaddr, err := share.UnmarshalSocks5UDPASSOCIATEData2(buf[:n1])
			if err != nil {
				return 0, nil, err
			}
			addr = xaddr
			copy(p, data)
			if len(p) > len(data) {
				n = len(data)
			} else {
				n = len(p)
			}
			break
		}
	}
	return n, addr, nil
}
