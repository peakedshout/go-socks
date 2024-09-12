package socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

type S5Auth struct {
	Socks5AuthNOAUTH   func(conn net.Conn) net.Conn
	Socks5AuthGSSAPI   func(conn net.Conn) net.Conn
	Socks5AuthPASSWORD *S5AuthPassword
	Socks5AuthIANA     [125]func(conn net.Conn) net.Conn
	Socks5AuthPRIVATE  [127]func(conn net.Conn) net.Conn
}

type socks5Config struct {
	proxyNetwork string
	proxyAddress string

	forward  Dialer
	uforward PacketListenerConfig

	auth *S5Auth
	cmd  byte

	bindCb BINDAddrCb
	udpCb  UDPDataHandler
}

func newSocks5Config(network string, address string, cmd byte, auth *S5Auth, forward Dialer, uforward PacketListenerConfig, bindCb BINDAddrCb, udpCb UDPDataHandler) (*socks5Config, error) {
	return &socks5Config{
		proxyNetwork: network,
		proxyAddress: address,
		forward:      forward,
		uforward:     uforward,
		auth:         auth,
		cmd:          cmd,
		bindCb:       bindCb,
		udpCb:        udpCb,
	}, nil
}

func (s5d *socks5Config) ListenPacket(network string, address string) (net.PacketConn, error) {
	return s5d.ListenPacketContext(context.Background(), network, address)
}

func (s5d *socks5Config) ListenPacketContext(ctx context.Context, network string, address string) (net.PacketConn, error) {
	err := s5d.checkSocks5CMD(socks5CMDUDPASSOCIATE)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	xctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := s5d.dialSocks5(ctx, xctx)
	if err != nil {
		return nil, err
	}
	conn, err = s5d.authSocks5(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	pconn, err := s5d.udpSocks5(ctx, conn, network, address)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return pconn, nil
}

func (s5d *socks5Config) Dial(network string, addr string) (net.Conn, error) {
	return s5d.DialContext(context.Background(), network, addr)
}

func (s5d *socks5Config) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	err := s5d.checkSocks5CMD(socks5CMDCONNECT, socks5CMDBIND)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	xctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := s5d.dialSocks5(ctx, xctx)
	if err != nil {
		return nil, err
	}
	conn, err = s5d.authSocks5(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	err = s5d.cmdSocks5(conn, network, addr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (s5d *socks5Config) dialSocks5(ctx, xctx context.Context) (conn net.Conn, err error) {
	if s5d.forward != nil {
		conn, err = s5d.forward.DialContext(ctx, s5d.proxyNetwork, s5d.proxyAddress)
		if err != nil {
			return nil, err
		}
	} else {
		dr := net.Dialer{}
		conn, err = dr.DialContext(ctx, s5d.proxyNetwork, s5d.proxyAddress)
		if err != nil {
			return nil, err
		}
	}
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-xctx.Done():
		}
	}()
	return conn, nil
}

func (s5d *socks5Config) cmdSocks5(conn net.Conn, network string, addr string) error {
	err := s5d.networkCheck(network)
	if err != nil {
		return err
	}
	b, err := s5d.getSocks5CMDBytes(s5d.cmd, addr)
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
	err = getSocks5RespErr(rep)
	if err != nil {
		return err
	}
	if s5d.cmd == socks5CMDBIND {
		xaddr, err := net.ResolveTCPAddr("", raddr)
		if xaddr.IP.IsUnspecified() {
			xaddr.IP = conn.RemoteAddr().(*net.TCPAddr).IP
		}
		if s5d.bindCb != nil {
			err = s5d.bindCb(xaddr)
			if err != nil {
				return err
			}
		}
		rep, _, err = s5d.readSocks5CMDResp(conn)
		if err != nil {
			return err
		}
		err = getSocks5RespErr(rep)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s5d *socks5Config) udpSocks5(ctx context.Context, conn net.Conn, network string, addr string) (net.PacketConn, error) {
	laddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, err
	}
	var uconn net.PacketConn
	if s5d.uforward != nil {
		uconn, err = s5d.uforward.ListenPacketContext(ctx, network, laddr.String())
		if err != nil {
			return nil, err
		}
	} else {
		lner := &net.ListenConfig{}
		uconn, err = lner.ListenPacket(ctx, network, laddr.String())
		if err != nil {
			return nil, err
		}
	}
	b, err := s5d.getSocks5CMDBytes(s5d.cmd, uconn.LocalAddr().String())
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
	err = getSocks5RespErr(rep)
	if err != nil {
		return nil, err
	}
	xaddr, _ := net.ResolveUDPAddr("", raddr)
	if xaddr.IP.IsUnspecified() {
		xaddr.IP = conn.RemoteAddr().(*net.TCPAddr).IP
	}
	pc := &socks5PacketConn{
		PacketConn: uconn,
		lifeConn:   conn,
		socksAddr:  xaddr,
		cb:         s5d.udpCb,
	}
	go pc.keepLife()
	return pc, nil
}

func (s5d *socks5Config) authSocks5(conn net.Conn) (net.Conn, error) {
	b, err := s5d.getSocks5AuthBytes()
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(b)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	if buf[0] != socksVersion5 {
		return nil, ErrSocksMessageParsingFailure
	}
	if buf[1] == socks5METHODCodeNOAUTH {
		if s5d.auth.Socks5AuthNOAUTH == nil {
			return nil, ErrSocks5AuthRejected
		}
		if nconn := s5d.auth.Socks5AuthNOAUTH(conn); nconn != nil {
			return nconn, nil
		} else {
			return nil, ErrSocks5AuthRejected
		}
	} else if buf[1] == socks5METHODCodeGSSAPI {
		if s5d.auth.Socks5AuthGSSAPI == nil {
			return nil, ErrSocks5AuthRejected
		}
		if nconn := s5d.auth.Socks5AuthGSSAPI(conn); nconn != nil {
			return nconn, nil
		} else {
			return nil, ErrSocks5AuthRejected
		}
	} else if buf[1] == socks5METHODCodePASSWORD {
		return s5d.authSocks5Password(conn)
	} else if buf[1] >= socks5METHODCodeIANA && buf[1] < socks5METHODCodePRIVATE {
		authFn := s5d.auth.Socks5AuthIANA[int(buf[1]-socks5METHODCodeIANA)]
		if authFn == nil {
			return nil, ErrSocks5AuthRejected
		}
		if nconn := authFn(conn); nconn != nil {
			return nconn, nil
		} else {
			return nil, ErrSocks5AuthRejected
		}
	} else if buf[1] >= socks5METHODCodePRIVATE && buf[1] < socks5RETHODCodeRejected {
		authFn := s5d.auth.Socks5AuthPRIVATE[int(buf[1]-socks5METHODCodePRIVATE)]
		if authFn == nil {
			return nil, ErrSocks5AuthRejected
		}
		if nconn := authFn(conn); nconn != nil {
			return nconn, nil
		} else {
			return nil, ErrSocks5AuthRejected
		}
	} else {
		return nil, ErrSocks5NOACCEPTABLEMETHODS
	}
}

func (s5d *socks5Config) authSocks5Password(conn net.Conn) (net.Conn, error) {
	if s5d.auth.Socks5AuthPASSWORD == nil {
		return nil, ErrSocks5AuthRejected
	}
	bs := new(bytes.Buffer)
	bs.Write([]byte{socks5AuthPasswordVER})
	bs.Write([]byte{byte(len(s5d.auth.Socks5AuthPASSWORD.User))})
	bs.Write([]byte(s5d.auth.Socks5AuthPASSWORD.User))
	bs.Write([]byte{byte(len(s5d.auth.Socks5AuthPASSWORD.Password))})
	bs.Write([]byte(s5d.auth.Socks5AuthPASSWORD.Password))
	_, err := conn.Write(bs.Bytes())
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	if buf[0] != socks5AuthPasswordVER {
		return nil, ErrSocksMessageParsingFailure
	}
	switch buf[1] {
	case socks5AuthRespPasswordSuccess:
		if s5d.auth.Socks5AuthPASSWORD.Cb != nil {
			conn = s5d.auth.Socks5AuthPASSWORD.Cb(conn)
		}
		return conn, nil
	case socks5AuthRespPasswordFailure:
		return nil, ErrSocks5AuthRejected
	default:
		return nil, ErrSocksMessageParsingFailure
	}
}

func (s5d *socks5Config) getSocks5AuthBytes() ([]byte, error) {
	if s5d.auth == nil {
		return nil, ErrSocks5NeedMETHODSAuth
	}
	bs := new(bytes.Buffer)
	bs.Write([]byte{socksVersion5, 0x00})
	var l byte = 0x00
	if s5d.auth.Socks5AuthNOAUTH != nil {
		bs.Write([]byte{socks5METHODCodeNOAUTH})
		l++
	}
	if s5d.auth.Socks5AuthGSSAPI != nil {
		bs.Write([]byte{socks5METHODCodeGSSAPI})
		l++
	}
	if s5d.auth.Socks5AuthPASSWORD != nil {
		bs.Write([]byte{socks5METHODCodePASSWORD})
		l++
	}
	for i, one := range s5d.auth.Socks5AuthIANA {
		if one != nil {
			bs.Write([]byte{byte(socks5METHODCodeIANA + i)})
			l++
		}
	}
	for i, one := range s5d.auth.Socks5AuthPRIVATE {
		if one != nil {
			bs.Write([]byte{byte(socks5METHODCodePRIVATE + i)})
			l++
		}
	}
	if l == 0x00 {
		return nil, ErrSocks5NeedMETHODSAuth
	}
	b := bs.Bytes()
	b[1] = l
	return b, nil
}

func (s5d *socks5Config) readSocks5CMDResp(conn net.Conn) (rep byte, addr string, err error) {
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return 0, "", err
	}
	if buf[0] != socksVersion5 || buf[2] != 0x00 {
		return 0, "", ErrSocksMessageParsingFailure
	}
	rep = buf[1]
	switch buf[3] {
	case socks5AddrTypeIPv4:
		buf = make([]byte, 256)
		_, err = io.ReadFull(conn, buf[:4+2])
		if err != nil {
			return 0, "", err
		}
		addr = fmt.Sprintf("%s:%d", net.IP(buf[:4]).String(), binary.BigEndian.Uint16(buf[4:4+2]))
		return rep, addr, nil
	case socks5AddrTypeIPv6:
		buf = make([]byte, 256)
		_, err = io.ReadFull(conn, buf[:16+2])
		if err != nil {
			return 0, "", err
		}
		addr = fmt.Sprintf("[%s]:%d", net.IP(buf[:16]).String(), binary.BigEndian.Uint16(buf[16:16+2]))
		return rep, addr, nil
	default:
		return 0, "", ErrSocksMessageParsingFailure
	}
}

func (s5d *socks5Config) getSocks5CMDBytes(cmd byte, addr string) ([]byte, error) {
	bs := new(bytes.Buffer)
	bs.Write([]byte{socksVersion5, cmd, 0x00})
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
		return nil, ErrAddrInvalid(addr, "port invalid")
	}
	var atyp byte = 0x00
	if ip == nil {
		if len(host) > 255 {
			return nil, ErrAddrInvalid(addr, "host invalid")
		}
		bs.Write([]byte{socks5AddrTypeDomain, byte(len(host))})
		bs.Write([]byte(host))
		bs.Write(binary.BigEndian.AppendUint16([]byte{}, uint16(p)))
	} else {
		xaddr := &net.TCPAddr{
			IP:   ip,
			Port: p,
			Zone: "",
		}
		ad := getSocks5AddrBytes(xaddr)
		switch len(ad) {
		case 4 + 2:
			atyp = socks5AddrTypeIPv4
		case 16 + 2:
			atyp = socks5AddrTypeIPv6
		}
		bs.Write([]byte{atyp})
		bs.Write(ad)
	}
	return bs.Bytes(), nil
}

func (s5d *socks5Config) checkSocks5CMD(cmd ...byte) error {
	for _, b := range cmd {
		if s5d.cmd == b {
			return nil
		}
	}
	return ErrSocks5CMDNotSupport
}

func (s5d *socks5Config) networkCheck(network string) error {
	switch s5d.cmd {
	case socks5CMDCONNECT, socks5CMDBIND:
		switch network {
		case "tcp", "tcp4", "tcp6":
			return nil
		}
	case socks5CMDUDPASSOCIATE:
		switch network {
		case "tcp", "tcp4", "tcp6":
			return nil
		}
	}
	return ErrNetworkNotSupport
}

type socks5PacketConn struct {
	net.PacketConn
	lifeConn  net.Conn
	socksAddr net.Addr
	cb        UDPDataHandler
}

func (s5pc *socks5PacketConn) keepLife() error {
	defer s5pc.Close()
	buf := make([]byte, defaultBufferSize)
	for {
		_, err := s5pc.lifeConn.Read(buf)
		if err != nil {
			return err
		}
	}
}

func (s5pc *socks5PacketConn) Close() error {
	_ = s5pc.lifeConn.Close()
	return s5pc.PacketConn.Close()
}

func (s5pc *socks5PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if s5pc.cb != nil {
		p, err = s5pc.cb.Encode(p)
		if err != nil {
			return 0, err
		}
	}
	b := marshalSocks5UDPASSOCIATEData(p, addr)
	n, err = s5pc.PacketConn.WriteTo(b, s5pc.socksAddr)
	if err != nil {
		s5pc.errClosed(err)
		return 0, err
	}
	return n, nil
}

func (s5pc *socks5PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		n1, raddr, err := s5pc.PacketConn.ReadFrom(p)
		if err != nil {
			s5pc.errClosed(err)
			return 0, nil, err
		}
		//Packets that do not need to come to other addresses
		if raddr.String() != s5pc.socksAddr.String() {
			continue
		} else {
			data, xaddr, err := unmarshalSocks5UDPASSOCIATEData2(p[:n1])
			if err != nil {
				continue
			}
			if s5pc.cb != nil {
				data, err = s5pc.cb.Decode(data)
				if err != nil {
					continue
				}
			}
			return copy(p, data), xaddr, nil
		}
	}
}

func (s5pc *socks5PacketConn) errClosed(err error) {
	if errors.Is(err, net.ErrClosed) {
		_ = s5pc.Close()
	}
}
