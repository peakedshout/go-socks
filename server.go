package socks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"time"
)

type Server struct {
	cfg *ServerConfig

	ctx    context.Context
	cancel context.CancelFunc
}

func NewServer(cfg *ServerConfig) (*Server, error) {
	return NewServerContext(context.Background(), cfg)
}

func NewServerContext(ctx context.Context, cfg *ServerConfig) (*Server, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg == nil {
		return nil, ErrNeedServerConfig
	}
	if !cfg.VersionSwitch.SwitchSocksVersion4 && !cfg.VersionSwitch.SwitchSocksVersion5 {
		return nil, ErrMeaninglessServiceVersion
	}
	if !cfg.CMDConfig.SwitchCMDCONNECT && !cfg.CMDConfig.SwitchCMDBIND && !cfg.CMDConfig.SwitchCMDUDPASSOCIATE {
		return nil, ErrMeaninglessServiceCmd
	}
	if cfg.BindTimeout == 0 {
		cfg.BindTimeout = 5 * time.Second
	}
	if cfg.UdpTimeout == 0 {
		cfg.UdpTimeout = 30 * time.Second
	}
	s := &Server{
		cfg: cfg,
	}
	err := s.handleSock5AuthPriority()
	if err != nil {
		return nil, err
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	return s, nil
}

func (s *Server) Serve(ln net.Listener) error {
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	return s.listen(ln)
}

func (s *Server) ListenAndServe(network string, addr string) error {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

func (s *Server) Close() error {
	s.cancel()
	return s.ctx.Err()
}

func (s *Server) listen(ln net.Listener) error {
	ctx, canecl := context.WithCancel(s.ctx)
	defer canecl()
	waitFunc(ctx, func() {
		_ = ln.Close()
	})
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	sc := &serverConn{
		Conn: conn,
	}
	defer sc.Close()
	ctx, cl := context.WithCancel(s.ctx)
	defer cl()
	waitFunc(ctx, func() {
		_ = conn.Close()
	})
	buf := make([]byte, socksVersionLen)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return
	}

	switch buf[0] {
	case socksVersion4:
		err = s.handleSocks4(sc)
		if err != nil {
			return
		}
	case socksVersion5:
		err = s.handleSocks5(sc)
		if err != nil {
			return
		}
	default:
		return
	}
	sc.ioCopy()
}

func (s *Server) handleSock5AuthPriority() error {
	if !s.cfg.VersionSwitch.SwitchSocksVersion5 {
		return nil
	}
	type unit struct {
		priority int8
		code     byte
	}
	var sl []*unit
	if s.cfg.Socks5AuthCb.Socks5AuthNOAUTH != nil {
		sl = append(sl, &unit{priority: s.cfg.Socks5AuthCb.Socks5AuthNOAUTHPriority, code: socks5METHODCodeNOAUTH})
	}
	if s.cfg.Socks5AuthCb.Socks5AuthGSSAPI != nil {
		sl = append(sl, &unit{priority: s.cfg.Socks5AuthCb.Socks5AuthGSSAPIPriority, code: socks5METHODCodeGSSAPI})
	}
	if s.cfg.Socks5AuthCb.Socks5AuthPASSWORD != nil {
		sl = append(sl, &unit{priority: s.cfg.Socks5AuthCb.Socks5AuthPASSWORDPriority, code: socks5METHODCodePASSWORD})
	}
	for i, one := range s.cfg.Socks5AuthCb.Socks5AuthIANA {
		if one != nil {
			sl = append(sl, &unit{priority: s.cfg.Socks5AuthCb.Socks5AuthIANAPriority[i], code: byte(socks5METHODCodeIANA + i)})
		}
	}
	for i, one := range s.cfg.Socks5AuthCb.Socks5AuthPRIVATE {
		if one != nil {
			sl = append(sl, &unit{priority: s.cfg.Socks5AuthCb.Socks5AuthPRIVATEPriority[i], code: byte(socks5METHODCodePRIVATE + i)})
		}
	}
	if len(sl) == 0 {
		return ErrSocks5NeedMETHODSAuth
	}
	sort.Slice(sl, func(i, j int) bool {
		return sl[i].priority < sl[j].priority
	})
	for _, one := range sl {
		s.cfg.Socks5AuthCb.socks5AuthPriority = append(s.cfg.Socks5AuthCb.socks5AuthPriority, one.code)
	}
	return nil
}

type serverConn struct {
	net.Conn
	copyConn net.Conn
	udpConn  net.PacketConn
}

func (c *serverConn) Close() error {
	if c.copyConn != nil {
		_ = c.copyConn.Close()
	}
	if c.udpConn != nil {
		_ = c.udpConn.Close()
	}
	return c.Conn.Close()
}

func (c *serverConn) ioCopy() {
	copyBuffer := io.Discard
	if c.udpConn != nil {
		defer c.udpConn.Close()
		go func() {
			buf := make([]byte, 32*1024)
			for {
				n, addr, err := c.udpConn.ReadFrom(buf)
				if err != nil {
					return
				}
				_, err = c.udpConn.WriteTo(buf[:n], addr)
				if err != nil {
					return
				}
			}
		}()
	}
	if c.copyConn != nil {
		defer c.copyConn.Close()
		go io.Copy(c.Conn, c.copyConn)
		copyBuffer = c.copyConn
	}
	_, _ = io.Copy(copyBuffer, c.Conn)
}

func (c *serverConn) writeSocks4Resp(code byte, addr net.Addr) error {
	bs := append([]byte{0x00, code}, getSocks4AddrBytes(addr)...)
	_, err := c.Write(bs)
	return err
}

func (c *serverConn) writeSocks5CMDResp(code byte, addr net.Addr) error {
	ad := getSocks5AddrBytes(addr)
	var atyp byte = 0x00
	switch len(ad) {
	case 4 + 2:
		atyp = socks5AddrTypeIPv4
	case 16 + 2:
		atyp = socks5AddrTypeIPv6
	}
	_, err := c.Write(append([]byte{socksVersion5, code, 0x00, atyp}, ad...))
	return err
}

func (c *serverConn) writeSocks5AuthResp(method byte) error {
	_, err := c.Write([]byte{socksVersion5, method})
	return err
}

func (c *serverConn) writeSocks5AuthPasswordResp(state bool) error {
	var code byte = socks5AuthRespPasswordSuccess
	if !state {
		code = socks5AuthRespPasswordFailure
	}
	_, err := c.Write([]byte{socks5AuthPasswordVER, code})
	return err
}

func (c *serverConn) getSocks5AddrInfo(atyp byte) (string, error) {
	buf := make([]byte, 256)
	switch atyp {
	case socks5AddrTypeIPv4:
		_, err := io.ReadFull(c, buf[:4+2])
		if err != nil {
			return "", err
		}
		addr := fmt.Sprintf("%s:%d", net.IP(buf[:4]).String(), binary.BigEndian.Uint16(buf[4:4+2]))
		return addr, nil
	case socks5AddrTypeDomain:
		_, err := io.ReadFull(c, buf[:1])
		if err != nil {
			return "", err
		}
		addrL := int(buf[0])
		_, err = io.ReadFull(c, buf[:addrL+2])
		if err != nil {
			return "", err
		}
		addr := fmt.Sprintf("%s:%d", string(buf[:addrL]), binary.BigEndian.Uint16(buf[addrL:addrL+2]))
		return addr, nil
	case socks5AddrTypeIPv6:
		_, err := io.ReadFull(c, buf[:16+2])
		if err != nil {
			return "", err
		}
		addr := fmt.Sprintf("[%s]:%d", net.IP(buf[:16]).String(), binary.BigEndian.Uint16(buf[16:16+2]))
		return addr, nil
	default:
		return "", ErrSocksMessageParsingFailure
	}
}
