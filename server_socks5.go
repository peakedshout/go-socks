package socks

import (
	"context"
	"io"
	"net"
	"strconv"
)

func (s *Server) handleSocks5(conn *serverConn) (err error) {
	buf := make([]byte, socks5NMETHODSLen)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return err
	}
	ml := int(buf[0])
	buf = make([]byte, ml)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return err
	}
	err = s.handleSocks5Auth(conn, buf)
	if err != nil {
		return err
	}
	return s.handleSocks5CMD(conn)
}

func (s *Server) handleSocks5Auth(conn *serverConn, methods []byte) (err error) {
	m := make(map[byte]bool)
	for _, one := range methods {
		m[one] = true
	}
	var method byte = socks5RETHODCodeRejected
	var methodCode byte = socks5RETHODCodeRejected
	for _, one := range s.cfg.Socks5AuthCb.socks5AuthPriority {
		if method != 0xFF {
			break
		}
		switch one {
		case socks5METHODCodeNOAUTH, socks5METHODCodeGSSAPI, socks5METHODCodePASSWORD:
			if m[one] {
				method = one
				methodCode = one
			}
		case socks5METHODCodeIANA:
			for i := one; i < socks5METHODCodePRIVATE; i++ {
				if m[i] {
					method = one
					methodCode = i
					break
				}
			}
		case socks5METHODCodePRIVATE:
			for i := one; i < socks5RETHODCodeRejected; i++ {
				if m[i] {
					method = one
					methodCode = i
					break
				}
			}
		}
	}
	err = conn.writeSocks5AuthResp(methodCode)
	if err != nil {
		return err
	}
	switch method {
	case socks5METHODCodeNOAUTH:
		if nconn := s.cfg.Socks5AuthCb.Socks5AuthNOAUTH(conn.Conn); nconn != nil {
			conn.Conn = nconn
			return nil
		} else {
			return ErrSocks5AuthRejected
		}
	case socks5METHODCodeGSSAPI:
		if nconn := s.cfg.Socks5AuthCb.Socks5AuthGSSAPI(conn.Conn); nconn != nil {
			conn.Conn = nconn
			return nil
		} else {
			return ErrSocks5AuthRejected
		}
	case socks5METHODCodePASSWORD:
		buf := make([]byte, socks5VERLen+socks5AuthPASSWORDUserLen)
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			return ErrSocks5AuthRejected
		}
		if buf[0] != socks5AuthPasswordVER {
			return ErrSocks5AuthRejected
		}
		ul := int(buf[1])
		buf = make([]byte, ul+socks5AuthPASSWORDPasswordLen)
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			return ErrSocks5AuthRejected
		}
		user := string(buf[:ul])
		pl := int(buf[ul])
		buf = make([]byte, pl)
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			return ErrSocks5AuthRejected
		}
		password := string(buf[:])
		nconn := s.cfg.Socks5AuthCb.Socks5AuthPASSWORD(conn.Conn, S5AuthPassword{
			User:     user,
			Password: password,
		})
		if nconn != nil {
			err = conn.writeSocks5AuthPasswordResp(true)
			if err != nil {
				return err
			}
			conn.Conn = nconn
			return nil
		} else {
			_ = conn.writeSocks5AuthPasswordResp(false)
			return ErrSocks5AuthRejected
		}
	case socks5METHODCodeIANA:
		if nconn := s.cfg.Socks5AuthCb.Socks5AuthIANA[int(methodCode-socks5METHODCodeIANA)](conn.Conn); nconn != nil {
			conn.Conn = nconn
			return nil
		} else {
			return ErrSocks5AuthRejected
		}
	case socks5METHODCodePRIVATE:
		if nconn := s.cfg.Socks5AuthCb.Socks5AuthPRIVATE[int(methodCode-socks5METHODCodePRIVATE)](conn.Conn); nconn != nil {
			conn.Conn = nconn
			return nil
		} else {
			return ErrSocks5AuthRejected
		}
	case socks5RETHODCodeRejected:
		return ErrSocks5AuthRejected
	}
	return nil
}

func (s *Server) handleSocks5CMD(conn *serverConn) (err error) {
	buf := make([]byte, socks5VERLen+socks5CMDLen+socks5RSVLen+socks5ATYPLen)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		_ = conn.writeSocks5CMDResp(socks5CMDRespFailure, conn.LocalAddr())
		return err
	}
	ver, cmd, rsv, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != socksVersion5 || rsv != 0x00 {
		_ = conn.writeSocks5CMDResp(socks5CMDRespConnNotAllowed, conn.LocalAddr())
		return ErrSocksMessageParsingFailure
	}
	addr, err := conn.getSocks5AddrInfo(atyp)
	if err != nil {
		_ = conn.writeSocks5CMDResp(socks5CMDRespAddNotSupported, conn.LocalAddr())
		return err
	}
	switch cmd {
	case socks5CMDCONNECT:
		if !s.cfg.CMDConfig.SwitchCMDCONNECT {
			_ = conn.writeSocks5CMDResp(socks5CMDRespCMDNotSupported, conn.LocalAddr())
			return ErrSocks5CMDNotSupport
		}
		return s.handleSocks5CMDCONNECT(conn, addr)
	case socks5CMDBIND:
		if !s.cfg.CMDConfig.SwitchCMDBIND {
			_ = conn.writeSocks5CMDResp(socks5CMDRespCMDNotSupported, conn.LocalAddr())
			return ErrSocks5CMDNotSupport
		}
		return s.handleSocks5CMDBind(conn, addr)
	case socks5CMDUDPASSOCIATE:
		if !s.cfg.CMDConfig.SwitchCMDUDPASSOCIATE {
			_ = conn.writeSocks5CMDResp(socks5CMDRespCMDNotSupported, conn.LocalAddr())
			return ErrSocks5CMDNotSupport
		}
		return s.handleSocks5CMDUDPASSOCIATE(conn, addr)
	default:
		_ = conn.writeSocks5CMDResp(socks5CMDRespCMDNotSupported, conn.LocalAddr())
		return ErrSocksMessageParsingFailure
	}
}

func (s *Server) handleSocks5CMDCONNECT(conn *serverConn, addr string) error {
	var handler CMDCONNECTHandler
	ctx := s.ctx
	if s.cfg.DialTimeout != 0 {
		tmpctx, cancel := context.WithTimeout(s.ctx, s.cfg.DialTimeout)
		defer cancel()
		ctx = tmpctx
	}
	if s.cfg.CMDConfig.CMDCONNECTHandler != nil {
		handler = s.cfg.CMDConfig.CMDCONNECTHandler
	} else {
		handler = DefaultCMDCONNECTHandler
	}
	cc, err := handler(ctx, addr)
	if err != nil {
		_ = conn.writeSocks5CMDResp(socks5CMDRespNetworkUnreachable, conn.LocalAddr())
		return err
	}
	conn.copyConn = cc
	return conn.writeSocks5CMDResp(socks5CMDRespSuccess, conn.LocalAddr())
}

func (s *Server) handleSocks5CMDBind(conn *serverConn, addr string) error {
	var handler CMDBINDHandler
	if s.cfg.CMDConfig.CMDBINDHandler != nil {
		handler = s.cfg.CMDConfig.CMDBINDHandler
	} else {
		handler = DefaultCMDBINDHandler
	}
	ch := make(chan net.Conn)
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.BindTimeout)
	defer cancel()
	laddr, err := handler(ctx, ch, addr)
	if err != nil {
		_ = conn.writeSocks5CMDResp(socks5CMDRespHostUnreachable, conn.LocalAddr())
		return err
	}
	err = conn.writeSocks5CMDResp(socks5CMDRespSuccess, laddr)
	if err != nil {
		err = conn.writeSocks5CMDResp(socks5CMDRespFailure, laddr)
		return err
	}
	select {
	case <-ctx.Done():
		_ = conn.writeSocks5CMDResp(socks5CMDRespTTLExpired, conn.LocalAddr())
		return ctx.Err()
	case bc, ok := <-ch:
		if !ok {
			err = conn.writeSocks5CMDResp(socks5CMDRespFailure, laddr)
			return err
		}
		conn.copyConn = bc
		return conn.writeSocks5CMDResp(socks5CMDRespSuccess, bc.RemoteAddr())
	}
}

func (s *Server) handleSocks5CMDUDPASSOCIATE(conn *serverConn, addr string) error {
	var checkAddr net.Addr
	rhost, rport, err := net.SplitHostPort(addr)
	if err != nil {
		_ = conn.writeSocks5CMDResp(socks5CMDRespHostUnreachable, conn.LocalAddr())
		return err
	}
	ip := net.ParseIP(rhost)
	if (ip != nil && ip.IsUnspecified()) && rport == "0" {
		checkAddr = nil
	} else {
		uaddr := &net.UDPAddr{}
		uaddr.IP = ip
		if ip != nil && ip.IsUnspecified() {
			rthost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			uaddr.IP = net.ParseIP(rthost)
		}
		port, _ := strconv.Atoi(rport)
		uaddr.Port = port
		checkAddr = uaddr
	}

	var handler CMDCMDUDPASSOCIATEHandler
	if s.cfg.CMDConfig.CMDBINDHandler != nil {
		handler = s.cfg.CMDConfig.CMDCMDUDPASSOCIATEHandler
	} else {
		handler = DefaultCMDCMDUDPASSOCIATEHandler
	}
	ctx := s.ctx
	if s.cfg.UdpTimeout != 0 {
		ctx = context.WithValue(s.ctx, udpTimeoutKey, s.cfg.UdpTimeout)
	}
	pconn, err := handler(ctx, checkAddr)
	if err != nil {
		_ = conn.writeSocks5CMDResp(socks5CMDRespHostUnreachable, conn.LocalAddr())
		return err
	}
	conn.udpConn = pconn
	err = conn.writeSocks5CMDResp(socks5CMDRespSuccess, pconn.LocalAddr())
	if err != nil {
		_ = conn.writeSocks5CMDResp(socks5CMDRespFailure, pconn.LocalAddr())
		return err
	}
	return nil
}
