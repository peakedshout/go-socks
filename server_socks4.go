package socks

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

func (s *Server) handleSocks4(conn *serverConn) (err error) {
	var otherCode byte
	defer func() {
		if err != nil {
			if otherCode == 0x00 {
				_ = conn.writeSocks4Resp(socks4RespCodeRejectedFailed, conn.LocalAddr())
			} else {
				_ = conn.writeSocks4Resp(otherCode, conn.LocalAddr())
			}
		}
	}()
	reader := bufio.NewReader(conn)
	buf := make([]byte, 7)
	_, err = io.ReadFull(reader, buf)
	if err != nil {
		return err
	}
	bs, err := reader.ReadBytes(socks4ByteNull)
	if err != nil {
		return err
	}
	//userid check
	userId := bs[:len(bs)-1]
	if s.cfg.Socks4AuthCb.Socks4UserIdAuth != nil {
		nconn, code := s.cfg.Socks4AuthCb.Socks4UserIdAuth(conn.Conn, userId)
		if code == socks4RespCodeGranted {
			conn.Conn = nconn
		} else if code == socks4RespCodeRejectedClientIdentd || code == socks4RespCodeRejectedDifferentUserId {
			otherCode = byte(code)
			return ErrSocks4UserIdInvalid
		} else {
			otherCode = socks4RespCodeRejectedFailed
			return ErrSocks4UserIdInvalid
		}
	}

	//parse addr
	addr := ""
	if buf[3] == 0 && buf[4] == 0 && buf[5] == 0 && buf[6] != 0 {
		//socks4a
		bs2, err := reader.ReadBytes(socks4ByteNull)
		if err != nil {
			return err
		}
		if len(bs2) < 2 {
			return ErrSocksMessageParsingFailure
		}
		addr = fmt.Sprintf("%s:%d", string(bs2[:len(bs2)-1]), binary.BigEndian.Uint16(buf[socks4CDLen:socks4CDLen+socks4DSTPORTLen]))
	} else {
		addr = fmt.Sprintf("%s:%d", net.IP(buf[socks4CDLen+socks4DSTPORTLen:socks4CDLen+socks4DSTPORTLen+socks4DSTIPLen]).String(), binary.BigEndian.Uint16(buf[socks4CDLen:socks4CDLen+socks4DSTPORTLen]))
	}

	switch buf[0] {
	case socks4CDCONNECT:
		if !s.cfg.CMDConfig.SwitchCMDCONNECT {
			return ErrSocks4CDNotSupport
		}
		err = s.handleSocks4CDCONNECT(conn, addr)
		if err != nil {
			return err
		}
		return nil
	case socks4CDBIND:
		if !s.cfg.CMDConfig.SwitchCMDBIND {
			return ErrSocks4CDNotSupport
		}
		err = s.handleSocks4CDBIND(conn, addr)
		if err != nil {
			return err
		}
		return nil
	default:
		return ErrSocksMessageParsingFailure
	}
}

func (s *Server) handleSocks4CDCONNECT(conn *serverConn, addr string) error {
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
		return err
	}
	conn.copyConn = cc
	return conn.writeSocks4Resp(socks4RespCodeGranted, conn.LocalAddr())
}

func (s *Server) handleSocks4CDBIND(conn *serverConn, addr string) error {
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
		return err
	}
	err = conn.writeSocks4Resp(socks4RespCodeGranted, laddr)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case bc := <-ch:
		conn.copyConn = bc
		return conn.writeSocks4Resp(socks4RespCodeGranted, bc.RemoteAddr())
	}
}
