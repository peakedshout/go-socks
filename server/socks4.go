package server

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"github.com/peakedshout/go-CFC/loger"
	"github.com/peakedshout/go-socks/share"
	"io"
	"net"
	"time"
)

func (c *Conn) handleSocks4() (err error) {
	var otherCode byte
	defer func() {
		if err != nil {
			if otherCode == 0x00 {
				c.writeSocks4Resp(share.Socks4RespCodeRejectedFailed, c.LocalAddr())
			} else {
				c.writeSocks4Resp(otherCode, c.LocalAddr())
			}
		}
	}()

	reader := bufio.NewReader(c)
	buf := make([]byte, 7)
	_, err = io.ReadFull(reader, buf)
	if err != nil {
		loger.SetLogTrace(err)
		return err
	}

	bs, err := reader.ReadBytes(share.Socks4ByteNull)
	if err != nil {
		loger.SetLogTrace(err)
		return err
	}
	//userid check
	userId := bs[:len(bs)-1]
	if c.ss.config.SocksAuthCb.Socks4UserIdAuth != nil {
		code := c.ss.config.SocksAuthCb.Socks4UserIdAuth(userId)
		if code == share.Socks4RespCodeGranted {
		} else if code == share.Socks4RespCodeRejectedClientIdentd || code == share.Socks4RespCodeRejectedDifferentUserId {
			otherCode = code
			err = share.ErrSocks4UserIdInvalid
			loger.SetLogTrace(err)
			return err
		} else {
			otherCode = share.Socks4RespCodeRejectedFailed
			err = share.ErrSocks4UserIdInvalid
			loger.SetLogTrace(err)
			return err
		}
	}

	//parse addr
	addr := ""
	if buf[3] == 0 && buf[4] == 0 && buf[5] == 0 && buf[6] != 0 {
		//socks4a
		bs2, err := reader.ReadBytes(share.Socks4ByteNull)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		if len(bs2) < 2 {
			err = share.ErrSocksMessageParsingFailure
			loger.SetLogTrace(err)
			return err
		}
		addr = fmt.Sprintf("%s:%d", string(bs2[:len(bs2)-1]), binary.BigEndian.Uint16(buf[share.Socks4CDLen:share.Socks4CDLen+share.Socks4DSTPORTLen]))
	} else {
		addr = fmt.Sprintf("%s:%d", net.IP(buf[share.Socks4CDLen+share.Socks4DSTPORTLen:share.Socks4CDLen+share.Socks4DSTPORTLen+share.Socks4DSTIPLen]).String(), binary.BigEndian.Uint16(buf[share.Socks4CDLen:share.Socks4CDLen+share.Socks4DSTPORTLen]))
	}

	switch buf[0] {
	case share.Socks4CDCONNECT:
		if !c.ss.config.CMDSwitch.SwitchCMDBIND {
			err = share.ErrCmdNotSupport
			loger.SetLogTrace(err)
			return err
		}
		err = c.handleSocks4CDCONNECT(addr)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		return nil
	case share.Socks4CDBIND:
		if !c.ss.config.CMDSwitch.SwitchCMDBIND {
			err = share.ErrCmdNotSupport
			loger.SetLogTrace(err)
			return err
		}
		err = c.handleSocks4CDBIND(addr)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		return nil
	default:
		err = share.ErrSocksMessageParsingFailure
		return err
	}
}

func (c *Conn) handleSocks4CDCONNECT(addr string) error {
	if c.ss.config.RelayConfig != nil {
		dr := net.Dialer{Timeout: c.ss.config.DialTimeout}
		conn, err := dr.DialContext(c.ctx, "tcp", c.ss.config.RelayConfig.Addr)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		if c.ss.config.RelayConfig.RelayTimeout != 0 {
			conn.SetDeadline(time.Now().Add(c.ss.config.RelayConfig.RelayTimeout))
			defer conn.SetDeadline(time.Time{})
		}
		c.copyConn = share.NewCopyConn(conn)
		c.keepEncrypt = c.ss.config.RelayConfig.KeepEncrypt
		c.reader = bufio.NewReader(c.copyConn)
		c.key = c.ss.config.RelayConfig.key
		err = c.writeCMsg(share.HeaderCMDCONNECT, "", 200, share.CMDInfo{Addr: addr, KeepEncrypt: c.keepEncrypt})
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		cMsg, err := c.key.ReadCMsg(c.reader, nil, nil)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		err = cMsg.CheckConnMsgHeaderAndCode(share.HeaderCMDCONNECT, 200)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
	} else {
		dr := net.Dialer{Timeout: c.ss.config.DialTimeout}
		conn, err := dr.DialContext(c.ctx, "tcp", addr)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		c.copyConn = share.NewCopyConn(conn)
	}
	go c.readFromCopyStream()
	return c.writeSocks4Resp(share.Socks4RespCodeGranted, c.LocalAddr())
}

func (c *Conn) handleSocks4CDBIND(addr string) error {
	var oaddr net.Addr
	if c.ss.config.RelayConfig != nil {
		dr := net.Dialer{Timeout: c.ss.config.DialTimeout}
		conn, err := dr.DialContext(c.ctx, "tcp", c.ss.config.RelayConfig.Addr)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		if c.ss.config.RelayConfig.RelayTimeout != 0 {
			conn.SetDeadline(time.Now().Add(c.ss.config.RelayConfig.RelayTimeout))
			defer conn.SetDeadline(time.Time{})
		}
		c.copyConn = share.NewCopyConn(conn)
		c.keepEncrypt = c.ss.config.RelayConfig.KeepEncrypt
		c.reader = bufio.NewReader(c.copyConn)
		c.key = c.ss.config.RelayConfig.key
		err = c.writeCMsg(share.HeaderCMDBIND, "", 200, share.CMDInfo{Addr: addr, KeepEncrypt: c.keepEncrypt})
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		cMsg, err := c.key.ReadCMsg(c.reader, nil, nil)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		err = cMsg.CheckConnMsgHeaderAndCode(share.HeaderCMDBIND, 200)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		var info share.CMDInfo
		err = cMsg.Unmarshal(&info)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		raddr, err := net.ResolveTCPAddr("", info.Addr)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		if raddr.IP.IsUnspecified() {
			raddr.IP = c.copyConn.RemoteAddr().(*net.TCPAddr).IP
		}
		err = c.writeSocks4Resp(share.Socks4RespCodeGranted, raddr)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		cMsg, err = c.key.ReadCMsg(c.reader, nil, nil)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		err = cMsg.CheckConnMsgHeaderAndCode(share.HeaderCMDBIND, 200)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		err = cMsg.Unmarshal(&info)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		oaddr, err = net.ResolveTCPAddr("", info.Addr)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
	} else {
		lner := net.ListenConfig{}
		ln, err := lner.Listen(c.ctx, "tcp", "")
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		go func() {
			defer ln.Close()
			for {
				conn, err := ln.Accept()
				if err != nil {
					loger.SetLogTrace(err)
					return
				}
				if conn.RemoteAddr().String() != addr {
					conn.Close()
				} else {
					c.copyConn = share.NewCopyConn(conn)
					c.ctxCancel()
					break
				}
			}
		}()
		err = c.writeSocks4Resp(share.Socks4RespCodeGranted, ln.Addr())
		if err != nil {
			loger.SetLogDebug(err)
			return err
		}
		select {
		case <-c.ctx.Done():
		case <-time.After(c.ss.config.BindTimeout):
			err = share.ErrTimeout
			loger.SetLogDebug(err)
			return err
		}
		if c.copyConn == nil {
			return net.ErrClosed
		}
		oaddr = c.copyConn.RemoteAddr()
	}
	go c.readFromCopyStream()
	return c.writeSocks4Resp(share.Socks4RespCodeGranted, oaddr)
}

func (c *Conn) writeSocks4Resp(code byte, addr net.Addr) error {
	bs := append([]byte{0x00, code}, share.GetSocks4AddrBytes(addr)...)
	_, err := c.Write(bs)
	return err
}
