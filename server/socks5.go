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

func (c *Conn) handleSocks5() (err error) {
	buf := make([]byte, share.Socks5NMETHODSLen)
	_, err = io.ReadFull(c, buf)
	if err != nil {
		loger.SetLogTrace(err)
		return err
	}
	ml := int(buf[0])
	buf = make([]byte, ml)
	_, err = io.ReadFull(c, buf)
	if err != nil {
		loger.SetLogTrace(err)
		return err
	}
	err = c.handleSocks5Auth(buf)
	if err != nil {
		return err
	}
	return c.handleSocks5CMD()
}
func (c *Conn) handleSocks5Auth(methods []byte) error {
	m := make(map[byte]bool)
	for _, one := range methods {
		m[one] = true
	}
	var method byte = share.Socks5RETHODCodeRejected
	var methodCode byte = share.Socks5RETHODCodeRejected
	for _, one := range c.ss.config.SocksAuthCb.socks5AuthPriority {
		if method != 0xFF {
			break
		}
		switch one {
		case share.Socks5METHODCodeNOAUTH, share.Socks5METHODCodeGSSAPI, share.Socks5METHODCodePASSWORD:
			if m[one] {
				method = one
				methodCode = one
			}
		case share.Socks5METHODCodeIANA:
			for i := one; i < share.Socks5METHODCodePRIVATE; i++ {
				if m[i] {
					method = one
					methodCode = i
					break
				}
			}
		case share.Socks5METHODCodePRIVATE:
			for i := one; i < share.Socks5RETHODCodeRejected; i++ {
				if m[i] {
					method = one
					methodCode = i
					break
				}
			}
		}
	}
	err := c.writeSocks5AuthResp(methodCode)
	if err != nil {
		loger.SetLogTrace(err)
		return err
	}
	switch method {
	case share.Socks5METHODCodeNOAUTH:
		return nil
	case share.Socks5METHODCodeGSSAPI:
		if c.ss.config.SocksAuthCb.Socks5AuthGSSAPI(c) {
			return nil
		} else {
			err = share.ErrSocks5AuthRejected
			loger.SetLogTrace(err)
			return err
		}
	case share.Socks5METHODCodePASSWORD:
		buf := make([]byte, share.Socks5VERLen+share.Socks5AuthPASSWORDUserLen)
		_, err = io.ReadFull(c, buf)
		if err != nil {
			err = share.ErrSocks5AuthRejected
			loger.SetLogTrace(err)
			return err
		}
		if buf[0] != share.Socks5AuthPasswordVER {
			err = share.ErrSocks5AuthRejected
			loger.SetLogTrace(err)
			return err
		}
		ul := int(buf[1])
		buf = make([]byte, ul+share.Socks5AuthPASSWORDPasswordLen)
		_, err = io.ReadFull(c, buf)
		if err != nil {
			err = share.ErrSocks5AuthRejected
			loger.SetLogTrace(err)
			return err
		}
		user := string(buf[:ul])
		pl := int(buf[ul])
		buf = make([]byte, pl)
		_, err = io.ReadFull(c, buf)
		if err != nil {
			err = share.ErrSocks5AuthRejected
			loger.SetLogTrace(err)
			return err
		}
		password := string(buf[:])
		state := c.ss.config.SocksAuthCb.Socks5AuthPASSWORD(share.Socks5AuthPassword{
			User:     user,
			Password: password,
		})
		if state {
			err = c.writeSocks5AuthPasswordResp(state)
			if err != nil {
				loger.SetLogTrace(err)
				return err
			}
			return nil
		} else {
			c.writeSocks5AuthPasswordResp(state)
			err = share.ErrSocks5AuthRejected
			loger.SetLogTrace(err)
			return err
		}
	case share.Socks5METHODCodeIANA:
		if c.ss.config.SocksAuthCb.Socks5AuthIANA[int(methodCode-share.Socks5METHODCodeIANA)](c) {
			return nil
		} else {
			err = share.ErrSocks5AuthRejected
			loger.SetLogTrace(err)
			return err
		}
	case share.Socks5METHODCodePRIVATE:
		if c.ss.config.SocksAuthCb.Socks5AuthPRIVATE[int(methodCode-share.Socks5METHODCodePRIVATE)](c) {
			return nil
		} else {
			err = share.ErrSocks5AuthRejected
			loger.SetLogTrace(err)
			return err
		}
	case share.Socks5RETHODCodeRejected:
		err = share.ErrSocks5AuthRejected
		loger.SetLogTrace(err)
		return err
	}
	return nil
}

func (c *Conn) writeSocks5AuthResp(method byte) error {
	_, err := c.Write([]byte{share.SocksVersion5, method})
	return err
}

func (c *Conn) writeSocks5AuthPasswordResp(state bool) error {
	var code byte = share.Socks5AuthRespPasswordSuccess
	if !state {
		code = share.Socks5AuthRespPasswordFailure
	}
	_, err := c.Write([]byte{share.Socks5AuthPasswordVER, code})
	return err
}

func (c *Conn) handleSocks5CMD() error {
	buf := make([]byte, share.Socks5VERLen+share.Socks5CMDLen+share.Socks5RSVLen+share.Socks5ATYPLen)
	_, err := io.ReadFull(c, buf)
	if err != nil {
		loger.SetLogTrace(err)
		return err
	}
	ver, cmd, rsv, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != share.SocksVersion5 || rsv != 0x00 {
		c.writeSocks5CMDResp(share.Socks5CMDRespConnNotAllowed, c.LocalAddr())
		err = share.ErrSocksMessageParsingFailure
		loger.SetLogTrace(err)
		return err
	}
	addr, err := c.getSocks5AddrInfo(atyp)
	if err != nil {
		c.writeSocks5CMDResp(share.Socks5CMDRespAddNotSupported, c.LocalAddr())
		loger.SetLogTrace(err)
		return err
	}
	switch cmd {
	case share.Socks5CMDCONNECT:
		if !c.ss.config.CMDSwitch.SwitchCMDCONNECT {
			c.writeSocks5CMDResp(share.Socks5CMDRespCMDNotSupported, c.LocalAddr())
			err = share.ErrCmdNotSupport
			loger.SetLogTrace(err)
			return err
		}
		return c.handleSocks5CMDCONNECT(addr)
	case share.Socks5CMDBIND:
		if !c.ss.config.CMDSwitch.SwitchCMDBIND {
			c.writeSocks5CMDResp(share.Socks5CMDRespCMDNotSupported, c.LocalAddr())
			err = share.ErrCmdNotSupport
			loger.SetLogTrace(err)
			return err
		}
		return c.handleSocks5CMDBind(addr)
	case share.Socks5CMDUDPASSOCIATE:
		if !c.ss.config.CMDSwitch.SwitchCMDUDPASSOCIATE {
			c.writeSocks5CMDResp(share.Socks5CMDRespCMDNotSupported, c.LocalAddr())
			err = share.ErrCmdNotSupport
			loger.SetLogTrace(err)
			return err
		}
		return c.handleSocks5CMDUDPASSOCIATE(addr)
	default:
		c.writeSocks5CMDResp(share.Socks5CMDRespCMDNotSupported, c.LocalAddr())
		err = share.ErrSocksMessageParsingFailure
		loger.SetLogTrace(err)
		return err
	}
}

func (c *Conn) handleSocks5CMDCONNECT(addr string) error {
	if c.ss.config.RelayConfig != nil {
		dr := net.Dialer{Timeout: c.ss.config.DialTimeout}
		conn, err := dr.DialContext(c.ctx, "tcp", c.ss.config.RelayConfig.Addr)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespNetworkUnreachable, c.LocalAddr())
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
			c.writeSocks5CMDResp(share.Socks5CMDRespNetworkUnreachable, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		cMsg, err := c.key.ReadCMsg(c.reader, nil, nil)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespNetworkUnreachable, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		err = cMsg.CheckConnMsgHeaderAndCode(share.HeaderCMDCONNECT, 200)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespHostUnreachable, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
	} else {
		dr := net.Dialer{Timeout: c.ss.config.DialTimeout}
		conn, err := dr.DialContext(c.ctx, "tcp", addr)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespHostUnreachable, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		c.copyConn = share.NewCopyConn(conn)
	}
	go c.readFromCopyStream()
	return c.writeSocks5CMDResp(share.Socks5CMDRespSuccess, c.LocalAddr())
}

func (c *Conn) handleSocks5CMDBind(addr string) error {
	var oaddr net.Addr
	if c.ss.config.RelayConfig != nil {
		dr := net.Dialer{Timeout: c.ss.config.DialTimeout}
		conn, err := dr.DialContext(c.ctx, "tcp", c.ss.config.RelayConfig.Addr)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespNetworkUnreachable, c.LocalAddr())
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
			c.writeSocks5CMDResp(share.Socks5CMDRespNetworkUnreachable, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		cMsg, err := c.key.ReadCMsg(c.reader, nil, nil)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespNetworkUnreachable, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		err = cMsg.CheckConnMsgHeaderAndCode(share.HeaderCMDBIND, 200)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespHostUnreachable, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		var info share.CMDInfo
		err = cMsg.Unmarshal(&info)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespFailure, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		raddr, err := net.ResolveTCPAddr("", info.Addr)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespFailure, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		if raddr.IP.IsUnspecified() {
			raddr.IP = c.copyConn.RemoteAddr().(*net.TCPAddr).IP
		}
		err = c.writeSocks5CMDResp(share.Socks5CMDRespSuccess, raddr)
		if err != nil {
			loger.SetLogTrace(err)
			return err
		}
		cMsg, err = c.key.ReadCMsg(c.reader, nil, nil)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespNetworkUnreachable, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		err = cMsg.CheckConnMsgHeaderAndCode(share.HeaderCMDBIND, 200)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespHostUnreachable, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		err = cMsg.Unmarshal(&info)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespFailure, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		oaddr, err = net.ResolveTCPAddr("", info.Addr)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespFailure, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
	} else {
		lner := net.ListenConfig{}
		ln, err := lner.Listen(c.ctx, "tcp", "")
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespHostUnreachable, c.LocalAddr())
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
		err = c.writeSocks5CMDResp(share.Socks5CMDRespSuccess, ln.Addr())
		if err != nil {
			err = c.writeSocks5CMDResp(share.Socks5CMDRespFailure, ln.Addr())
			loger.SetLogDebug(err)
			return err
		}
		select {
		case <-c.ctx.Done():
		case <-time.After(c.ss.config.BindTimeout):
			c.writeSocks5CMDResp(share.Socks5CMDRespTTLExpired, c.LocalAddr())
			err = share.ErrTimeout
			loger.SetLogDebug(err)
			return err
		}
		if c.copyConn == nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespConnRefused, c.LocalAddr())
			return net.ErrClosed
		}
		oaddr = c.copyConn.RemoteAddr()
	}
	go c.readFromCopyStream()
	return c.writeSocks5CMDResp(share.Socks5CMDRespSuccess, oaddr)
}

func (c *Conn) handleSocks5CMDUDPASSOCIATE(addr string) error {
	checkAddr, err := net.ResolveUDPAddr("", addr)
	if err != nil {
		err = c.writeSocks5CMDResp(share.Socks5CMDRespFailure, c.LocalAddr())
		loger.SetLogTrace(err)
		return err
	}
	if checkAddr.IP.IsUnspecified() {
		checkAddr.IP = c.RemoteAddr().(*net.TCPAddr).IP
	}

	var raddr net.Addr
	if c.ss.config.RelayConfig != nil {
		lner := net.ListenConfig{}
		pconn, err := lner.ListenPacket(c.ctx, "udp", "")
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespFailure, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		c.udpConn = share.NewUdpConn(pconn, checkAddr)
		//dr := net.Dialer{Timeout: c.ss.config.DialTimeout}
		//xConn, err := dr.DialContext(c.ctx, "udp", checkAddr.String())
		//if err != nil {
		//	err = c.writeSocks5CMDResp(share.Socks5CMDRespFailure, c.LocalAddr())
		//	loger.SetLogTrace(err)
		//	return err
		//}
		//c.xConn = share.NewCopyConn2(xConn, c.networkSpeed.Upload, c.networkSpeed.Download)
		dr2 := net.Dialer{Timeout: c.ss.config.DialTimeout}
		conn, err := dr2.DialContext(c.ctx, "tcp", c.ss.config.RelayConfig.Addr)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespHostUnreachable, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		c.copyConn = share.NewCopyConn(conn)
		c.reader = bufio.NewReader(c.copyConn)
		c.key = c.ss.config.RelayConfig.key
		c.keepEncrypt = c.ss.config.RelayConfig.KeepEncrypt
		err = c.writeCMsg(share.HeaderCMDUDPASSOCIATE, "", 200, nil)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespNetworkUnreachable, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		cMsg, err := c.key.ReadCMsg(c.reader, nil, nil)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespNetworkUnreachable, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		err = cMsg.CheckConnMsgHeaderAndCode(share.HeaderCMDUDPASSOCIATE, 200)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespHostUnreachable, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		var info share.CMDInfo
		err = cMsg.Unmarshal(&info)
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespFailure, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		raddr, _ = net.ResolveUDPAddr("", c.udpConn.LocalAddr().String())
		go c.readFromRelayUdp(checkAddr)
	} else {
		lner := net.ListenConfig{}
		pconn, err := lner.ListenPacket(c.ctx, "udp", "")
		if err != nil {
			c.writeSocks5CMDResp(share.Socks5CMDRespHostUnreachable, c.LocalAddr())
			loger.SetLogTrace(err)
			return err
		}
		c.udpConn = share.NewUdpConn(pconn, checkAddr)
		raddr = pconn.LocalAddr()
		go c.readFromLocalUdp(checkAddr)
	}
	err = c.writeSocks5CMDResp(share.Socks5CMDRespSuccess, raddr)
	if err != nil {
		err = c.writeSocks5CMDResp(share.Socks5CMDRespFailure, raddr)
		loger.SetLogDebug(err)
		return err
	}
	return nil
}

func (c *Conn) readFromRelayUdp(addr *net.UDPAddr) {
	go func() {
		for {
			buf := make([]byte, share.DefaultBufferSize)
			n, raddr, err := c.udpConn.ReadFrom(buf)
			if err != nil {
				loger.SetLogTrace(err)
				return
			}
			if raddr.String() == addr.String() {
				c.networkSpeed.Download.Set(n)
				data, xaddr, err := share.UnmarshalSocks5UDPASSOCIATEData2(buf[:n])
				if err != nil {
					loger.SetLogTrace(err)
					return
				}
				if xaddr.IP.IsUnspecified() {
					xaddr.IP = c.RemoteAddr().(*net.TCPAddr).IP
				}
				err = c.writeCMsg(share.HeaderPacket, "", 200, share.UdpPacket{
					Addr: xaddr,
					Data: data,
				})
				if err != nil {
					loger.SetLogTrace(err)
					return
				}
			}
		}
	}()
	for {
		up, err := c.readCMsgPacket()
		if err != nil {
			loger.SetLogTrace(err)
			return
		}
		b := share.MarshalSocks5UDPASSOCIATEData(up.Data, up.Addr)
		n1, err := c.udpConn.WriteTo(b, addr)
		if err != nil {
			loger.SetLogTrace(err)
			return
		}
		c.networkSpeed.Upload.Set(n1)
	}
}

func (c *Conn) readFromLocalUdp(addr *net.UDPAddr) {
	for {
		buf := make([]byte, share.DefaultBufferSize)
		n, raddr, err := c.udpConn.ReadFrom(buf)
		if err != nil {
			loger.SetLogTrace(err)
			return
		}
		if raddr.String() == addr.String() {
			c.networkSpeed.Download.Set(n)
			data, xaddr, err := share.UnmarshalSocks5UDPASSOCIATEData2(buf[:n])
			if err != nil {
				loger.SetLogTrace(err)
				return
			}
			if xaddr.IP.IsUnspecified() {
				xaddr.IP = c.RemoteAddr().(*net.TCPAddr).IP
			}
			_, err = c.udpConn.WriteTo(data, xaddr)
			if err != nil {
				loger.SetLogTrace(err)
				return
			}
		} else {
			b := share.MarshalSocks5UDPASSOCIATEData(buf[:n], raddr)
			n1, err := c.udpConn.WriteTo(b, addr)
			if err != nil {
				loger.SetLogTrace(err)
				return
			}
			c.networkSpeed.Upload.Set(n1)
		}
	}
}

func (c *Conn) getSocks5AddrInfo(atyp byte) (string, error) {
	buf := make([]byte, 256)
	switch atyp {
	case share.Socks5AddrTypeIPv4:
		_, err := io.ReadFull(c, buf[:4+2])
		if err != nil {
			return "", err
		}
		addr := fmt.Sprintf("%s:%d", net.IP(buf[:4]).String(), binary.BigEndian.Uint16(buf[4:4+2]))
		return addr, nil
	case share.Socks5AddrTypeDomain:
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
	case share.Socks5AddrTypeIPv6:
		_, err := io.ReadFull(c, buf[:16+2])
		if err != nil {
			return "", err
		}
		addr := fmt.Sprintf("[%s]:%d", net.IP(buf[:16]).String(), binary.BigEndian.Uint16(buf[16:16+2]))
		return addr, nil
	default:
		return "", share.ErrSocksMessageParsingFailure
	}
}

func (c *Conn) writeSocks5CMDResp(code byte, addr net.Addr) error {
	ad := share.GetSocks5AddrBytes(addr)
	var atyp byte = 0x00
	switch len(ad) {
	case 4 + 2:
		atyp = share.Socks5AddrTypeIPv4
	case 16 + 2:
		atyp = share.Socks5AddrTypeIPv6
	}
	_, err := c.Write(append([]byte{share.SocksVersion5, code, 0x00, atyp}, ad...))
	return err
}
