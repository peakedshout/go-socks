package server

import (
	"bufio"
	"context"
	"github.com/peakedshout/go-CFC/loger"
	"github.com/peakedshout/go-CFC/tool"
	"github.com/peakedshout/go-socks/share"
	"io"
	"net"
)

type Conn struct {
	net.Conn
	copyConn *share.CopyConn
	udpConn  *share.UdpConn

	reader *bufio.Reader
	key    tool.Key

	keepEncrypt bool

	networkSpeed tool.NetworkSpeedTicker
	ctx          context.Context
	ctxCancel    context.CancelFunc

	ss *SocksServer
}

func (c *Conn) handleData() error {
	buf := make([]byte, share.SocksVersionLen)
	_, err := io.ReadFull(c, buf)
	if err != nil {
		loger.SetLogTrace(err)
		return err
	}
	switch buf[0] {
	case share.SocksVersion4:
		return c.handleSocks4()
	case share.SocksVersion5:
		return c.handleSocks5()
	default:
		err = share.ErrSocksMessageParsingFailure
		loger.SetLogTrace(err)
		return err
	}
}

func (c *Conn) readToCopy() error {
	for {
		buf := make([]byte, share.DefaultBufferSize)
		n, err := c.Read(buf)
		if err != nil {
			loger.SetLogDebug(err)
			return err
		}
		if c.copyConn == nil {
			continue
		}
		if c.keepEncrypt {
			err = c.writeCMsg(share.HeaderStream, "", 200, buf[:n])
			if err != nil {
				loger.SetLogDebug(err)
				return err
			}
		} else {
			n, err = c.copyConn.Write(buf[:n])
			if err != nil {
				loger.SetLogDebug(err)
				return err
			}
		}
	}
}

func (c *Conn) readFromCopyStream() error {
	for {
		var b []byte
		if c.keepEncrypt {
			bs, err := c.readCMsgStream()
			if err != nil {
				loger.SetLogDebug(err)
				return err
			}
			b = bs
		} else {
			buf := make([]byte, share.DefaultBufferSize)
			n, err := c.copyConn.Read(buf)
			if err != nil {
				loger.SetLogDebug(err)
				return err
			}
			b = buf[:n]
		}
		_, err := c.Write(b)
		if err != nil {
			loger.SetLogDebug(err)
			return err
		}
	}
}

func (c *Conn) writeCMsg(header string, id string, code int, data interface{}) error {
	bs := c.key.SetMsg(header, id, code, data)
	for _, one := range bs {
		_, err := c.copyConn.Write(one)
		if err != nil {
			return err
		}
	}
	return nil
}
func (c *Conn) readCMsgStream() ([]byte, error) {
	cMsg, err := c.key.ReadCMsg(c.reader, nil, nil)
	if err != nil {
		return nil, err
	}
	err = cMsg.CheckConnMsgHeaderAndCode(share.HeaderStream, 200)
	if err != nil {
		return nil, err
	}
	var b []byte
	err = cMsg.Unmarshal(&b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
func (c *Conn) readCMsgPacket() (packet *share.UdpPacket, err error) {
	cMsg, err := c.key.ReadCMsg(c.reader, nil, nil)
	if err != nil {
		return nil, err
	}
	err = cMsg.CheckConnMsgHeaderAndCode(share.HeaderPacket, 200)
	if err != nil {
		return nil, err
	}
	var info share.UdpPacket
	err = cMsg.Unmarshal(&info)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if err != nil {
		return 0, err
	}
	c.networkSpeed.Upload.Set(n)
	return n, err
}
func (c *Conn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err != nil {
		return 0, err
	}
	c.networkSpeed.Download.Set(n)
	return n, err
}
func (c *Conn) Close() error {
	c.ctxCancel()
	if c.copyConn != nil {
		c.copyConn.Close()
	}
	if c.udpConn != nil {
		c.udpConn.Close()
	}
	return c.Conn.Close()
}
