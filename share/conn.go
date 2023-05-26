package share

import (
	"github.com/peakedshout/go-CFC/tool"
	"net"
)

type CopyConn struct {
	net.Conn
	networkSpeed tool.NetworkSpeedTicker
}

func NewCopyConn(conn net.Conn) *CopyConn {
	return &CopyConn{
		Conn:         conn,
		networkSpeed: tool.NewNetworkSpeedTicker(),
	}
}

func NewCopyConn2(conn net.Conn, u, d *tool.SpeedTicker) *CopyConn {
	return &CopyConn{
		Conn: conn,
		networkSpeed: tool.NetworkSpeedTicker{
			Upload:   u,
			Download: d,
		},
	}
}

func (cc *CopyConn) Write(b []byte) (n int, err error) {
	n, err = cc.Conn.Write(b)
	if err != nil {
		return 0, err
	}
	cc.networkSpeed.Upload.Set(n)
	return n, err
}
func (cc *CopyConn) Read(b []byte) (n int, err error) {
	n, err = cc.Conn.Read(b)
	if err != nil {
		return 0, err
	}
	cc.networkSpeed.Download.Set(n)
	return n, err
}

type UdpConn struct {
	net.PacketConn
	ignoreAddr   net.Addr
	networkSpeed tool.NetworkSpeedTicker
}

func NewUdpConn(conn net.PacketConn, ignoreAddr net.Addr) *UdpConn {
	return &UdpConn{
		PacketConn:   conn,
		ignoreAddr:   ignoreAddr,
		networkSpeed: tool.NewNetworkSpeedTicker(),
	}
}

func (uc *UdpConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	n, err = uc.PacketConn.WriteTo(b, addr)
	if err != nil {
		return 0, err
	}
	if uc.ignoreAddr != nil && addr.String() == uc.ignoreAddr.String() {
		return n, err
	}
	uc.networkSpeed.Upload.Set(n)
	return n, err
}
func (uc *UdpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = uc.PacketConn.ReadFrom(p)
	if err != nil {
		return 0, nil, err
	}
	if uc.ignoreAddr != nil && addr.String() == uc.ignoreAddr.String() {
		return n, addr, err
	}
	uc.networkSpeed.Download.Set(n)
	return n, addr, err
}
