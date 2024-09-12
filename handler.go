package socks

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

type CMDCONNECTHandler = func(ctx context.Context, addr string) (net.Conn, error)

type CMDBINDHandler = func(ctx context.Context, ch chan<- net.Conn, raddr string) (laddr net.Addr, err error)

type CMDCMDUDPASSOCIATEHandler = func(ctx context.Context, addr net.Addr) (net.PacketConn, error)

var DefaultCMDCONNECTHandler CMDCONNECTHandler = func(ctx context.Context, addr string) (net.Conn, error) {
	dr := net.Dialer{}
	conn, err := dr.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

var DefaultCMDBINDHandler CMDBINDHandler = func(ctx context.Context, ch chan<- net.Conn, raddr string) (laddr net.Addr, err error) {
	lner := net.ListenConfig{}
	ln, err := lner.Listen(ctx, "tcp", "")
	if err != nil {
		return nil, err
	}
	waitFunc(ctx, func() {
		_ = ln.Close()
	})
	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				close(ch)
				return
			}
			if conn.RemoteAddr().String() != raddr {
				conn.Close()
			} else {
				select {
				case <-ctx.Done():
					conn.Close()
					return
				case ch <- conn:
					return
				}
			}
		}
	}()
	return ln.Addr(), nil
}

var DefaultCMDCMDUDPASSOCIATEHandler CMDCMDUDPASSOCIATEHandler = func(ctx context.Context, addr net.Addr) (net.PacketConn, error) {
	lner := net.ListenConfig{}
	pconn, err := lner.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return nil, err
	}
	uconn := newUdpConn(ctx, pconn, addr)
	return uconn, nil
}

type udpConn struct {
	net.PacketConn
	mux     sync.Mutex
	m       map[net.Addr]net.PacketConn
	laddr   net.Addr
	ctx     context.Context
	cancel  context.CancelFunc
	timeout time.Duration
	cb      UDPDataHandler
}

func newUdpConn(ctx context.Context, pconn net.PacketConn, laddr net.Addr) net.PacketConn {
	uc := &udpConn{
		PacketConn: pconn,
		mux:        sync.Mutex{},
		m:          make(map[net.Addr]net.PacketConn),
		laddr:      laddr,
		timeout:    30 * time.Second,
	}
	value := ctx.Value(udpTimeoutKey)
	if value != nil {
		t, ok := value.(time.Duration)
		if ok {
			uc.timeout = t
		}
	}
	value = ctx.Value(udpHandlerKey)
	if value != nil {
		u, ok := value.(UDPDataHandler)
		if ok {
			uc.cb = u
		}
	}
	uc.ctx, uc.cancel = context.WithCancel(ctx)
	return uc
}

func (u *udpConn) ReadFrom(p []byte) (a int, b net.Addr, c error) {
	for {
		n, raddr, err := u.PacketConn.ReadFrom(p)
		if err != nil {
			return 0, nil, err
		}

		data, xaddr, err := unmarshalSocks5UDPASSOCIATEData2(p[:n])
		if err != nil {
			continue
		}
		if u.laddr != nil && u.laddr.String() != raddr.String() {
			continue
		}
		if u.cb != nil {
			data, err = u.cb.Decode(data)
			if err != nil {
				continue
			}
		}

		uaddr := &udpAddr{
			laddr: raddr,
			raddr: xaddr,
		}

		return copy(p, data), uaddr, nil
	}
}

func (u *udpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	uaddr, ok := addr.(*udpAddr)
	if !ok {
		return 0, errors.New("invalid net.Addr")
	}
	u.mux.Lock()
	defer u.mux.Unlock()
	pconn, ok := u.m[uaddr.laddr]
	for {
		if !ok {
			listenConfig := net.ListenConfig{}
			pconn, err = listenConfig.ListenPacket(u.ctx, uaddr.laddr.Network(), ":0")
			if err != nil {
				return 0, err
			}
			u.m[uaddr.laddr] = pconn
			go u.subRead(pconn, uaddr.laddr)
		}
		err = pconn.SetDeadline(time.Now().Add(u.timeout))
		if err != nil {
			_ = pconn.Close()
			if errors.Is(err, net.ErrClosed) {
				ok = false
				continue
			}
			return 0, err
		}
		break
	}

	return pconn.WriteTo(p, uaddr.raddr)
}

func (u *udpConn) Close() error {
	u.cancel()
	u.mux.Lock()
	defer u.mux.Unlock()
	for _, pconn := range u.m {
		_ = pconn.Close()
	}
	return u.PacketConn.Close()
}

func (u *udpConn) subRead(pconn net.PacketConn, laddr net.Addr) {
	defer func() {
		pconn.Close()
		u.mux.Lock()
		defer u.mux.Unlock()
		xconn, ok := u.m[laddr]
		if ok && xconn == pconn {
			delete(u.m, laddr)
		}
	}()
	buf := make([]byte, defaultUdpBufferSize)
	for {
		err := pconn.SetDeadline(time.Now().Add(u.timeout))
		if err != nil {
			return
		}
		n, addr, err := pconn.ReadFrom(buf)
		if err != nil {
			return
		}
		var data []byte
		if u.cb != nil {
			data, err = u.cb.Encode(buf[:n])
			if err != nil {
				continue
			}
		}
		data = marshalSocks5UDPASSOCIATEData(buf[:n], addr)
		_, err = u.PacketConn.WriteTo(data, laddr)
		if err != nil {
			return
		}
	}
}

type udpAddr struct {
	laddr, raddr net.Addr
}

func (u *udpAddr) Network() string {
	return u.raddr.Network()
}

func (u *udpAddr) String() string {
	return u.raddr.String()
}
