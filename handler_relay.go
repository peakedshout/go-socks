package socks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	relayCMDCONNECT = iota
	relayCMDBIND
	relayCMDUDPASSOCIATE
)

func RelayServe(rwc io.ReadWriteCloser) error {
	defer rwc.Close()
	b := make([]byte, 1)
	_, err := io.ReadFull(rwc, b)
	if err != nil {
		return err
	}
	switch b[0] {
	case relayCMDCONNECT:
		return relayServeCMDCONNECT(rwc)
	case relayCMDBIND:
		return relayServeCMDBIND(rwc)
	case relayCMDUDPASSOCIATE:
		return relayServeCMDCMDUDPASSOCIATE(rwc)
	default:
		return errors.New("invalid relay")
	}
}

func RelayCMDCONNECTHandler(cb func(ctx context.Context) (net.Conn, error)) CMDCONNECTHandler {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		rwc, err := cb(ctx)
		if err != nil {
			return nil, err
		}
		_, err = rwc.Write(append([]byte{relayCMDCONNECT}, makeStrBytes(addr)...))
		if err != nil {
			return nil, err
		}
		b := make([]byte, 1)
		_, err = io.ReadFull(rwc, b)
		if err != nil {
			return nil, err
		}
		if b[0] != 0xff {
			_ = rwc.Close()
			return nil, io.ErrClosedPipe
		}
		return rwc, nil
	}
}

func RelayCMDBINDHandler(cb func(ctx context.Context) (net.Conn, error)) CMDBINDHandler {
	return func(ctx context.Context, ch chan<- net.Conn, raddr string) (laddr net.Addr, err error) {
		rwc, err := cb(ctx)
		if err != nil {
			return nil, err
		}
		_, err = rwc.Write(append([]byte{relayCMDBIND}, makeStrBytes(raddr)...))
		if err != nil {
			return nil, err
		}
		lnAddr, err := readStr(rwc)
		if err != nil {
			return
		}
		tcpAddr, err := net.ResolveTCPAddr("", lnAddr)
		if err != nil {
			return
		}
		if tcpAddr.IP.IsUnspecified() {
			addr := rwc.RemoteAddr().String()
			host, _, _ := net.SplitHostPort(addr)
			tcpAddr.IP = net.ParseIP(host)
		}
		ctx1, cl := monitorConn(ctx, rwc)
		go func() {
			defer cl()
			b := make([]byte, 1)
			_, err = io.ReadFull(rwc, b)
			if err != nil {
				close(ch)
				return
			}
			if b[0] != 0xff {
				close(ch)
				_ = rwc.Close()
				return
			}
			select {
			case <-ctx1.Done():
				_ = rwc.Close()
				return
			case ch <- rwc:
				return
			}
		}()
		return tcpAddr, nil
	}
}

func RelayCMDCMDUDPASSOCIATE(cb func(ctx context.Context) (net.Conn, error)) CMDCMDUDPASSOCIATEHandler {
	return func(ctx context.Context, addr net.Addr) (net.PacketConn, error) {
		rwc, err := cb(ctx)
		if err != nil {
			return nil, err
		}
		_, err = rwc.Write([]byte{relayCMDUDPASSOCIATE})
		if err != nil {
			return nil, err
		}
		b := make([]byte, 1)
		_, err = io.ReadFull(rwc, b)
		if err != nil {
			return nil, err
		}
		if b[0] != 0xff {
			_ = rwc.Close()
			return nil, io.ErrClosedPipe
		}
		lner := net.ListenConfig{}
		pconn, err := lner.ListenPacket(ctx, "udp", ":0")
		if err != nil {
			return nil, err
		}
		return newRelayUdpConn(pconn, rwc, addr), nil
	}
}

func newRelayUdpConn(pconn net.PacketConn, rwc io.ReadWriteCloser, laddr net.Addr) *relayUdpConn {
	ruc := &relayUdpConn{
		PacketConn: pconn,
		rwc:        rwc,
		laddr:      laddr,
		cb:         nil,
	}
	go ruc.async()
	return ruc
}

type relayUdpConn struct {
	net.PacketConn
	rwc   io.ReadWriteCloser
	laddr net.Addr
	cb    UDPDataHandler
}

func (ruc *relayUdpConn) ReadFrom(p []byte) (a int, b net.Addr, c error) {
	for {
		n, raddr, err := ruc.PacketConn.ReadFrom(p)
		if err != nil {
			return 0, nil, err
		}

		data, xaddr, err := unmarshalSocks5UDPASSOCIATEData2(p[:n])
		if err != nil {
			continue
		}
		if ruc.laddr != nil && ruc.laddr.String() != raddr.String() {
			continue
		}
		if ruc.cb != nil {
			data, err = ruc.cb.Decode(data)
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

func (ruc *relayUdpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	uaddr, ok := addr.(*udpAddr)
	if !ok {
		return 0, errors.New("invalid net.Addr")
	}
	bs := new(bytes.Buffer)
	bs.Write(makeStrBytes(uaddr.laddr.String()))
	bs.Write(makeStrBytes(uaddr.raddr.String()))
	bs.Write(p)
	return ruc.rwc.Write(bs.Bytes())
}

func (ruc *relayUdpConn) Close() error {
	_ = ruc.rwc.Close()
	return ruc.PacketConn.Close()
}

func (ruc *relayUdpConn) async() {
	defer ruc.Close()
	for {
		laddr, err := readStr(ruc.rwc)
		if err != nil {
			return
		}
		raddr, err := readStr(ruc.rwc)
		if err != nil {
			return
		}
		b, err := readBytes(ruc.rwc)
		if err != nil {
			return
		}
		xraddr, err := net.ResolveUDPAddr("", raddr)
		if err != nil {
			return
		}
		xladdr, err := net.ResolveUDPAddr("", laddr)
		if err != nil {
			return
		}
		if ruc.cb != nil {
			b, err = ruc.cb.Encode(b)
			if err != nil {
				continue
			}
		}
		data := marshalSocks5UDPASSOCIATEData(b, xraddr)
		_, err = ruc.PacketConn.WriteTo(data, xladdr)
		if err != nil {
			return
		}
	}
}

func relayServeCMDCONNECT(rwc io.ReadWriteCloser) error {
	addr, err := readStr(rwc)
	if err != nil {
		return err
	}
	ctx, cl := monitorConn(context.Background(), rwc)
	dr := net.Dialer{}
	conn, err := dr.DialContext(ctx, "tcp", addr)
	cl()
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = rwc.Write([]byte{0xff})
	if err != nil {
		return err
	}
	go io.Copy(rwc, conn)
	_, err = io.Copy(conn, rwc)
	return err
}

func relayServeCMDBIND(rwc io.ReadWriteCloser) error {
	raddr, err := readStr(rwc)
	if err != nil {
		return err
	}
	ctx, cl := monitorConn(context.Background(), rwc)
	lner := net.ListenConfig{}
	ln, err := lner.Listen(ctx, "tcp", "")
	if err != nil {
		cl()
		return err
	}
	_, err = rwc.Write(makeStrBytes(ln.Addr().String()))
	if err != nil {
		cl()
		return err
	}
	waitFunc(ctx, func() {
		_ = ln.Close()
	})
	var conn net.Conn
	for {
		conn, err = ln.Accept()
		if err != nil {
			cl()
			return err
		}
		if conn.RemoteAddr().String() != raddr {
			conn.Close()
		} else {
			select {
			case <-ctx.Done():
				conn.Close()
				return ctx.Err()
			default:
			}
			break
		}
	}
	cl()
	defer conn.Close()
	_, err = rwc.Write([]byte{0xff})
	if err != nil {
		return err
	}
	go io.Copy(rwc, conn)
	_, err = io.Copy(conn, rwc)
	return err
}

func relayServeCMDCMDUDPASSOCIATE(rwc io.ReadWriteCloser) error {
	uTimeout := 30 * time.Second
	ctx, cl := monitorConn(context.Background(), rwc)
	defer cl()
	var mux sync.Mutex
	m := make(map[string]net.PacketConn)
	defer func() {
		mux.Lock()
		defer mux.Unlock()
		for _, conn := range m {
			_ = conn.Close()
		}
	}()
	_, err := rwc.Write([]byte{0xff})
	if err != nil {
		return err
	}
	for {
		laddr, err := readStr(rwc)
		if err != nil {
			return err
		}
		raddr, err := readStr(rwc)
		if err != nil {
			return err
		}
		data, err := readBytes(rwc)
		if err != nil {
			return err
		}
		xaddr, err := net.ResolveUDPAddr("", raddr)
		if err != nil {
			return err
		}
		mux.Lock()
		packetConn, ok := m[laddr]
		for {
			if !ok {
				lp := net.ListenConfig{}
				packetConn, err = lp.ListenPacket(ctx, "udp", ":0")
				if err != nil {
					break
				}
				m[laddr] = packetConn
				go func() {
					defer func() {
						_ = packetConn.Close()
						mux.Lock()
						defer mux.Unlock()
						xconn, ok := m[laddr]
						if ok && xconn == packetConn {
							delete(m, laddr)
						}
					}()
					buf := make([]byte, defaultUdpBufferSize)
					for {
						err := packetConn.SetDeadline(time.Now().Add(uTimeout))
						if err != nil {
							return
						}
						n, addr, err := packetConn.ReadFrom(buf)
						if err != nil {
							return
						}
						bs := new(bytes.Buffer)
						bs.Write(makeStrBytes(laddr))
						bs.Write(makeStrBytes(addr.String()))
						bs.Write(makeBytes(buf[:n]))
						_, err = rwc.Write(bs.Bytes())
						if err != nil {
							return
						}
					}
				}()
			}
			err = packetConn.SetDeadline(time.Now().Add(uTimeout))
			if err != nil {
				_ = packetConn.Close()
				if errors.Is(err, net.ErrClosed) {
					ok = false
					continue
				}
				break
			}
		}
		mux.Unlock()
		if err != nil {
			return err
		}
		_, _ = packetConn.WriteTo(data, xaddr)
	}
}

func makeStrBytes(s string) []byte {
	return append([]byte{byte(len(s))}, []byte(s)...)
}

func makeBytes(b []byte) []byte {
	return append([]byte{byte(len(b))}, b...)
}

func readStr(r io.Reader) (string, error) {
	b := make([]byte, 1)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return "", err
	}
	b = make([]byte, b[0])
	_, err = io.ReadFull(r, b)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func readBytes(r io.Reader) ([]byte, error) {
	b := make([]byte, 1)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}
	b = make([]byte, b[0])
	_, err = io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
