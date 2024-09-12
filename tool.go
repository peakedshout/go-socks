package socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

func marshalSocks5UDPASSOCIATEData(b []byte, addr net.Addr) []byte {
	ab := getSocks5AddrBytes(addr)
	bs := new(bytes.Buffer)
	bs.Write([]byte{0x00, 0x00, 0x00})
	if len(ab) == 4+2 {
		bs.Write([]byte{socks5AddrTypeIPv4})
	} else if len(ab) == 16+2 {
		bs.Write([]byte{socks5AddrTypeIPv6})
	} else {
		bs.Write([]byte{0x00})
	}
	bs.Write(ab)
	bs.Write(b)
	return bs.Bytes()
}
func unmarshalSocks5UDPASSOCIATEData(b []byte) (data []byte, addr string, err error) {
	if b[0] != 0x00 || b[1] != 0x00 || b[2] != 0x00 {
		return nil, "", ErrSocks5UDPASSOCIATEDataUnmarshalFailure
	}
	switch b[3] {
	case socks5AddrTypeIPv4:
		ab := b[4 : 4+4+2]
		addr = fmt.Sprintf("%s:%d", string(ab[:4]), binary.BigEndian.Uint16(ab[4:4+2]))
		return b[4+4+2:], addr, nil
	case socks5AddrTypeDomain:
		al := int(b[4])
		ab := b[5 : 5+al+2]
		addr = fmt.Sprintf("%s:%d", string(ab[:al]), binary.BigEndian.Uint16(ab[al:al+2]))
		return b[5+al+2:], addr, nil
	case socks5AddrTypeIPv6:
		ab := b[4 : 4+16+2]
		addr = fmt.Sprintf("[%s]:%d", string(ab[:16]), binary.BigEndian.Uint16(ab[16:16+2]))
		return b[4+16+2:], addr, nil
	default:
		return nil, "", ErrSocks5UDPASSOCIATEDataUnmarshalFailure
	}
}
func unmarshalSocks5UDPASSOCIATEData2(b []byte) (data []byte, addr *net.UDPAddr, err error) {
	if b[0] != 0x00 || b[1] != 0x00 || b[2] != 0x00 {
		return nil, nil, ErrSocks5UDPASSOCIATEDataUnmarshalFailure
	}
	switch b[3] {
	case socks5AddrTypeIPv4:
		ab := b[4 : 4+4+2]
		ip := make([]byte, 4)
		copy(ip, ab[:4])
		addr = &net.UDPAddr{
			IP:   ip,
			Port: int(binary.BigEndian.Uint16(ab[4 : 4+2])),
			Zone: "",
		}
		return b[4+4+2:], addr, nil
	case socks5AddrTypeDomain:
		al := int(b[4])
		ab := b[5 : 5+al+2]
		ipAddr, err := net.ResolveIPAddr("", string(ab[:al]))
		if err != nil {
			return nil, nil, err
		}
		addr = &net.UDPAddr{
			IP:   ipAddr.IP,
			Port: int(binary.BigEndian.Uint16(ab[al : al+2])),
			Zone: "",
		}
		return b[5+al+2:], addr, nil
	case socks5AddrTypeIPv6:
		ab := b[4 : 4+16+2]
		ip := make([]byte, 16)
		copy(ip, ab[:16])
		addr = &net.UDPAddr{
			IP:   ip,
			Port: int(binary.BigEndian.Uint16(ab[16 : 16+2])),
			Zone: "",
		}
		return b[4+16+2:], addr, nil
	default:
		return nil, nil, ErrSocks5UDPASSOCIATEDataUnmarshalFailure
	}
}

func getSocks4AddrBytes(addr net.Addr) []byte {
	if addr == nil {
		return nil
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		taddr := a
		if taddr.IP.IsUnspecified() {
			taddr.IP = net.IP{0, 0, 0, 0}
		}
		taddr.IP = taddr.IP.To4()
		bs := append([]byte{0, 0}, taddr.IP...)
		binary.BigEndian.PutUint16(bs, uint16(taddr.Port))
		return bs
	case *net.UDPAddr:
		uaddr := a
		if uaddr.IP.IsUnspecified() {
			uaddr.IP = net.IP{0, 0, 0, 0}
		}
		uaddr.IP = uaddr.IP.To4()
		bs := append([]byte{0, 0}, uaddr.IP...)
		binary.BigEndian.PutUint16(bs, uint16(uaddr.Port))
		return bs
	default:
		return nil
	}
}
func getSocks5AddrBytes(addr net.Addr) []byte {
	if addr == nil {
		return nil
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		taddr := a
		if taddr.IP.To4() != nil {
			taddr.IP = taddr.IP.To4()
		}
		return binary.BigEndian.AppendUint16(taddr.IP, uint16(taddr.Port))
	case *net.UDPAddr:
		uaddr := a
		if uaddr.IP.To4() != nil {
			uaddr.IP = uaddr.IP.To4()
		}
		return binary.BigEndian.AppendUint16(uaddr.IP, uint16(uaddr.Port))
	default:
		return nil
	}
}

func waitFunc(ctx context.Context, fn func()) {
	go func() {
		<-ctx.Done()
		fn()
	}()
}

func monitorConn(ctx context.Context, rc io.ReadCloser) (context.Context, context.CancelFunc) {
	zero := make([]byte, 0)
	tr := time.NewTimer(0 * time.Second)
	if ctx == nil {
		ctx = context.Background()
	}
	nCtx, cl := context.WithCancel(ctx)
	go func() {
		defer tr.Stop()
		defer cl()
		for {
			_, err := rc.Read(zero)
			if err != nil {
				cl()
				return
			}
			if !tr.Stop() {
				<-tr.C
			}
			tr.Reset(1 * time.Second)
			select {
			case <-nCtx.Done():
				if ctx.Err() != nil {
					_ = rc.Close()
				}
				return
			case <-tr.C:
			}
		}
	}()
	return nCtx, cl
}
