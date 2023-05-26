package share

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

func MarshalSocks5UDPASSOCIATEData(b []byte, addr net.Addr) []byte {
	ab := GetSocks5AddrBytes(addr)
	bs := new(bytes.Buffer)
	bs.Write([]byte{0x00, 0x00, 0x00})
	if len(ab) == 4+2 {
		bs.Write([]byte{Socks5AddrTypeIPv4})
	} else if len(ab) == 16+2 {
		bs.Write([]byte{Socks5AddrTypeIPv6})
	} else {
		bs.Write([]byte{0x00})
	}
	bs.Write(ab)
	bs.Write(b)
	return bs.Bytes()
}
func UnmarshalSocks5UDPASSOCIATEData(b []byte) (data []byte, addr string, err error) {
	if b[0] != 0x00 || b[1] != 0x00 || b[2] != 0x00 {
		return nil, "", ErrSocks5UDPASSOCIATEDataUnmarshalFailure
	}
	switch b[3] {
	case Socks5AddrTypeIPv4:
		ab := b[4 : 4+4+2]
		addr = fmt.Sprintf("%s:%d", string(ab[:4]), binary.BigEndian.Uint16(ab[4:4+2]))
		return b[4+4+2:], addr, nil
	case Socks5AddrTypeDomain:
		al := int(b[4])
		ab := b[5 : 5+al+2]
		addr = fmt.Sprintf("%s:%d", string(ab[:al]), binary.BigEndian.Uint16(ab[al:al+2]))
		return b[5+al+2:], addr, nil
	case Socks5AddrTypeIPv6:
		ab := b[4 : 4+16+2]
		addr = fmt.Sprintf("[%s]:%d", string(ab[:16]), binary.BigEndian.Uint16(ab[16:16+2]))
		return b[4+16+2:], addr, nil
	default:
		return nil, "", ErrSocks5UDPASSOCIATEDataUnmarshalFailure
	}
}
func UnmarshalSocks5UDPASSOCIATEData2(b []byte) (data []byte, addr *net.UDPAddr, err error) {
	if b[0] != 0x00 || b[1] != 0x00 || b[2] != 0x00 {
		return nil, nil, ErrSocks5UDPASSOCIATEDataUnmarshalFailure
	}
	switch b[3] {
	case Socks5AddrTypeIPv4:
		ab := b[4 : 4+4+2]
		addr = &net.UDPAddr{
			IP:   ab[:4],
			Port: int(binary.BigEndian.Uint16(ab[4 : 4+2])),
			Zone: "",
		}
		return b[4+4+2:], addr, nil
	case Socks5AddrTypeDomain:
		al := int(b[4])
		ab := b[5 : 5+al+2]
		addr = &net.UDPAddr{
			IP:   ab[:al],
			Port: int(binary.BigEndian.Uint16(ab[al : al+2])),
			Zone: "",
		}
		return b[5+al+2:], addr, nil
	case Socks5AddrTypeIPv6:
		ab := b[4 : 4+16+2]
		addr = &net.UDPAddr{
			IP:   ab[:16],
			Port: int(binary.BigEndian.Uint16(ab[16 : 16+2])),
			Zone: "",
		}
		return b[4+16+2:], addr, nil
	default:
		return nil, nil, ErrSocks5UDPASSOCIATEDataUnmarshalFailure
	}
}

func GetSocks4AddrBytes(addr net.Addr) []byte {
	if addr == nil {
		return nil
	}
	switch addr.(type) {
	case *net.TCPAddr:
		taddr := addr.(*net.TCPAddr)
		if taddr.IP.IsUnspecified() {
			taddr.IP = net.IP{0, 0, 0, 0}
		}
		taddr.IP = taddr.IP.To4()
		bs := append([]byte{0, 0}, taddr.IP...)
		binary.BigEndian.PutUint16(bs, uint16(taddr.Port))
		return bs
	case *net.UDPAddr:
		uaddr := addr.(*net.UDPAddr)
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
func GetSocks5AddrBytes(addr net.Addr) []byte {
	if addr == nil {
		return nil
	}
	switch addr.(type) {
	case *net.TCPAddr:
		taddr := addr.(*net.TCPAddr)
		if taddr.IP.To4() != nil {
			taddr.IP = taddr.IP.To4()
		}
		return binary.BigEndian.AppendUint16(taddr.IP, uint16(taddr.Port))
	case *net.UDPAddr:
		uaddr := addr.(*net.UDPAddr)
		if uaddr.IP.To4() != nil {
			uaddr.IP = uaddr.IP.To4()
		}
		return binary.BigEndian.AppendUint16(uaddr.IP, uint16(uaddr.Port))
	default:
		return nil
	}
}
