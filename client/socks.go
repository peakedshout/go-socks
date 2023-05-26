package client

import (
	"context"
	"github.com/peakedshout/go-socks/share"
	"net"
)

func NewSocks5ConnCONNECT(address string, auth *Socks5Auth, forward SocksDialer) (SocksDialer, error) {
	if auth == nil {
		return nil, share.ErrSocks5NeedMETHODSAuth
	}
	s5d := &Socks5Dialer{
		addr:           address,
		ctx:            nil,
		auth:           auth,
		forward:        forward,
		forwardContext: nil,
		cmd:            share.Socks5CMDCONNECT,
		bindCb:         nil,
	}
	return s5d, nil
}
func NewSocks5ConnCONNECTContext(address string, auth *Socks5Auth, forward SocksContextDialer) (SocksContextDialer, error) {
	if auth == nil {
		return nil, share.ErrSocks5NeedMETHODSAuth
	}
	s5d := &Socks5Dialer{
		addr:           address,
		ctx:            nil,
		auth:           auth,
		forward:        nil,
		forwardContext: forward,
		cmd:            share.Socks5CMDCONNECT,
		bindCb:         nil,
	}
	return s5d, nil
}
func NewSocks5ConnBIND(address string, auth *Socks5Auth, forward SocksDialer, bindCb AddrCb) (SocksDialer, error) {
	if auth == nil {
		return nil, share.ErrSocks5NeedMETHODSAuth
	}
	s5d := &Socks5Dialer{
		addr:           address,
		ctx:            nil,
		auth:           auth,
		forward:        forward,
		forwardContext: nil,
		cmd:            share.Socks5CMDBIND,
		bindCb:         bindCb,
	}
	return s5d, nil
}
func NewSocks5ConnBINDContext(address string, auth *Socks5Auth, forward SocksContextDialer, bindCb AddrCb) (SocksContextDialer, error) {
	if auth == nil {
		return nil, share.ErrSocks5NeedMETHODSAuth
	}
	s5d := &Socks5Dialer{
		addr:           address,
		ctx:            nil,
		auth:           auth,
		forward:        nil,
		forwardContext: forward,
		cmd:            share.Socks5CMDBIND,
		bindCb:         bindCb,
	}
	return s5d, nil
}

func NewSocks4ConnCONNECT(address string, userId share.Socks4UserId, forward SocksDialer) (SocksDialer, error) {
	s4d := &Socks4Dialer{
		addr:           address,
		ctx:            nil,
		userId:         userId,
		forward:        forward,
		forwardContext: nil,
		cd:             share.Socks4CDCONNECT,
		bindCb:         nil,
	}
	return s4d, nil
}
func NewSocks4ConnCONNECTContext(address string, userId share.Socks4UserId, forward SocksContextDialer) (SocksContextDialer, error) {
	s4d := &Socks4Dialer{
		addr:           address,
		ctx:            nil,
		userId:         userId,
		forward:        nil,
		forwardContext: forward,
		cd:             share.Socks4CDCONNECT,
		bindCb:         nil,
	}
	return s4d, nil
}
func NewSocks4ConnBIND(address string, userId share.Socks4UserId, forward SocksDialer, bindCb AddrCb) (SocksDialer, error) {
	s4d := &Socks4Dialer{
		addr:           address,
		ctx:            nil,
		userId:         userId,
		forward:        forward,
		forwardContext: nil,
		cd:             share.Socks4CDBIND,
		bindCb:         bindCb,
	}
	return s4d, nil
}
func NewSocks4ConnBINDContext(address string, userId share.Socks4UserId, forward SocksContextDialer, bindCb AddrCb) (SocksContextDialer, error) {
	s4d := &Socks4Dialer{
		addr:           address,
		ctx:            nil,
		userId:         userId,
		forward:        nil,
		forwardContext: forward,
		cd:             share.Socks4CDBIND,
		bindCb:         bindCb,
	}
	return s4d, nil
}

func NewSocks5ConnUDPASSOCIATE(address string, auth *Socks5Auth, forward SocksDialer, uforward SocksUdpDialer) (SocksUdpDialer, error) {
	s5d := &Socks5Dialer{
		addr:            address,
		ctx:             nil,
		auth:            auth,
		forward:         forward,
		forwardContext:  nil,
		uforward:        uforward,
		uforwardContext: nil,
		cmd:             share.Socks5CMDUDPASSOCIATE,
		bindCb:          nil,
	}
	return s5d, nil
}
func NewSocks5ConnUDPASSOCIATEContext(address string, auth *Socks5Auth, forward SocksContextDialer, uforward SocksUdpContextDialer) (SocksUdpContextDialer, error) {
	s5d := &Socks5Dialer{
		addr:            address,
		ctx:             nil,
		auth:            auth,
		forward:         nil,
		forwardContext:  forward,
		uforward:        nil,
		uforwardContext: uforward,
		cmd:             share.Socks5CMDUDPASSOCIATE,
		bindCb:          nil,
	}
	return s5d, nil
}

type SocksDialer interface {
	Dial(network, addr string) (c net.Conn, err error)
}
type SocksContextDialer interface {
	DialContext(ctx context.Context, network, addr string) (c net.Conn, err error)
}
type SocksUdpDialer interface {
	DialUDP(network, addr string) (pc net.PacketConn, err error)
}
type SocksUdpContextDialer interface {
	DialUDPContext(ctx context.Context, network, addr string) (pc net.PacketConn, err error)
}

type AddrCb func(addr net.Addr) error
