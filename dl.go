package socks

import (
	"context"
	"net"
)

type Dialer interface {
	Dial(network string, addr string) (net.Conn, error)
	DialContext(ctx context.Context, network string, addr string) (net.Conn, error)
}

type ListenerConfig interface {
	Listen(network string, address string) (net.Listener, error)
	ListenContext(ctx context.Context, network string, address string) (net.Listener, error)
}

type PacketListenerConfig interface {
	ListenPacket(network string, address string) (net.PacketConn, error)
	ListenPacketContext(ctx context.Context, network string, address string) (net.PacketConn, error)
}
