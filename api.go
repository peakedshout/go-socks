package go_socks

import (
	"github.com/peakedshout/go-socks/client"
	"github.com/peakedshout/go-socks/relay"
	"github.com/peakedshout/go-socks/server"
	"github.com/peakedshout/go-socks/share"
)

func Socks4CONNECT(address string, userId share.Socks4UserId, forward client.SocksDialer) (client.SocksDialer, error) {
	return client.NewSocks4ConnCONNECT(address, userId, forward)
}
func Socks4CONNECTContext(address string, userId share.Socks4UserId, forward client.SocksContextDialer) (client.SocksContextDialer, error) {
	return client.NewSocks4ConnCONNECTContext(address, userId, forward)
}

func Socks4Bind(address string, userId share.Socks4UserId, forward client.SocksDialer, bindCb client.AddrCb) (client.SocksDialer, error) {
	return client.NewSocks4ConnBIND(address, userId, forward, bindCb)
}

func Socks4BindContext(address string, userId share.Socks4UserId, forward client.SocksContextDialer, bindCb client.AddrCb) (client.SocksContextDialer, error) {
	return client.NewSocks4ConnBINDContext(address, userId, forward, bindCb)
}

func Socks5CONNECT(address string, auth *client.Socks5Auth, forward client.SocksDialer) (client.SocksDialer, error) {
	return client.NewSocks5ConnCONNECT(address, auth, forward)
}

func Socks5CONNECTContext(address string, auth *client.Socks5Auth, forward client.SocksContextDialer) (client.SocksContextDialer, error) {
	return client.NewSocks5ConnCONNECTContext(address, auth, forward)
}

func Socks5Bind(address string, auth *client.Socks5Auth, forward client.SocksDialer, bindCb client.AddrCb) (client.SocksDialer, error) {
	return client.NewSocks5ConnBIND(address, auth, forward, bindCb)
}

func Socks5BindContext(address string, auth *client.Socks5Auth, forward client.SocksContextDialer, bindCb client.AddrCb) (client.SocksContextDialer, error) {
	return client.NewSocks5ConnBINDContext(address, auth, forward, bindCb)
}

func Socks5UDPASSOCIATE(address string, auth *client.Socks5Auth, forward client.SocksDialer, uforward client.SocksUdpDialer) (client.SocksUdpDialer, error) {
	return client.NewSocks5ConnUDPASSOCIATE(address, auth, forward, uforward)
}

func Socks5UDPASSOCIATEContext(address string, auth *client.Socks5Auth, forward client.SocksContextDialer, uforward client.SocksUdpContextDialer) (client.SocksUdpContextDialer, error) {
	return client.NewSocks5ConnUDPASSOCIATEContext(address, auth, forward, uforward)
}

func ListenSocksDefault(addr string) (*server.SocksServer, error) {
	return server.NewDefaultSocksServer(addr)
}

func ListenSocks(config *server.SocksServerConfig) (*server.SocksServer, error) {
	return server.NewSocksServer(config)
}

func ListenRelayServerDefault(addr string, rawKey string) (*relay.Server, error) {
	return relay.NewDefaultServer(addr, rawKey)
}

func ListenRelayServer(config *relay.ServerConfig) (*relay.Server, error) {
	return relay.NewServer(config)
}
