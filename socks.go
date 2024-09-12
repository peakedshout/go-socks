package socks

import "net"

func Serve(ln net.Listener, cfg *ServerConfig) error {
	server, err := NewServer(cfg)
	if err != nil {
		return err
	}
	defer server.Close()
	return server.Serve(ln)
}

func ListenAndServe(network string, addr string, cfg *ServerConfig) error {
	server, err := NewServer(cfg)
	if err != nil {
		return err
	}
	defer server.Close()
	return server.ListenAndServe(network, addr)
}

func ListenSocksDefault(network string, addr string) error {
	server, err := NewServer(ServerSimplifyConfig{
		SwitchSocksVersion4: true,
		SwitchSocksVersion5: true,
		SwitchCMDCONNECT:    true,
	}.Build())
	if err != nil {
		return err
	}
	return server.ListenAndServe(network, addr)
}
