package socks

func SOCKS4CONNECT(network string, address string, userid S4UserId, forward Dialer) (Dialer, error) {
	return newSocks4Config(network, address, socks4CDCONNECT, userid, forward, nil)
}

func SOCKS4BIND(network string, address string, userid S4UserId, forward Dialer, bindCb BINDAddrCb) (Dialer, error) {
	return newSocks4Config(network, address, socks4CDBIND, userid, forward, bindCb)
}

func SOCKS5CONNECT(network string, address string, auth *S5Auth, forward Dialer) (Dialer, error) {
	return newSocks5Config(network, address, socks5CMDCONNECT, auth, forward, nil, nil, nil)
}
func SOCKS5BIND(network string, address string, auth *S5Auth, forward Dialer, bindCb BINDAddrCb) (Dialer, error) {
	return newSocks5Config(network, address, socks5CMDBIND, auth, forward, nil, bindCb, nil)
}

func SOCKS5UDPASSOCIATE(network string, address string, auth *S5Auth, forward Dialer, uforward PacketListenerConfig, udpCb UDPDataHandler) (PacketListenerConfig, error) {
	return newSocks5Config(network, address, socks5CMDUDPASSOCIATE, auth, forward, uforward, nil, udpCb)
}

func SOCKS5CONNECTP(network string, address string, auth *S5AuthPassword, forward Dialer) (Dialer, error) {
	a := &S5Auth{
		Socks5AuthNOAUTH:   DefaultAuthConnCb,
		Socks5AuthPASSWORD: auth,
	}
	return newSocks5Config(network, address, socks5CMDCONNECT, a, forward, nil, nil, nil)
}
func SOCKS5BINDP(network string, address string, auth *S5AuthPassword, forward Dialer, bindCb BINDAddrCb) (Dialer, error) {
	a := &S5Auth{
		Socks5AuthNOAUTH:   DefaultAuthConnCb,
		Socks5AuthPASSWORD: auth,
	}
	return newSocks5Config(network, address, socks5CMDBIND, a, forward, nil, bindCb, nil)
}

func SOCKS5UDPASSOCIATEP(network string, address string, auth *S5AuthPassword, forward Dialer, uforward PacketListenerConfig, udpCb UDPDataHandler) (PacketListenerConfig, error) {
	a := &S5Auth{
		Socks5AuthNOAUTH:   DefaultAuthConnCb,
		Socks5AuthPASSWORD: auth,
	}
	return newSocks5Config(network, address, socks5CMDUDPASSOCIATE, a, forward, uforward, nil, udpCb)
}
