package share

import (
	"errors"
	"fmt"
)

var ErrHeaderInvalid = errors.New("header invalid")
var ErrCmdNotSupport = errors.New("socks cmd not support")

var ErrBindFailToRegister = errors.New("bind fail to register")

var ErrTimeout = errors.New("timeout")

var ErrMeaninglessServiceVersion = errors.New("meaningless service: not handle socks version")
var ErrMeaninglessServiceCmd = errors.New("meaningless service: not handle socks cmd")

var ErrSocksMessageParsingFailure = errors.New("socks message parsing failure")
var ErrSocksVersionNotSupport = errors.New("socks version not support")

var ErrSocks4UserIdInvalid = errors.New("socks4 user-id invalid")

var ErrSocks5NOACCEPTABLEMETHODS = errors.New("socks5 NO ACCEPTABLE METHODS")
var ErrSocks5NeedMETHODSAuth = errors.New("socks5 need METHODS auth")
var ErrSocks5AuthRejected = errors.New("socks5 Auth Rejected")
var ErrSocks5UDPASSOCIATEDataUnmarshalFailure = errors.New("socks5 UDP ASSOCIATE data unmarshal failure")

var ErrSocks4NotSupportIPv6 = errors.New("socks4 not support IPv6")

var ErrAddrInvalid = func(addr string, err ...string) error { return fmt.Errorf("addr invalid: %s - %v", addr, err) }

func GetSocks4RespErr(cd byte) error {
	switch cd {
	case Socks4RespCodeGranted:
		return nil
	case Socks4RespCodeRejectedFailed:
		return errors.New("request rejected or failed")
	case Socks4RespCodeRejectedClientIdentd:
		return errors.New("request rejected becasue SOCKS server cannot connect to identd on the client")
	case Socks4RespCodeRejectedDifferentUserId:
		return errors.New("request rejected because the client program and identd report different user-ids")
	default:
		return ErrSocksMessageParsingFailure
	}
}
func GetSocks5RespErr(rep byte) error {
	switch rep {
	case Socks5CMDRespSuccess:
		return nil
	case Socks5CMDRespFailure:
		return errors.New("general SOCKS server failure")
	case Socks5CMDRespConnNotAllowed:
		return errors.New("connection not allowed by ruleset")
	case Socks5CMDRespNetworkUnreachable:
		return errors.New("network unreachable")
	case Socks5CMDRespHostUnreachable:
		return errors.New("host unreachable")
	case Socks5CMDRespConnRefused:
		return errors.New("connection refused")
	case Socks5CMDRespTTLExpired:
		return errors.New("TTL expired")
	case Socks5CMDRespCMDNotSupported:
		return errors.New("command not supported")
	case Socks5CMDRespAddNotSupported:
		return errors.New("address type not supported")
	default:
		return ErrSocksMessageParsingFailure
	}
}
