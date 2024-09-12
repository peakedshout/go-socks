package socks

import (
	"errors"
	"fmt"
)

var ErrNeedServerConfig = errors.New("need server config")

var ErrNetworkNotSupport = errors.New("network not support")

var ErrSocks5CMDNotSupport = errors.New("socks5 cmd not support")
var ErrSocks4CDNotSupport = errors.New("socks4 cd not support")

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

func getSocks4RespErr(cd byte) error {
	switch cd {
	case socks4RespCodeGranted:
		return nil
	case socks4RespCodeRejectedFailed:
		return errors.New("request rejected or failed")
	case socks4RespCodeRejectedClientIdentd:
		return errors.New("request rejected becasue SOCKS server cannot connect to identd on the client")
	case socks4RespCodeRejectedDifferentUserId:
		return errors.New("request rejected because the client program and identd report different user-ids")
	default:
		return ErrSocksMessageParsingFailure
	}
}
func getSocks5RespErr(rep byte) error {
	switch rep {
	case socks5CMDRespSuccess:
		return nil
	case socks5CMDRespFailure:
		return errors.New("general SOCKS server failure")
	case socks5CMDRespConnNotAllowed:
		return errors.New("connection not allowed by ruleset")
	case socks5CMDRespNetworkUnreachable:
		return errors.New("network unreachable")
	case socks5CMDRespHostUnreachable:
		return errors.New("host unreachable")
	case socks5CMDRespConnRefused:
		return errors.New("connection refused")
	case socks5CMDRespTTLExpired:
		return errors.New("TTL expired")
	case socks5CMDRespCMDNotSupported:
		return errors.New("command not supported")
	case socks5CMDRespAddNotSupported:
		return errors.New("address type not supported")
	default:
		return ErrSocksMessageParsingFailure
	}
}
