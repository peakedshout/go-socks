package socks

const defaultBufferSize = 4096

const defaultUdpBufferSize = 32 * 1024

const (
	socksVersion4 = 0x04
	socksVersion5 = 0x05
)

const (
	socksVersionLen = 1

	socks4VNLen      = 1
	socks4CDLen      = 1
	socks4DSTPORTLen = 2
	socks4DSTIPLen   = 4
	socks4NullLen    = 1

	socks5VERLen      = 1
	socks5NMETHODSLen = 1

	socks5CMDLen  = 1
	socks5RSVLen  = 1
	socks5ATYPLen = 1
	socks5PORTLen = 2

	socks5AuthPASSWORDUserLen     = 1
	socks5AuthPASSWORDPasswordLen = 1
)

const (
	socks4RespCodeGranted                 = 0x5A //request granted
	socks4RespCodeRejectedFailed          = 0x5B //request rejected or failed
	socks4RespCodeRejectedClientIdentd    = 0x5C //request rejected becasue SOCKS server cannot connect to identd on the client
	socks4RespCodeRejectedDifferentUserId = 0x5D //request rejected because the client program and identd report different user-ids
)

const (
	socks5METHODCodeNOAUTH   = 0x00 //NO AUTHENTICATION REQUIRED
	socks5METHODCodeGSSAPI   = 0x01 //GSSAPI
	socks5METHODCodePASSWORD = 0x02 //USERNAME/PASSWORD
	socks5METHODCodeIANA     = 0x03 //IANA ASSIGNED
	socks5METHODCodePRIVATE  = 0x80 //RESERVED FOR PRIVATE METHODS
	socks5RETHODCodeRejected = 0xFF //NO ACCEPTABLE METHODS
)

const (
	socks5CMDCONNECT      = 0x01
	socks5CMDBIND         = 0x02
	socks5CMDUDPASSOCIATE = 0x03
)

const (
	socks5AddrTypeIPv4   = 0x01
	socks5AddrTypeDomain = 0x03
	socks5AddrTypeIPv6   = 0x04
)

const (
	socks5CMDRespSuccess            = 0x00 //succeeded
	socks5CMDRespFailure            = 0x01 //general SOCKS server failure
	socks5CMDRespConnNotAllowed     = 0x02 //connection not allowed by ruleset
	socks5CMDRespNetworkUnreachable = 0x03 //Network unreachable
	socks5CMDRespHostUnreachable    = 0x04 //Host unreachable
	socks5CMDRespConnRefused        = 0x05 //Connection refused
	socks5CMDRespTTLExpired         = 0x06 //TTL expired
	socks5CMDRespCMDNotSupported    = 0x07 //Command not supported
	socks5CMDRespAddNotSupported    = 0x08 //Address type not supported
	socks5CMDRespNULL               = 0x09 //unassigned
)

const (
	socks5AuthPasswordVER = 0x01

	socks5AuthRespPasswordSuccess = 0x00
	socks5AuthRespPasswordFailure = 0x01
)

const (
	socks4ByteNull = 0x00

	socks4CDCONNECT = 0x01
	socks4CDBIND    = 0x02
)

const udpTimeoutKey = "timeout"
const udpHandlerKey = "handler"
