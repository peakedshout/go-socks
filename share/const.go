package share

const DefaultBufferSize = 4096

const (
	SocksVersion4 = 0x04
	SocksVersion5 = 0x05
)

const (
	SocksVersionLen = 1

	Socks4VNLen      = 1
	Socks4CDLen      = 1
	Socks4DSTPORTLen = 2
	Socks4DSTIPLen   = 4
	Socks4NullLen    = 1

	Socks5VERLen      = 1
	Socks5NMETHODSLen = 1

	Socks5CMDLen  = 1
	Socks5RSVLen  = 1
	Socks5ATYPLen = 1
	Socks5PORTLen = 2

	Socks5AuthPASSWORDUserLen     = 1
	Socks5AuthPASSWORDPasswordLen = 1
)

const (
	Socks4RespCodeGranted                 = 0x5A //request granted
	Socks4RespCodeRejectedFailed          = 0x5B //request rejected or failed
	Socks4RespCodeRejectedClientIdentd    = 0x5C //request rejected becasue SOCKS server cannot connect to identd on the client
	Socks4RespCodeRejectedDifferentUserId = 0x5D //request rejected because the client program and identd report different user-ids
)

const (
	Socks5METHODCodeNOAUTH   = 0x00 //NO AUTHENTICATION REQUIRED
	Socks5METHODCodeGSSAPI   = 0x01 //GSSAPI
	Socks5METHODCodePASSWORD = 0x02 //USERNAME/PASSWORD
	Socks5METHODCodeIANA     = 0x03 //IANA ASSIGNED
	Socks5METHODCodePRIVATE  = 0x80 //RESERVED FOR PRIVATE METHODS
	Socks5RETHODCodeRejected = 0xFF //NO ACCEPTABLE METHODS
)

const (
	Socks5CMDCONNECT      = 0x01
	Socks5CMDBIND         = 0x02
	Socks5CMDUDPASSOCIATE = 0x03
)

const (
	Socks5AddrTypeIPv4   = 0x01
	Socks5AddrTypeDomain = 0x03
	Socks5AddrTypeIPv6   = 0x04
)

const (
	Socks5CMDRespSuccess            = 0x00 //succeeded
	Socks5CMDRespFailure            = 0x01 //general SOCKS server failure
	Socks5CMDRespConnNotAllowed     = 0x02 //connection not allowed by ruleset
	Socks5CMDRespNetworkUnreachable = 0x03 //Network unreachable
	Socks5CMDRespHostUnreachable    = 0x04 //Host unreachable
	Socks5CMDRespConnRefused        = 0x05 //Connection refused
	Socks5CMDRespTTLExpired         = 0x06 //TTL expired
	Socks5CMDRespCMDNotSupported    = 0x07 //Command not supported
	Socks5CMDRespAddNotSupported    = 0x08 //Address type not supported
	Socks5CMDRespNULL               = 0x09 //unassigned
)

const (
	Socks5AuthPasswordVER = 0x01

	Socks5AuthRespPasswordSuccess = 0x00
	Socks5AuthRespPasswordFailure = 0x01
)

const (
	Socks4ByteNull = 0x00

	Socks4CDCONNECT = 0x01
	Socks4CDBIND    = 0x02
)
