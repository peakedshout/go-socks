package share

import "net"

const (
	HeaderCMDCONNECT      = "HeaderCMDCONNECT"
	HeaderCMDBIND         = "HeaderCMDBIND"
	HeaderCMDUDPASSOCIATE = "HeaderCMDUDPASSOCIATE"

	HeaderPing   = "HeaderPing"
	HeaderStream = "HeaderStream"
	HeaderPacket = "HeaderPacket"
)

type CMDInfo struct {
	Addr        string
	KeepEncrypt bool
}

type UdpPacket struct {
	Addr *net.UDPAddr
	Data []byte
}
