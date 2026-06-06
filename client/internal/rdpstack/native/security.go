package native

import "fmt"

type SecurityMode string

const (
	SecurityStandardRDP SecurityMode = "rdp"
	SecurityTLS         SecurityMode = "tls"
	SecurityNLA         SecurityMode = "nla"
)

func (p RDPProtocol) NeedsTLS() bool {
	return p == ProtocolSSL || p == ProtocolHybrid || p == ProtocolHybridEx
}

func (p RDPProtocol) NeedsCredSSP() bool {
	return p == ProtocolHybrid || p == ProtocolHybridEx
}

func (p RDPProtocol) Supported() bool {
	return p == ProtocolRDP || p == ProtocolSSL || p == ProtocolHybrid
}

func SecurityModeForProtocol(p RDPProtocol) (SecurityMode, error) {
	switch p {
	case ProtocolRDP:
		return SecurityStandardRDP, nil
	case ProtocolSSL:
		return SecurityTLS, nil
	case ProtocolHybrid:
		return SecurityNLA, nil
	case ProtocolHybridEx:
		return "", fmt.Errorf("RDP HYBRID_EX security is not supported yet")
	default:
		return "", fmt.Errorf("unsupported RDP security protocol: 0x%08x", uint32(p))
	}
}
