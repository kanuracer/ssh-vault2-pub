package native

import "fmt"

var (
	spnegoOID = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	ntlmOID   = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
)

func EncodeSPNEGONegTokenInit(ntlmType1 []byte) ([]byte, error) {
	if len(ntlmType1) == 0 {
		return nil, fmt.Errorf("SPNEGO NegTokenInit empty NTLM token")
	}
	mechTypes := derExplicit(0, derSeq(derOID(ntlmOID)))
	mechToken := derExplicit(2, derOctet(ntlmType1))
	negTokenInit := derExplicit(0, derSeq(append(mechTypes, mechToken...)))
	content := append(derOID(spnegoOID), negTokenInit...)
	return derTLV(0x60, content), nil
}

func EncodeSPNEGONegTokenResp(ntlmToken []byte) ([]byte, error) {
	if len(ntlmToken) == 0 {
		return nil, fmt.Errorf("SPNEGO NegTokenResp empty NTLM token")
	}
	body := derExplicit(2, derOctet(ntlmToken))
	return derExplicit(1, derSeq(body)), nil
}

func DecodeSPNEGONegTokenResp(p []byte) ([]byte, error) {
	tag, content, rest, err := derReadTLV(p)
	if err != nil {
		return nil, err
	}
	if tag == 0x60 {
		_, inner, r, err := derReadTLV(content) // SPNEGO OID
		_ = inner
		if err != nil {
			return nil, err
		}
		if len(r) == 0 {
			return nil, fmt.Errorf("SPNEGO initial token missing negTokenResp")
		}
		tag, content, rest, err = derReadTLV(r)
		if err != nil {
			return nil, err
		}
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("SPNEGO response trailing bytes: %d", len(rest))
	}
	if tag != 0xa1 {
		return nil, fmt.Errorf("SPNEGO expected NegTokenResp [1], got 0x%02x", tag)
	}
	seqTag, seq, seqRest, err := derReadTLV(content)
	if err != nil {
		return nil, err
	}
	if seqTag != 0x30 || len(seqRest) != 0 {
		return nil, fmt.Errorf("SPNEGO NegTokenResp not sequence")
	}
	for len(seq) > 0 {
		fieldTag, field, r, err := derReadTLV(seq)
		if err != nil {
			return nil, err
		}
		if fieldTag == 0xa2 {
			return derDecodeExplicitOctet(field)
		}
		seq = r
	}
	return nil, fmt.Errorf("SPNEGO NegTokenResp missing responseToken")
}

func derOID(v []byte) []byte { return derTLV(0x06, v) }
