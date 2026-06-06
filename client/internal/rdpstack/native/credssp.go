package native

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type TSRequest struct {
	Version     int
	NegoTokens  [][]byte
	AuthInfo    []byte
	PubKeyAuth  []byte
	ErrorCode   *int
	ClientNonce []byte
}

func EncodeTSRequest(r TSRequest) ([]byte, error) {
	var body bytes.Buffer
	body.Write(derExplicit(0, derInteger(r.Version)))
	if len(r.NegoTokens) > 0 {
		var seqOf bytes.Buffer
		for _, tok := range r.NegoTokens {
			seqOf.Write(derSeq(derExplicit(0, derOctet(tok))))
		}
		body.Write(derExplicit(1, derSeq(seqOf.Bytes())))
	}
	if r.AuthInfo != nil {
		body.Write(derExplicit(2, derOctet(r.AuthInfo)))
	}
	if r.PubKeyAuth != nil {
		body.Write(derExplicit(3, derOctet(r.PubKeyAuth)))
	}
	if r.ErrorCode != nil {
		body.Write(derExplicit(4, derInteger(*r.ErrorCode)))
	}
	if r.ClientNonce != nil {
		body.Write(derExplicit(5, derOctet(r.ClientNonce)))
	}
	return derSeq(body.Bytes()), nil
}

func DecodeTSRequest(p []byte) (TSRequest, error) {
	tag, content, rest, err := derReadTLV(p)
	if err != nil {
		return TSRequest{}, err
	}
	if tag != 0x30 {
		return TSRequest{}, fmt.Errorf("TSRequest not sequence: 0x%02x", tag)
	}
	if len(rest) != 0 {
		return TSRequest{}, fmt.Errorf("TSRequest trailing bytes: %d", len(rest))
	}
	var out TSRequest
	for len(content) > 0 {
		var inner []byte
		tag, inner, content, err = derReadTLV(content)
		if err != nil {
			return TSRequest{}, err
		}
		idx := int(tag - 0xa0)
		switch idx {
		case 0:
			out.Version, err = derDecodeInteger(inner)
		case 1:
			out.NegoTokens, err = derDecodeNegoTokens(inner)
		case 2:
			out.AuthInfo, err = derDecodeExplicitOctet(inner)
		case 3:
			out.PubKeyAuth, err = derDecodeExplicitOctet(inner)
		case 4:
			v, e := derDecodeInteger(inner)
			err = e
			out.ErrorCode = &v
		case 5:
			out.ClientNonce, err = derDecodeExplicitOctet(inner)
		default:
			return TSRequest{}, fmt.Errorf("unknown TSRequest context tag 0x%02x", tag)
		}
		if err != nil {
			return TSRequest{}, err
		}
	}
	return out, nil
}

func EncodeTSPasswordCredentials(domain, user, password string) ([]byte, error) {
	var body bytes.Buffer
	body.Write(derExplicit(0, derOctet(utf16leBytes(domain))))
	body.Write(derExplicit(1, derOctet(utf16leBytes(user))))
	body.Write(derExplicit(2, derOctet(utf16leBytes(password))))
	return derSeq(body.Bytes()), nil
}

func EncodeTSCredentials(credType int, credentials []byte) ([]byte, error) {
	var body bytes.Buffer
	body.Write(derExplicit(0, derInteger(credType)))
	body.Write(derExplicit(1, derOctet(credentials)))
	return derSeq(body.Bytes()), nil
}

func derDecodeNegoTokens(p []byte) ([][]byte, error) {
	tag, seqContent, rest, err := derReadTLV(p)
	if err != nil {
		return nil, err
	}
	if tag != 0x30 || len(rest) != 0 {
		return nil, fmt.Errorf("negoTokens not sequence")
	}
	var out [][]byte
	for len(seqContent) > 0 {
		tag, one, r, err := derReadTLV(seqContent)
		if err != nil {
			return nil, err
		}
		if tag != 0x30 {
			return nil, fmt.Errorf("nego token item not sequence: 0x%02x", tag)
		}
		tok, err := derDecodeExplicitOctetFromTag(one, 0xa0)
		if err != nil {
			return nil, err
		}
		out = append(out, tok)
		seqContent = r
	}
	return out, nil
}

func derDecodeInteger(p []byte) (int, error) {
	tag, content, rest, err := derReadTLV(p)
	if err != nil {
		return 0, err
	}
	if tag != 0x02 || len(rest) != 0 {
		return 0, fmt.Errorf("not DER integer")
	}
	if len(content) == 0 || len(content) > 4 {
		return 0, fmt.Errorf("bad DER integer length %d", len(content))
	}
	v := 0
	for _, b := range content {
		v = (v << 8) | int(b)
	}
	return v, nil
}

func derDecodeExplicitOctet(p []byte) ([]byte, error) { return derDecodeExplicitOctetFromTag(p, 0x04) }
func derDecodeExplicitOctetFromTag(p []byte, want byte) ([]byte, error) {
	tag, content, rest, err := derReadTLV(p)
	if err != nil {
		return nil, err
	}
	if tag != want || len(rest) != 0 {
		return nil, fmt.Errorf("unexpected DER tag 0x%02x", tag)
	}
	if want != 0x04 {
		return derDecodeExplicitOctet(content)
	}
	out := make([]byte, len(content))
	copy(out, content)
	return out, nil
}

func derSeq(p []byte) []byte               { return derTLV(0x30, p) }
func derExplicit(tag int, p []byte) []byte { return derTLV(byte(0xa0+tag), p) }
func derOctet(p []byte) []byte             { return derTLV(0x04, p) }
func derInteger(v int) []byte {
	if v == 0 {
		return derTLV(0x02, []byte{0})
	}
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], uint32(v))
	i := 0
	for i < 3 && tmp[i] == 0 {
		i++
	}
	if tmp[i]&0x80 != 0 {
		i--
	}
	if i < 0 {
		i = 0
	}
	return derTLV(0x02, tmp[i:])
}
func derTLV(tag byte, p []byte) []byte {
	var out bytes.Buffer
	out.WriteByte(tag)
	derLength(len(p), &out)
	out.Write(p)
	return out.Bytes()
}
func derLength(n int, b *bytes.Buffer) {
	if n <= 0x7f {
		b.WriteByte(byte(n))
		return
	}
	if n <= 0xff {
		b.WriteByte(0x81)
		b.WriteByte(byte(n))
		return
	}
	b.WriteByte(0x82)
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], uint16(n))
	b.Write(tmp[:])
}
func derReadTLV(p []byte) (tag byte, content []byte, rest []byte, err error) {
	if len(p) < 2 {
		return 0, nil, nil, fmt.Errorf("DER TLV too short")
	}
	tag = p[0]
	lnByte := p[1]
	header := 2
	ln := int(lnByte)
	if lnByte&0x80 != 0 {
		n := int(lnByte & 0x7f)
		if n == 0 || n > 2 || len(p) < 2+n {
			return 0, nil, nil, fmt.Errorf("DER bad length")
		}
		header += n
		ln = 0
		for _, b := range p[2:header] {
			ln = (ln << 8) | int(b)
		}
	}
	if ln < 0 || header+ln > len(p) {
		return 0, nil, nil, fmt.Errorf("DER length exceeds buffer")
	}
	return tag, p[header : header+ln], p[header+ln:], nil
}
