// Package native contains ssh-vault2's own RDP wire-core building blocks.
package native

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const tpktVersion = 3

func EncodeTPKT(payload []byte) ([]byte, error) {
	if len(payload) > 0xffff-4 {
		return nil, fmt.Errorf("TPKT payload too large: %d", len(payload))
	}
	out := make([]byte, 4+len(payload))
	out[0] = tpktVersion
	out[1] = 0
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	copy(out[4:], payload)
	return out, nil
}

func DecodeTPKT(data []byte) (payload []byte, rest []byte, err error) {
	if len(data) < 4 {
		return nil, nil, errors.New("TPKT header too short")
	}
	if data[0] != tpktVersion {
		return nil, nil, fmt.Errorf("unsupported TPKT version: %d", data[0])
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length < 4 {
		return nil, nil, fmt.Errorf("invalid TPKT length: %d", length)
	}
	if len(data) < length {
		return nil, nil, fmt.Errorf("incomplete TPKT packet: %d < %d", len(data), length)
	}
	return data[4:length], data[length:], nil
}

// EncodeX224ConnectionRequest builds the initial X.224 Connection Request TPDU
// with an RDP Negotiation Request asking for TLS/NLA capable security.
func EncodeX224ConnectionRequest(cookieHost string) ([]byte, error) {
	host := sanitizeCookieHost(cookieHost)
	cookie := []byte("Cookie: mstshash=" + host + "\r\n")
	// CR TPDU: length indicator, type E0, dst-ref, src-ref, class/options.
	bodyLen := 6 + len(cookie) + 8
	if bodyLen > 0xff {
		return nil, fmt.Errorf("X224 CR too large: %d", bodyLen)
	}
	p := make([]byte, 0, bodyLen+1)
	p = append(p, byte(bodyLen), 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00)
	p = append(p, cookie...)
	// RDP Negotiation Request: type=1, flags=0, length=8, protocols=SSL|HYBRID.
	p = append(p, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00)
	return EncodeTPKT(p)
}

func sanitizeCookieHost(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "ssh-vault2"
	}
	v = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return -1
		}
		if r < 32 || r > 126 {
			return -1
		}
		return r
	}, v)
	if len(v) > 31 {
		v = v[:31]
	}
	if v == "" {
		return "ssh-vault2"
	}
	return v
}
