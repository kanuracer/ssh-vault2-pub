package native

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

const (
	ntlmNegotiateUnicode                 uint32 = 0x00000001
	ntlmNegotiateOEM                     uint32 = 0x00000002
	ntlmRequestTarget                    uint32 = 0x00000004
	ntlmNegotiateSign                    uint32 = 0x00000010
	ntlmNegotiateSeal                    uint32 = 0x00000020
	ntlmNegotiateLMKey                   uint32 = 0x00000080
	ntlmNegotiateNTLM                    uint32 = 0x00000200
	ntlmNegotiateDomainSupplied          uint32 = 0x00001000
	ntlmNegotiateWorkstationSupplied     uint32 = 0x00002000
	ntlmNegotiateAlwaysSign              uint32 = 0x00008000
	ntlmTargetTypeDomain                 uint32 = 0x00010000
	ntlmTargetTypeServer                 uint32 = 0x00020000
	ntlmNegotiateExtendedSessionSecurity uint32 = 0x00080000
	ntlmNegotiateTargetInfo              uint32 = 0x00800000
	ntlmNegotiateVersion                 uint32 = 0x02000000
	ntlmNegotiate128                     uint32 = 0x20000000
	ntlmNegotiateKeyExch                 uint32 = 0x40000000
	ntlmNegotiate56                      uint32 = 0x80000000
)

type NTLMChallenge struct {
	TargetName      []byte
	Flags           uint32
	ServerChallenge [8]byte
	TargetInfo      []byte
	Raw             []byte
	Timestamp       uint64
}

func NTOWFv2(password, user, domain string) []byte {
	h := md4.New()
	h.Write(utf16leBytes(password))
	ntHash := h.Sum(nil)
	mac := hmac.New(md5.New, ntHash)
	mac.Write(utf16leBytes(strings.ToUpper(user) + domain))
	return mac.Sum(nil)
}

func BuildNTLMNegotiate(workstation, domain string) ([]byte, error) {
	domainBytes := []byte(strings.ToUpper(strings.TrimSpace(domain)))
	workstationBytes := []byte(strings.ToUpper(strings.TrimSpace(workstation)))
	flags := ntlmNegotiateUnicode | ntlmRequestTarget | ntlmNegotiateSign | ntlmNegotiateSeal |
		ntlmNegotiateNTLM | ntlmNegotiateAlwaysSign | ntlmNegotiateExtendedSessionSecurity |
		ntlmNegotiateTargetInfo | ntlmNegotiateVersion | ntlmNegotiate128 | ntlmNegotiateKeyExch | ntlmNegotiate56

	payloadOffset := uint32(40)
	buf := bytes.NewBuffer(make([]byte, 0, payloadOffset+uint32(len(domainBytes)+len(workstationBytes))))
	buf.Write([]byte("NTLMSSP\x00"))
	le32(buf, 1)
	le32(buf, flags)
	writeSecBuffer(buf, uint16(len(domainBytes)), payloadOffset)
	writeSecBuffer(buf, uint16(len(workstationBytes)), payloadOffset+uint32(len(domainBytes)))
	buf.Write(ntlmVersionBytes())
	buf.Write(domainBytes)
	buf.Write(workstationBytes)
	return buf.Bytes(), nil
}

func ParseNTLMChallenge(msg []byte) (*NTLMChallenge, error) {
	if len(msg) < 48 {
		return nil, fmt.Errorf("NTLM challenge too short: %d", len(msg))
	}
	if !bytes.Equal(msg[:8], []byte("NTLMSSP\x00")) {
		return nil, fmt.Errorf("NTLM challenge bad signature")
	}
	if typ := binary.LittleEndian.Uint32(msg[8:12]); typ != 2 {
		return nil, fmt.Errorf("NTLM message type %d, want 2", typ)
	}
	name, err := readSecBuffer(msg, 12)
	if err != nil {
		return nil, fmt.Errorf("NTLM target name: %w", err)
	}
	info, err := readSecBuffer(msg, 40)
	if err != nil {
		return nil, fmt.Errorf("NTLM target info: %w", err)
	}
	out := &NTLMChallenge{TargetName: name, Flags: binary.LittleEndian.Uint32(msg[20:24]), TargetInfo: info, Raw: append([]byte{}, msg...)}
	copy(out.ServerChallenge[:], msg[24:32])
	out.Timestamp = ntlmTargetInfoTimestamp(info)
	return out, nil
}

func writeSecBuffer(buf *bytes.Buffer, ln uint16, off uint32) {
	le16(buf, ln)
	le16(buf, ln)
	le32(buf, off)
}

func readSecBuffer(msg []byte, at int) ([]byte, error) {
	if at+8 > len(msg) {
		return nil, fmt.Errorf("security buffer header truncated")
	}
	ln := int(binary.LittleEndian.Uint16(msg[at : at+2]))
	off := int(binary.LittleEndian.Uint32(msg[at+4 : at+8]))
	if ln == 0 {
		return nil, nil
	}
	if off < 0 || off > len(msg) || off+ln > len(msg) {
		return nil, fmt.Errorf("security buffer out of bounds: off=%d len=%d msg=%d", off, ln, len(msg))
	}
	out := make([]byte, ln)
	copy(out, msg[off:off+ln])
	return out, nil
}

func utf16leBytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(out[i*2:i*2+2], r)
	}
	return out
}

func ntlmTargetInfoTimestamp(info []byte) uint64 {
	for i := 0; i+4 <= len(info); {
		id := binary.LittleEndian.Uint16(info[i : i+2])
		ln := int(binary.LittleEndian.Uint16(info[i+2 : i+4]))
		i += 4
		if i+ln > len(info) {
			return 0
		}
		if id == 0 {
			return 0
		}
		if id == 7 && ln == 8 {
			return binary.LittleEndian.Uint64(info[i : i+8])
		}
		i += ln
	}
	return 0
}

func ntlmTargetInfoWithMICFlag(info []byte) []byte {
	const msvAvFlags uint16 = 6
	const micPresent uint32 = 2
	out := append([]byte{}, info...)
	for i := 0; i+4 <= len(out); {
		id := binary.LittleEndian.Uint16(out[i : i+2])
		ln := int(binary.LittleEndian.Uint16(out[i+2 : i+4]))
		value := i + 4
		if value+ln > len(out) {
			return append([]byte{}, info...)
		}
		if id == msvAvFlags && ln == 4 {
			binary.LittleEndian.PutUint32(out[value:value+4], binary.LittleEndian.Uint32(out[value:value+4])|micPresent)
			return out
		}
		if id == 0 {
			insert := make([]byte, 8)
			binary.LittleEndian.PutUint16(insert[0:2], msvAvFlags)
			binary.LittleEndian.PutUint16(insert[2:4], 4)
			binary.LittleEndian.PutUint32(insert[4:8], micPresent)
			withFlags := append([]byte{}, out[:i]...)
			withFlags = append(withFlags, insert...)
			withFlags = append(withFlags, out[i:]...)
			return withFlags
		}
		i = value + ln
	}
	out = append(out, 6, 0, 4, 0, 2, 0, 0, 0, 0, 0, 0, 0)
	return out
}

const (
	msvAvEOL             uint16 = 0
	msvAvFlags           uint16 = 6
	msvAvTargetName      uint16 = 9
	msvAvChannelBindings uint16 = 10
	msvAvMICPresent      uint32 = 2
)

func ntlmAuthenticateTargetInfo(info []byte, servicePrincipalName string, includeMIC bool) []byte {
	var out bytes.Buffer
	for i := 0; i+4 <= len(info); {
		id := binary.LittleEndian.Uint16(info[i : i+2])
		ln := int(binary.LittleEndian.Uint16(info[i+2 : i+4]))
		value := i + 4
		if value+ln > len(info) {
			break
		}
		if id == msvAvEOL {
			break
		}
		if id == msvAvFlags || id == msvAvTargetName || id == msvAvChannelBindings {
			i = value + ln
			continue
		}
		writeAVPair(&out, id, info[value:value+ln])
		i = value + ln
	}
	if includeMIC {
		var flags [4]byte
		binary.LittleEndian.PutUint32(flags[:], msvAvMICPresent)
		writeAVPair(&out, msvAvFlags, flags[:])
	}
	// desktop client/WinPR sends MsvAvChannelBindings by default for CredSSP EPA.
	// With no explicit SEC_CHANNEL_BINDINGS buffer the MD5 hash is 16 zero bytes.
	writeAVPair(&out, msvAvChannelBindings, make([]byte, 16))
	if strings.TrimSpace(servicePrincipalName) != "" {
		writeAVPair(&out, msvAvTargetName, utf16leBytes(servicePrincipalName))
	}
	le16(&out, msvAvEOL)
	le16(&out, 0)
	// WinPR reserves eight trailing zero bytes in NTLMv2 authenticate target info.
	out.Write(make([]byte, 8))
	return out.Bytes()
}

func writeAVPair(buf *bytes.Buffer, id uint16, value []byte) {
	le16(buf, id)
	le16(buf, uint16(len(value)))
	buf.Write(value)
}

func ntlmVersionBytes() []byte { return []byte{0x06, 0x00, 0x72, 0x17, 0x00, 0x00, 0x00, 0x0f} }
