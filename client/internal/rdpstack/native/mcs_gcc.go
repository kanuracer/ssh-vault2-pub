package native

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

const (
	gccCSCore     uint16 = 0xc001
	gccCSSecurity uint16 = 0xc002
	gccCSNet      uint16 = 0xc003

	rdpVersion5Plus uint32 = 0x00080004

	color8BPP uint16 = 0xca01
	sasDel    uint16 = 0xaa03
	kbdUS     uint32 = 0x00000409
	kbdIBM101 uint32 = 0x00000004
	high24BPP uint16 = 0x0018

	support15BPP uint16 = 0x0004
	support16BPP uint16 = 0x0002
	support24BPP uint16 = 0x0001
	support32BPP uint16 = 0x0008

	earlyErrInfo uint16 = 0x0001
	earlyWant32  uint16 = 0x0002
)

const (
	ChannelOptionInitialized  uint32 = 0x80000000
	ChannelOptionEncryptRDP   uint32 = 0x40000000
	ChannelOptionEncryptSC    uint32 = 0x20000000
	ChannelOptionEncryptCS    uint32 = 0x10000000
	ChannelOptionPriorityHigh uint32 = 0x08000000
	ChannelOptionCompressRDP  uint32 = 0x00800000
	ChannelOptionCompress     uint32 = 0x00400000
	ChannelOptionShowProtocol uint32 = 0x00200000
)

type DomainParameters struct {
	MaxChannelIDs, MaxUserIDs, MaxTokenIDs  int
	NumPriorities, MinThroughput, MaxHeight int
	MaxMCSPDUSize, ProtocolVersion          int
}

type GCCClientSettings struct {
	Width, Height    int
	ColorDepth       int
	ClientName       string
	SelectedProtocol RDPProtocol
	KeyboardLayout   uint32
	Channels         []GCCChannel
}

type GCCChannel struct {
	Name    string
	Options uint32
}

func EncodeBERDomainParameters(p DomainParameters) []byte {
	var body bytes.Buffer
	berInteger(p.MaxChannelIDs, &body)
	berInteger(p.MaxUserIDs, &body)
	berInteger(p.MaxTokenIDs, &body)
	berInteger(p.NumPriorities, &body)
	berInteger(p.MinThroughput, &body)
	berInteger(p.MaxHeight, &body)
	berInteger(p.MaxMCSPDUSize, &body)
	berInteger(p.ProtocolVersion, &body)
	return berTLV(0x30, body.Bytes())
}

func EncodeMCSConnectInitial(userData []byte) ([]byte, error) {
	if len(userData) == 0 {
		return nil, fmt.Errorf("MCS ConnectInitial userData empty")
	}
	var body bytes.Buffer
	body.Write(berTLV(0x04, []byte{0x01}))
	body.Write(berTLV(0x04, []byte{0x01}))
	body.Write(berTLV(0x01, []byte{0xff}))
	for _, p := range []DomainParameters{
		{MaxChannelIDs: 34, MaxUserIDs: 2, MaxTokenIDs: 0, NumPriorities: 1, MinThroughput: 0, MaxHeight: 1, MaxMCSPDUSize: 0xffff, ProtocolVersion: 2},
		{MaxChannelIDs: 1, MaxUserIDs: 1, MaxTokenIDs: 1, NumPriorities: 1, MinThroughput: 0, MaxHeight: 1, MaxMCSPDUSize: 0x420, ProtocolVersion: 2},
		{MaxChannelIDs: 0xffff, MaxUserIDs: 0xfc17, MaxTokenIDs: 0xffff, NumPriorities: 1, MinThroughput: 0, MaxHeight: 1, MaxMCSPDUSize: 0xffff, ProtocolVersion: 2},
	} {
		body.Write(EncodeBERDomainParameters(p))
	}
	body.Write(berTLV(0x04, userData))
	return berApplication(101, body.Bytes()), nil
}

func EncodeGCCConferenceCreateRequest(s GCCClientSettings) ([]byte, error) {
	if s.Width <= 0 {
		s.Width = 1280
	}
	if s.Height <= 0 {
		s.Height = 800
	}
	if s.ClientName == "" {
		s.ClientName = "ssh-vault2"
	}
	if s.KeyboardLayout == 0 {
		s.KeyboardLayout = kbdUS
	}

	userData := append(encodeCSCore(s), encodeCSSecurity()...)
	userData = append(userData, encodeCSNet(s.Channels)...)

	var out bytes.Buffer
	perChoice(0, &out)
	perObjectID([]byte{0, 0, 20, 124, 0, 1}, &out)
	perLength(len(userData)+14, &out)
	perChoice(0, &out)
	perSelection(0x08, &out)
	perNumericString("1", 1, &out)
	out.WriteByte(0x00)
	out.WriteByte(0x01)
	perChoice(0xc0, &out)
	perOctetStream([]byte("Duca"), 4, &out)
	perOctetStream(userData, 0, &out)
	return out.Bytes(), nil
}

func encodeCSCore(s GCCClientSettings) []byte {
	var body bytes.Buffer
	le16(&body, gccCSCore)
	le16(&body, 0x00d8)
	le32(&body, rdpVersion5Plus)
	le16(&body, uint16(s.Width))
	le16(&body, uint16(s.Height))
	le16(&body, color8BPP)
	le16(&body, sasDel)
	le32(&body, s.KeyboardLayout)
	le32(&body, 3790)
	body.Write(utf16Fixed(s.ClientName, 32))
	le32(&body, kbdIBM101)
	le32(&body, 0)
	le32(&body, 12)
	body.Write(make([]byte, 64))
	le16(&body, color8BPP)
	le16(&body, 1)
	le32(&body, 0)
	le16(&body, high24BPP)
	le16(&body, support15BPP|support16BPP|support24BPP|support32BPP)
	early := earlyErrInfo
	if s.ColorDepth >= 32 {
		early |= earlyWant32
	}
	le16(&body, early)
	body.Write(make([]byte, 64))
	body.WriteByte(0) // connectionType unknown; don't overclaim autodetect/dynvc
	body.WriteByte(0)
	le32(&body, uint32(s.SelectedProtocol))
	return body.Bytes()
}

func encodeCSSecurity() []byte {
	var body bytes.Buffer
	le16(&body, gccCSSecurity)
	le16(&body, 12)
	le32(&body, 0x00000001|0x00000002|0x00000008)
	le32(&body, 0)
	return body.Bytes()
}

func encodeCSNet(channels []GCCChannel) []byte {
	var body bytes.Buffer
	le16(&body, gccCSNet)
	le16(&body, uint16(8+len(channels)*12))
	le32(&body, uint32(len(channels)))
	for _, ch := range channels {
		name := make([]byte, 8)
		copy(name, []byte(sanitizeChannelName(ch.Name)))
		body.Write(name)
		le32(&body, ch.Options)
	}
	return body.Bytes()
}

func sanitizeChannelName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return -1
		}
		return r
	}, s)
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func utf16Fixed(s string, n int) []byte {
	out := make([]byte, n)
	u := utf16.Encode([]rune(s))
	for i, r := range u {
		if i*2+1 >= n {
			break
		}
		binary.LittleEndian.PutUint16(out[i*2:i*2+2], r)
	}
	return out
}

func berInteger(n int, b *bytes.Buffer) {
	var tmp [4]byte
	switch {
	case n <= 0xff:
		b.Write([]byte{0x02, 0x01, byte(n)})
	case n <= 0xffff:
		binary.BigEndian.PutUint16(tmp[:2], uint16(n))
		b.Write([]byte{0x02, 0x02})
		b.Write(tmp[:2])
	default:
		binary.BigEndian.PutUint32(tmp[:4], uint32(n))
		b.Write([]byte{0x02, 0x04})
		b.Write(tmp[:4])
	}
}

func berTLV(tag byte, payload []byte) []byte {
	var out bytes.Buffer
	out.WriteByte(tag)
	berLength(len(payload), &out)
	out.Write(payload)
	return out.Bytes()
}

func berApplication(tag int, payload []byte) []byte {
	var out bytes.Buffer
	if tag > 30 {
		out.WriteByte(0x7f)
		out.WriteByte(byte(tag))
	} else {
		out.WriteByte(0x60 | byte(tag))
	}
	berLength(len(payload), &out)
	out.Write(payload)
	return out.Bytes()
}

func berLength(n int, b *bytes.Buffer) {
	if n <= 0x7f {
		b.WriteByte(byte(n))
		return
	}
	b.WriteByte(0x82)
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], uint16(n))
	b.Write(tmp[:])
}

func perLength(n int, b *bytes.Buffer) {
	if n > 0x7f {
		binary.Write(b, binary.BigEndian, uint16(n|0x8000))
		return
	}
	b.WriteByte(byte(n))
}
func perChoice(v byte, b *bytes.Buffer)    { b.WriteByte(v) }
func perSelection(v byte, b *bytes.Buffer) { b.WriteByte(v) }
func perObjectID(oid []byte, b *bytes.Buffer) {
	b.WriteByte(5)
	b.WriteByte((oid[0] << 4) | (oid[1] & 0x0f))
	b.Write(oid[2:6])
}
func perNumericString(s string, min int, b *bytes.Buffer) {
	mlen := len(s) - min
	if mlen < 0 {
		mlen = min
	}
	perLength(mlen, b)
	for i := 0; i < len(s); i += 2 {
		c1 := (s[i] - '0') % 10
		c2 := byte(0)
		if i+1 < len(s) {
			c2 = (s[i+1] - '0') % 10
		}
		b.WriteByte((c1 << 4) | c2)
	}
}
func perOctetStream(p []byte, min int, b *bytes.Buffer) {
	mlen := len(p) - min
	if mlen < 0 {
		mlen = min
	}
	perLength(mlen, b)
	b.Write(p)
}
func le16(b *bytes.Buffer, v uint16) {
	var x [2]byte
	binary.LittleEndian.PutUint16(x[:], v)
	b.Write(x[:])
}
func le32(b *bytes.Buffer, v uint32) {
	var x [4]byte
	binary.LittleEndian.PutUint32(x[:], v)
	b.Write(x[:])
}
