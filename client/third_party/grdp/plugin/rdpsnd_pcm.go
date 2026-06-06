package plugin

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"

	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
)

const (
	rdpsndWave        uint8 = 0x02
	rdpsndClose       uint8 = 0x01
	rdpsndWaveConfirm uint8 = 0x05
	rdpsndTraining    uint8 = 0x06
	rdpsndFormats     uint8 = 0x07
	rdpsndQualityMode uint8 = 0x0c

	waveFormatPCM uint16 = 0x0001
)

type RDPSNDAudioChunk struct {
	FormatNo      uint16
	Channels      uint16
	SampleRate    uint32
	BitsPerSample uint16
	Base64        string
}

type RDPSNDAudioSink func(RDPSNDAudioChunk)

type rdpsndFormat struct {
	Tag           uint16
	Channels      uint16
	SampleRate    uint32
	AvgBytes      uint32
	BlockAlign    uint16
	BitsPerSample uint16
	Extra         []byte
	ServerIndex   uint16
}

type RDPSNDClient struct {
	sender        core.ChannelSender
	sink          RDPSNDAudioSink
	formats       []rdpsndFormat
	current       rdpsndFormat
	currentValid  bool
	waitingWave   bool
	wavePrefix    []byte
	waveTimestamp uint16
	waveBlock     uint8
}

func NewRDPSNDClient(sink RDPSNDAudioSink) *RDPSNDClient { return &RDPSNDClient{sink: sink} }

func (c *RDPSNDClient) GetType() (string, uint32) {
	return RDPSND_SVC_CHANNEL_NAME, uint32(StaticVirtualChannels[RDPSND_SVC_CHANNEL_NAME])
}

func (c *RDPSNDClient) Sender(sender core.ChannelSender) { c.sender = sender }

func (c *RDPSNDClient) Process(s []byte) {
	if c.waitingWave {
		data := append(append([]byte(nil), c.wavePrefix...), s...)
		if c.sink != nil && c.currentValid && len(data) > 0 {
			c.sink(RDPSNDAudioChunk{FormatNo: c.current.ServerIndex, Channels: c.current.Channels, SampleRate: c.current.SampleRate, BitsPerSample: c.current.BitsPerSample, Base64: base64.StdEncoding.EncodeToString(data)})
		}
		c.sendWaveConfirm(c.waveTimestamp, c.waveBlock)
		c.waitingWave = false
		c.wavePrefix = nil
		return
	}
	if len(s) < 4 {
		return
	}
	msgType := s[0]
	bodyLen := int(binary.LittleEndian.Uint16(s[2:4]))
	body := s[4:]
	if bodyLen <= len(body) {
		body = body[:bodyLen]
	}
	switch msgType {
	case rdpsndFormats:
		c.processFormats(body)
	case rdpsndTraining:
		if len(body) >= 4 {
			c.sendTrainingConfirm(binary.LittleEndian.Uint16(body[0:2]), binary.LittleEndian.Uint16(body[2:4]))
		}
	case rdpsndWave:
		c.processWaveInfo(body)
	case rdpsndClose:
		c.waitingWave = false
	default:
		glog.Debugf("rdpsnd: ignore msgType=0x%02x len=%d", msgType, bodyLen)
	}
}

func (c *RDPSNDClient) processFormats(body []byte) {
	if len(body) < 20 {
		return
	}
	n := int(binary.LittleEndian.Uint16(body[14:16]))
	p := 20
	server := make([]rdpsndFormat, 0, n)
	for i := 0; i < n && p+18 <= len(body); i++ {
		f := rdpsndFormat{
			Tag:           binary.LittleEndian.Uint16(body[p : p+2]),
			Channels:      binary.LittleEndian.Uint16(body[p+2 : p+4]),
			SampleRate:    binary.LittleEndian.Uint32(body[p+4 : p+8]),
			AvgBytes:      binary.LittleEndian.Uint32(body[p+8 : p+12]),
			BlockAlign:    binary.LittleEndian.Uint16(body[p+12 : p+14]),
			BitsPerSample: binary.LittleEndian.Uint16(body[p+14 : p+16]),
			ServerIndex:   uint16(i),
		}
		extra := int(binary.LittleEndian.Uint16(body[p+16 : p+18]))
		p += 18
		if extra > 0 && p+extra <= len(body) {
			f.Extra = append([]byte(nil), body[p:p+extra]...)
			p += extra
		}
		server = append(server, f)
	}
	selected := make([]rdpsndFormat, 0, 1)
	for _, f := range server {
		if f.Tag == waveFormatPCM && (f.BitsPerSample == 16 || f.BitsPerSample == 8) && f.Channels >= 1 && f.Channels <= 2 && f.SampleRate > 0 {
			selected = append(selected, f)
			break
		}
	}
	c.formats = selected
	if len(selected) > 0 {
		c.current = selected[0]
		c.currentValid = true
	}
	c.sendClientFormats(selected)
	c.sendQualityMode()
}

func (c *RDPSNDClient) processWaveInfo(body []byte) {
	if len(body) < 12 || len(c.formats) == 0 {
		return
	}
	formatNo := binary.LittleEndian.Uint16(body[2:4])
	if int(formatNo) >= len(c.formats) {
		return
	}
	c.current = c.formats[formatNo]
	c.currentValid = true
	c.waveTimestamp = binary.LittleEndian.Uint16(body[0:2])
	c.waveBlock = body[4]
	c.wavePrefix = append([]byte(nil), body[8:12]...)
	c.waitingWave = true
}

func (c *RDPSNDClient) sendClientFormats(formats []rdpsndFormat) {
	b := &bytes.Buffer{}
	writeU32(b, 0x00000003) // alive + volume
	writeU32(b, 0xffffffff)
	writeU32(b, 0)
	writeU16(b, 0)
	writeU16(b, uint16(len(formats)))
	b.WriteByte(0)
	writeU16(b, 6)
	b.WriteByte(0)
	for _, f := range formats {
		writeU16(b, f.Tag)
		writeU16(b, f.Channels)
		writeU32(b, f.SampleRate)
		writeU32(b, f.AvgBytes)
		writeU16(b, f.BlockAlign)
		writeU16(b, f.BitsPerSample)
		writeU16(b, uint16(len(f.Extra)))
		b.Write(f.Extra)
	}
	c.send(rdpsndFormats, b.Bytes())
}

func (c *RDPSNDClient) sendTrainingConfirm(ts, size uint16) {
	b := &bytes.Buffer{}
	writeU16(b, ts)
	writeU16(b, size)
	c.send(rdpsndTraining, b.Bytes())
}

func (c *RDPSNDClient) sendWaveConfirm(ts uint16, block uint8) {
	b := &bytes.Buffer{}
	writeU16(b, ts)
	b.WriteByte(block)
	b.WriteByte(0)
	c.send(rdpsndWaveConfirm, b.Bytes())
}

func (c *RDPSNDClient) sendQualityMode() {
	b := &bytes.Buffer{}
	writeU16(b, 2) // high quality
	writeU16(b, 0)
	c.send(rdpsndQualityMode, b.Bytes())
}

func (c *RDPSNDClient) send(msgType uint8, payload []byte) {
	if c.sender == nil {
		return
	}
	b := &bytes.Buffer{}
	b.WriteByte(msgType)
	b.WriteByte(0)
	writeU16(b, uint16(len(payload)))
	b.Write(payload)
	_, _ = c.sender.SendToChannel(RDPSND_SVC_CHANNEL_NAME, b.Bytes())
}
