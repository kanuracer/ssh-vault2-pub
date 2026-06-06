package plugin

import (
	"bytes"
	"encoding/binary"
)

const (
	rdpgfxCmdWireToSurface1   uint16 = 0x0001
	rdpgfxCmdWireToSurface2   uint16 = 0x0002
	rdpgfxCmdCreateSurface    uint16 = 0x0009
	rdpgfxCmdDeleteSurface    uint16 = 0x000a
	rdpgfxCmdStartFrame       uint16 = 0x000b
	rdpgfxCmdEndFrame         uint16 = 0x000c
	rdpgfxCmdFrameAcknowledge uint16 = 0x000d
	rdpgfxCmdResetGraphics    uint16 = 0x000e
	rdpgfxCmdMapSurfaceOutput uint16 = 0x000f
	rdpgfxCmdCapsAdvertise    uint16 = 0x0012
	rdpgfxCmdCapsConfirm      uint16 = 0x0013

	rdpgfxCapVersion8      uint32 = 0x00080004
	rdpgfxCapVersion81     uint32 = 0x00080105
	rdpgfxCapVersion10     uint32 = 0x000a0002
	rdpgfxCapVersion101    uint32 = 0x000a0100
	rdpgfxCapVersion102    uint32 = 0x000a0200
	rdpgfxCapVersion103    uint32 = 0x000a0301
	rdpgfxCapVersion104    uint32 = 0x000a0400
	rdpgfxCapVersion105    uint32 = 0x000a0502
	rdpgfxCapVersion106    uint32 = 0x000a0600
	rdpgfxCapVersion106Err uint32 = 0x000a0601
	rdpgfxCapVersion107    uint32 = 0x000a0701

	rdpgfxCapsFlagAVCDisabled      uint32 = 0x00000020
	rdpgfxCapsFlagScaledMapDisable uint32 = 0x00000080

	rdpgfxCodecIDClearCodec uint16 = 0x0008

	rdpgfxPixelFormatXRGB8888 byte = 0x20
)

type RDPGFXSurfaceUpdate struct {
	SurfaceID uint16
	Left      int
	Top       int
	Width     int
	Height    int
	RGBA      []byte
}

type RDPGFXSurfaceSink func(RDPGFXSurfaceUpdate)

type RDPGFXState struct {
	CapsConfirmed     bool
	SelectedCap       uint32
	CurrentFrameID    uint32
	FramesDecoded     uint32
	SurfaceUpdateSeen uint64
}

type RDPGFXClient struct {
	sender DynamicChannelSender
	sink   RDPGFXSurfaceSink
	state  RDPGFXState
	clear  *ClearCodecDecoder
	zgfx   *ZGFXDecoder
}

func NewRDPGFXClient(sink RDPGFXSurfaceSink) *RDPGFXClient {
	return &RDPGFXClient{sink: sink, clear: NewClearCodecDecoder(), zgfx: NewZGFXDecoder()}
}

func (c *RDPGFXClient) DynamicChannelName() string { return RDPGFX_DVC_CHANNEL_NAME }

func (c *RDPGFXClient) OnOpen(sender DynamicChannelSender) {
	c.sender = sender
	c.sendCapsAdvertise()
}

func (c *RDPGFXClient) ProcessDynamic(data []byte) {
	if len(data) > 0 && (data[0] == zgfxSegmentedSingle || data[0] == zgfxSegmentedMultipart) {
		decoded, err := c.zgfx.Decompress(data)
		if err != nil {
			return
		}
		data = decoded
	}
	r := bytes.NewReader(data)
	for r.Len() >= 8 {
		startLen := r.Len()
		header := make([]byte, 8)
		if _, err := r.Read(header); err != nil {
			return
		}
		cmd := binary.LittleEndian.Uint16(header[0:2])
		pduLen := binary.LittleEndian.Uint32(header[4:8])
		if pduLen < 8 || int(pduLen)-8 > r.Len() {
			return
		}
		body := make([]byte, int(pduLen)-8)
		if _, err := r.Read(body); err != nil {
			return
		}
		c.processPDU(cmd, body)
		if r.Len() == startLen {
			return
		}
	}
}

func (c *RDPGFXClient) State() RDPGFXState { return c.state }

func (c *RDPGFXClient) processPDU(cmd uint16, body []byte) {
	switch cmd {
	case rdpgfxCmdWireToSurface1:
		c.processWireToSurface1(body)
	case rdpgfxCmdCapsConfirm:
		if len(body) >= 4 {
			c.state.CapsConfirmed = true
			c.state.SelectedCap = binary.LittleEndian.Uint32(body[:4])
		}
	case rdpgfxCmdStartFrame:
		if len(body) >= 8 {
			c.state.CurrentFrameID = binary.LittleEndian.Uint32(body[4:8])
		}
	case rdpgfxCmdEndFrame:
		if len(body) >= 4 {
			frameID := binary.LittleEndian.Uint32(body[:4])
			c.state.CurrentFrameID = frameID
			c.state.FramesDecoded++
			c.sendFrameAck(frameID)
		}
	}
}

func (c *RDPGFXClient) processWireToSurface1(body []byte) {
	if len(body) < 17 || c.sink == nil {
		return
	}
	surfaceID := binary.LittleEndian.Uint16(body[0:2])
	codecID := binary.LittleEndian.Uint16(body[2:4])
	pixelFormat := body[4]
	left := int(binary.LittleEndian.Uint16(body[5:7]))
	top := int(binary.LittleEndian.Uint16(body[7:9]))
	right := int(binary.LittleEndian.Uint16(body[9:11]))
	bottom := int(binary.LittleEndian.Uint16(body[11:13]))
	dataLen := int(binary.LittleEndian.Uint32(body[13:17]))
	if right < left || bottom < top || dataLen < 0 || 17+dataLen > len(body) {
		return
	}
	w := right - left
	h := bottom - top
	if w <= 0 || h <= 0 {
		return
	}
	if codecID != rdpgfxCodecIDClearCodec || pixelFormat != rdpgfxPixelFormatXRGB8888 {
		return
	}
	rgba, err := c.clear.Decode(body[17:17+dataLen], w, h)
	if err != nil {
		return
	}
	c.state.SurfaceUpdateSeen++
	c.sink(RDPGFXSurfaceUpdate{SurfaceID: surfaceID, Left: left, Top: top, Width: w, Height: h, RGBA: rgba})
}

func (c *RDPGFXClient) sendCapsAdvertise() {
	type capset struct{ version, length, flags uint32 }
	caps := []capset{
		{rdpgfxCapVersion8, 4, 0},
		{rdpgfxCapVersion81, 4, 0},
		{rdpgfxCapVersion10, 4, rdpgfxCapsFlagAVCDisabled},
		{rdpgfxCapVersion101, 16, 0},
		{rdpgfxCapVersion102, 4, rdpgfxCapsFlagAVCDisabled},
		{rdpgfxCapVersion103, 4, rdpgfxCapsFlagAVCDisabled},
		{rdpgfxCapVersion104, 4, rdpgfxCapsFlagAVCDisabled},
		{rdpgfxCapVersion105, 4, rdpgfxCapsFlagAVCDisabled},
		{rdpgfxCapVersion106, 4, rdpgfxCapsFlagAVCDisabled},
		{rdpgfxCapVersion106Err, 4, rdpgfxCapsFlagAVCDisabled},
		{rdpgfxCapVersion107, 4, rdpgfxCapsFlagAVCDisabled | rdpgfxCapsFlagScaledMapDisable},
	}
	size := 2
	for _, cap := range caps {
		size += 8 + int(cap.length)
	}
	body := make([]byte, size)
	binary.LittleEndian.PutUint16(body[0:2], uint16(len(caps)))
	off := 2
	for _, cap := range caps {
		binary.LittleEndian.PutUint32(body[off:off+4], cap.version)
		binary.LittleEndian.PutUint32(body[off+4:off+8], cap.length)
		if cap.length >= 4 {
			binary.LittleEndian.PutUint32(body[off+8:off+12], cap.flags)
		}
		off += 8 + int(cap.length)
	}
	c.send(rdpgfxCmdCapsAdvertise, body)
}

func (c *RDPGFXClient) sendFrameAck(frameID uint32) {
	body := make([]byte, 12)
	binary.LittleEndian.PutUint32(body[0:4], 0) // QUEUE_DEPTH_UNAVAILABLE
	binary.LittleEndian.PutUint32(body[4:8], frameID)
	binary.LittleEndian.PutUint32(body[8:12], c.state.FramesDecoded)
	c.send(rdpgfxCmdFrameAcknowledge, body)
}

func (c *RDPGFXClient) send(cmd uint16, body []byte) {
	if c.sender == nil {
		return
	}
	p := make([]byte, 8+len(body))
	binary.LittleEndian.PutUint16(p[0:2], cmd)
	binary.LittleEndian.PutUint16(p[2:4], 0)
	binary.LittleEndian.PutUint32(p[4:8], uint32(len(p)))
	copy(p[8:], body)
	_ = c.sender.SendDynamic(p)
}

var _ DynamicChannelTransport = (*RDPGFXClient)(nil)
