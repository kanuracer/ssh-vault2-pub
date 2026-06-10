package plugin

import (
	"bytes"
	"encoding/binary"
	"testing"
)

type recordingDynamicSenderForGfx struct{ writes [][]byte }

func (s *recordingDynamicSenderForGfx) SendDynamic(p []byte) error {
	s.writes = append(s.writes, append([]byte(nil), p...))
	return nil
}

func rdpgfxHeader(cmd uint16, body []byte) []byte {
	p := make([]byte, 8+len(body))
	binary.LittleEndian.PutUint16(p[0:2], cmd)
	binary.LittleEndian.PutUint16(p[2:4], 0)
	binary.LittleEndian.PutUint32(p[4:8], uint32(len(p)))
	copy(p[8:], body)
	return p
}

func TestRDPGFXOnOpenSendsCapsAdvertiseWithAVCDisabled(t *testing.T) {
	sender := &recordingDynamicSenderForGfx{}
	gfx := NewRDPGFXClient(nil)

	if got := gfx.DynamicChannelName(); got != RDPGFX_DVC_CHANNEL_NAME {
		t.Fatalf("name=%q", got)
	}
	gfx.OnOpen(sender)

	if len(sender.writes) != 1 {
		t.Fatalf("writes=%d, want caps advertise", len(sender.writes))
	}
	p := sender.writes[0]
	if len(p) < 22 {
		t.Fatalf("caps advertise too short: %x", p)
	}
	if cmd := binary.LittleEndian.Uint16(p[0:2]); cmd != rdpgfxCmdCapsAdvertise {
		t.Fatalf("cmd=0x%04x, want caps advertise", cmd)
	}
	count := binary.LittleEndian.Uint16(p[8:10])
	if count < 8 {
		t.Fatalf("caps count=%d, want desktop client-like cap ladder", count)
	}
	seen107 := false
	off := 10
	for i := 0; i < int(count); i++ {
		if off+8 > len(p) {
			t.Fatalf("cap %d truncated", i)
		}
		version := binary.LittleEndian.Uint32(p[off : off+4])
		length := binary.LittleEndian.Uint32(p[off+4 : off+8])
		if off+8+int(length) > len(p) {
			t.Fatalf("cap %d length=%d truncated", i, length)
		}
		flags := uint32(0)
		if length >= 4 {
			flags = binary.LittleEndian.Uint32(p[off+8 : off+12])
		}
		if version == rdpgfxCapVersion107 {
			seen107 = true
			if flags&rdpgfxCapsFlagAVCDisabled == 0 || flags&rdpgfxCapsFlagScaledMapDisable == 0 {
				t.Fatalf("10.7 flags=0x%08x, want AVC disabled + scaled-map disabled", flags)
			}
		}
		off += 8 + int(length)
	}
	if !seen107 {
		t.Fatalf("10.7 cap missing")
	}
}

func TestRDPGFXWireToSurface1ClearCodecEmitsSurfaceUpdate(t *testing.T) {
	updates := make([]RDPGFXSurfaceUpdate, 0, 1)
	gfx := NewRDPGFXClient(func(u RDPGFXSurfaceUpdate) { updates = append(updates, u) })
	payload := clearCodecUncompressedPayload(1, 1, []byte{0x00, 0x00, 0xff})
	body := make([]byte, 2+2+1+8+4+len(payload))
	binary.LittleEndian.PutUint16(body[0:2], 3) // surfaceId
	binary.LittleEndian.PutUint16(body[2:4], rdpgfxCodecIDClearCodec)
	body[4] = rdpgfxPixelFormatXRGB8888
	binary.LittleEndian.PutUint16(body[5:7], 10)   // left
	binary.LittleEndian.PutUint16(body[7:9], 20)   // top
	binary.LittleEndian.PutUint16(body[9:11], 11)  // right
	binary.LittleEndian.PutUint16(body[11:13], 21) // bottom
	binary.LittleEndian.PutUint32(body[13:17], uint32(len(payload)))
	copy(body[17:], payload)

	gfx.ProcessDynamic(rdpgfxHeader(rdpgfxCmdWireToSurface1, body))

	if len(updates) != 1 {
		t.Fatalf("updates=%d, want 1", len(updates))
	}
	u := updates[0]
	if u.SurfaceID != 3 || u.Left != 10 || u.Top != 20 || u.Width != 1 || u.Height != 1 {
		t.Fatalf("update meta=%+v", u)
	}
	if want := []byte{255, 0, 0, 255}; !bytes.Equal(u.RGBA, want) {
		t.Fatalf("rgba=%v, want %v", u.RGBA, want)
	}
}

func TestRDPGFXEndFrameSendsFrameAcknowledge(t *testing.T) {
	sender := &recordingDynamicSenderForGfx{}
	gfx := NewRDPGFXClient(nil)
	gfx.OnOpen(sender)
	sender.writes = nil

	body := make([]byte, 4)
	binary.LittleEndian.PutUint32(body, 42)
	gfx.ProcessDynamic(rdpgfxHeader(rdpgfxCmdEndFrame, body))

	if len(sender.writes) != 1 {
		t.Fatalf("writes=%d, want frame ack", len(sender.writes))
	}
	ack := sender.writes[0]
	if cmd := binary.LittleEndian.Uint16(ack[0:2]); cmd != rdpgfxCmdFrameAcknowledge {
		t.Fatalf("cmd=0x%04x, want frame ack", cmd)
	}
	if frameID := binary.LittleEndian.Uint32(ack[12:16]); frameID != 42 {
		t.Fatalf("frameID=%d, want 42", frameID)
	}
	if total := binary.LittleEndian.Uint32(ack[16:20]); total != 1 {
		t.Fatalf("total=%d, want 1", total)
	}
}
