package plugin

import (
	"bytes"
	"encoding/binary"
	"testing"
)

type recordingChannelSender struct{ writes [][]byte }

func (s *recordingChannelSender) SendToChannel(channel string, p []byte) (int, error) {
	if channel != DRDYNVC_SVC_CHANNEL_NAME {
		return 0, nil
	}
	s.writes = append(s.writes, append([]byte(nil), p...))
	return len(p), nil
}

type recordingDynamicChannel struct {
	name string
	seen [][]byte
}

func (c *recordingDynamicChannel) DynamicChannelName() string         { return c.name }
func (c *recordingDynamicChannel) OnOpen(sender DynamicChannelSender) {}
func (c *recordingDynamicChannel) ProcessDynamic(data []byte) {
	c.seen = append(c.seen, append([]byte(nil), data...))
}

func drdynvcCapabilityRequest(version uint16) []byte {
	b := bytes.NewBuffer(nil)
	b.WriteByte(0x50)
	b.WriteByte(0)
	binary.Write(b, binary.LittleEndian, version)
	return b.Bytes()
}

func drdynvcCreateRequest(channelID uint32, name string) []byte {
	b := bytes.NewBuffer(nil)
	b.WriteByte(byte(0x10 | drdynvcCBIDOneByte))
	b.WriteByte(byte(channelID))
	b.WriteString(name)
	b.WriteByte(0)
	return b.Bytes()
}

func drdynvcData(channelID uint32, payload []byte) []byte {
	b := bytes.NewBuffer(nil)
	b.WriteByte(byte(0x30 | drdynvcCBIDOneByte))
	b.WriteByte(byte(channelID))
	b.Write(payload)
	return b.Bytes()
}

func TestDrdynvcRepliesToCapabilityRequest(t *testing.T) {
	sender := &recordingChannelSender{}
	c := NewDrdynvcClient()
	c.Sender(sender)

	c.Process(drdynvcCapabilityRequest(3))

	if len(sender.writes) != 1 {
		t.Fatalf("writes=%d, want 1", len(sender.writes))
	}
	want := []byte{0x50, 0x00, 0x03, 0x00}
	if !bytes.Equal(sender.writes[0], want) {
		t.Fatalf("capability response %x, want %x", sender.writes[0], want)
	}
	if st := c.State(); st.CapabilityVersion != 3 || !st.CapabilityConfirmed {
		t.Fatalf("state=%+v, want version=3 confirmed", st)
	}
}

func TestDrdynvcAcceptsRdpgfxCreateAndRoutesData(t *testing.T) {
	sender := &recordingChannelSender{}
	rdpgfx := &recordingDynamicChannel{name: RDPGFX_DVC_CHANNEL_NAME}
	c := NewDrdynvcClient()
	c.RegisterDynamic(rdpgfx)
	c.Sender(sender)

	c.Process(drdynvcCreateRequest(7, RDPGFX_DVC_CHANNEL_NAME))

	if st := c.State(); st.OpenChannels[7] != RDPGFX_DVC_CHANNEL_NAME {
		t.Fatalf("open channels=%+v, want channel 7 rdpgfx", st.OpenChannels)
	}
	if len(sender.writes) != 1 {
		t.Fatalf("writes=%d, want create response", len(sender.writes))
	}
	want := []byte{0x10 | drdynvcCBIDOneByte, 0x07, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(sender.writes[0], want) {
		t.Fatalf("create response %x, want %x", sender.writes[0], want)
	}

	c.Process(drdynvcData(7, []byte("gfx")))
	if len(rdpgfx.seen) != 1 || string(rdpgfx.seen[0]) != "gfx" {
		t.Fatalf("routed=%q, want gfx", rdpgfx.seen)
	}
}
