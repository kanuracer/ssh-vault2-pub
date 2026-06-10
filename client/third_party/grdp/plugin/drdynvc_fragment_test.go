package plugin

import "testing"

func TestDrdynvcReassemblesDataFirstWithTwoByteLength(t *testing.T) {
	ch := &recordingDynamicChannel{name: RDPGFX_DVC_CHANNEL_NAME}
	c := NewDrdynvcClient()
	c.RegisterDynamic(ch)
	// open graphics channel id=7
	c.Process([]byte{0x10, 0x07, 'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', ':', ':', 'W', 'i', 'n', 'd', 'o', 'w', 's', ':', ':', 'R', 'D', 'S', ':', ':', 'G', 'r', 'a', 'p', 'h', 'i', 'c', 's', 0})

	// DATA_FIRST: cmd=2, Sp=1 => 2-byte length, cbChId=0 => 1-byte channel id.
	c.Process([]byte{0x24, 0x07, 0x05, 0x00, 'h', 'e'})
	if len(ch.seen) != 0 {
		t.Fatalf("delivered partial payload")
	}
	c.Process([]byte{0x30, 0x07, 'l', 'l', 'o'})
	if len(ch.seen) != 1 || string(ch.seen[0]) != "hello" {
		t.Fatalf("payloads=%q", ch.seen)
	}
}
