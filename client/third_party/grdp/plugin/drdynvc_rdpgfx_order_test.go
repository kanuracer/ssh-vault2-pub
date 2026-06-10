package plugin

import (
	"encoding/binary"
	"testing"
)

func TestDrdynvcSendsCreateResponseBeforeRdpgfxCapsAdvertise(t *testing.T) {
	sender := &recordingChannelSender{}
	c := NewDrdynvcClient()
	c.RegisterDynamic(NewRDPGFXClient(nil))
	c.Sender(sender)

	c.Process(drdynvcCreateRequest(7, RDPGFX_DVC_CHANNEL_NAME))

	if len(sender.writes) != 2 {
		t.Fatalf("writes=%d, want create response then rdpgfx caps", len(sender.writes))
	}
	if sender.writes[0][0]>>4 != drdynvcCmdCreate {
		t.Fatalf("first write=%x, want create response", sender.writes[0])
	}
	if sender.writes[1][0]>>4 != drdynvcCmdData {
		t.Fatalf("second write=%x, want dynamic data", sender.writes[1])
	}
	if cmd := binary.LittleEndian.Uint16(sender.writes[1][2:4]); cmd != rdpgfxCmdCapsAdvertise {
		t.Fatalf("second dynamic cmd=0x%04x, want rdpgfx caps advertise", cmd)
	}
}
