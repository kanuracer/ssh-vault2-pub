package client

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/emission"
	"github.com/tomatome/grdp/plugin"
	"github.com/tomatome/grdp/protocol/pdu"
)

type fakeRDPTransport struct{ emission.Emitter }

func newFakeRDPTransport() *fakeRDPTransport {
	return &fakeRDPTransport{Emitter: *emission.NewEmitter()}
}
func (t *fakeRDPTransport) Read(b []byte) (int, error)  { return 0, nil }
func (t *fakeRDPTransport) Write(b []byte) (int, error) { return len(b), nil }
func (t *fakeRDPTransport) Close() error                { return nil }

var _ core.Transport = (*fakeRDPTransport)(nil)

func localClearPayload(width, height uint16, bgr []byte) []byte {
	body := bytes.NewBuffer(nil)
	body.WriteByte(0)
	body.WriteByte(0)
	binary.Write(body, binary.LittleEndian, uint32(0))
	binary.Write(body, binary.LittleEndian, uint32(0))
	subLen := uint32(13 + len(bgr))
	binary.Write(body, binary.LittleEndian, subLen)
	binary.Write(body, binary.LittleEndian, uint16(0))
	binary.Write(body, binary.LittleEndian, uint16(0))
	binary.Write(body, binary.LittleEndian, width)
	binary.Write(body, binary.LittleEndian, height)
	binary.Write(body, binary.LittleEndian, uint32(len(bgr)))
	body.WriteByte(0)
	body.Write(bgr)
	return body.Bytes()
}

func localGFXHeader(cmd uint16, body []byte) []byte {
	p := make([]byte, 8+len(body))
	binary.LittleEndian.PutUint16(p[0:2], cmd)
	binary.LittleEndian.PutUint32(p[4:8], uint32(len(p)))
	copy(p[8:], body)
	return p
}

func TestRdpClientGraphicsChannelsEmitGFXUpdate(t *testing.T) {
	c := &RdpClient{pdu: pdu.NewClient(newFakeRDPTransport())}
	var got []plugin.RDPGFXSurfaceUpdate
	c.pdu.On("gfx-update", func(data interface{}) {
		for _, u := range data.([]plugin.RDPGFXSurfaceUpdate) {
			got = append(got, u)
		}
	})

	drdynvc := c.newGraphicsDrdynvc()
	drdynvc.Process([]byte{0x10, 0x05, 'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', ':', ':', 'W', 'i', 'n', 'd', 'o', 'w', 's', ':', ':', 'R', 'D', 'S', ':', ':', 'G', 'r', 'a', 'p', 'h', 'i', 'c', 's', 0})

	clear := localClearPayload(1, 1, []byte{0, 0, 255})
	body := make([]byte, 17+len(clear))
	binary.LittleEndian.PutUint16(body[0:2], 1)
	binary.LittleEndian.PutUint16(body[2:4], 8)
	body[4] = 0x20
	binary.LittleEndian.PutUint16(body[5:7], 2)
	binary.LittleEndian.PutUint16(body[7:9], 3)
	binary.LittleEndian.PutUint16(body[9:11], 3)
	binary.LittleEndian.PutUint16(body[11:13], 4)
	binary.LittleEndian.PutUint32(body[13:17], uint32(len(clear)))
	copy(body[17:], clear)
	drdynvc.Process(append([]byte{0x30, 0x05}, localGFXHeader(1, body)...))

	if len(got) != 1 {
		t.Fatalf("gfx updates=%d, want 1", len(got))
	}
	if got[0].Left != 2 || got[0].Top != 3 || !bytes.Equal(got[0].RGBA, []byte{255, 0, 0, 255}) {
		t.Fatalf("update=%+v", got[0])
	}
}
