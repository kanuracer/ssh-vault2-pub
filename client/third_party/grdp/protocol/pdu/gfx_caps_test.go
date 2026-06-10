package pdu

import (
	"testing"

	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/emission"
)

type fakeCapTransport struct{ *emission.Emitter }

func (t *fakeCapTransport) Read(b []byte) (int, error)                      { return 0, nil }
func (t *fakeCapTransport) Write(b []byte) (int, error)                     { return len(b), nil }
func (t *fakeCapTransport) Close() error                                    { return nil }
func (t *fakeCapTransport) Connect() error                                  { return nil }
func (t *fakeCapTransport) SendFastPath(secFlag byte, payload []byte) error { return nil }

var _ core.Transport = (*fakeCapTransport)(nil)

func TestPDULayerAdvertisesGraphicsSurfaceCapabilities(t *testing.T) {
	p := NewPDULayer(&fakeCapTransport{Emitter: emission.NewEmitter()})
	if _, ok := p.clientCapabilities[CAPSETTYPE_SURFACE_COMMANDS].(*SurfaceCommandsCapability); !ok {
		t.Fatalf("missing surface commands capability")
	}
	fa, ok := p.clientCapabilities[CAPSSETTYPE_FRAME_ACKNOWLEDGE].(*FrameAcknowledgeCapability)
	if !ok {
		t.Fatalf("missing frame acknowledge capability")
	}
	if fa.MaxUnacknowledgedFrameCount == 0 {
		t.Fatalf("frame acknowledge count not set")
	}
}
