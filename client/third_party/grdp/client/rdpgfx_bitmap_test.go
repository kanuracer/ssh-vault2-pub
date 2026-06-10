package client

import (
	"bytes"
	"testing"

	"github.com/tomatome/grdp/plugin"
)

func TestGFXSurfaceUpdateMapsToBitmapForOnBitmapPath(t *testing.T) {
	u := plugin.RDPGFXSurfaceUpdate{SurfaceID: 9, Left: 4, Top: 5, Width: 2, Height: 1, RGBA: []byte{255, 0, 0, 255, 0, 255, 0, 255}}
	b := bitmapFromGFXSurfaceUpdate(u)

	if b.DestLeft != 4 || b.DestTop != 5 || b.DestRight != 5 || b.DestBottom != 5 {
		t.Fatalf("dest=%+v", b)
	}
	if b.Width != 2 || b.Height != 1 || b.BitsPerPixel != 4 || b.ColorDepth != 32 || b.PixelFormat != "rgba32" || b.IsCompress {
		t.Fatalf("bitmap meta=%+v", b)
	}
	if !bytes.Equal(b.Data, u.RGBA) {
		t.Fatalf("data=%v want=%v", b.Data, u.RGBA)
	}
}
