package main

import (
	"bytes"
	"testing"

	"github.com/tomatome/grdp/client"
)

func TestRDPApplyGFXRGBA32BitmapUsesInclusiveDestBounds(t *testing.T) {
	svc := NewAppService()
	id := "gfx-rgba"
	svc.rdps[id] = &rdpRec{state: SessionState{ID: id}, width: 4, height: 4, closed: make(chan struct{}), renderWake: make(chan struct{}, 1)}
	bm := client.Bitmap{DestLeft: 1, DestTop: 2, DestRight: 2, DestBottom: 2, Width: 2, Height: 1, BitsPerPixel: 4, ColorDepth: 32, PixelFormat: "rgba32", Data: []byte{255, 0, 0, 255, 0, 255, 0, 255}}

	if err := svc.rdpApplyBitmaps(id, []client.Bitmap{bm}); err != nil {
		t.Fatalf("rdpApplyBitmaps error: %v", err)
	}
	r := svc.rdps[id]
	got := r.fb[((2*r.fbWidth)+1)*4 : ((2*r.fbWidth)+3)*4]
	want := []byte{255, 0, 0, 255, 0, 255, 0, 255}
	if !bytes.Equal(got, want) {
		t.Fatalf("fb pixels=%v want=%v", got, want)
	}
}
