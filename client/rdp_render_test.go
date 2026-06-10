package main

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/tomatome/grdp/client"
)

func TestRDPRenderPacketEncodesBinaryRGBA(t *testing.T) {
	frame := RDPRenderFrame{SessionID: "s1", Seq: 7, Left: 1, Top: 2, Width: 2, Height: 1, SurfaceWidth: 10, SurfaceHeight: 20, Stride: 8, RGBA: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	pkt, err := EncodeRDPRenderPacket(frame)
	if err != nil {
		t.Fatalf("EncodeRDPRenderPacket: %v", err)
	}
	if string(pkt[:6]) != rdpRenderMagic {
		t.Fatalf("magic = %q", pkt[:6])
	}
	if got := binary.LittleEndian.Uint64(pkt[6:14]); got != 7 {
		t.Fatalf("seq = %d", got)
	}
	if got := binary.LittleEndian.Uint32(pkt[14:18]); got != 1 {
		t.Fatalf("left = %d", got)
	}
	if got := binary.LittleEndian.Uint32(pkt[18:22]); got != 2 {
		t.Fatalf("top = %d", got)
	}
	if got := binary.LittleEndian.Uint32(pkt[22:26]); got != 2 {
		t.Fatalf("width = %d", got)
	}
	if got := binary.LittleEndian.Uint32(pkt[26:30]); got != 1 {
		t.Fatalf("height = %d", got)
	}
	if got := pkt[42]; got != 1 {
		t.Fatalf("format = %d", got)
	}
	if got := binary.LittleEndian.Uint32(pkt[50:54]); got != 8 {
		t.Fatalf("payloadLen = %d", got)
	}
	if string(pkt[54:]) != string(frame.RGBA) {
		t.Fatalf("payload = %v", pkt[54:])
	}
}

func TestRDPRenderPacketAdaptiveKeepsRawWithoutClientOptIn(t *testing.T) {
	frame := solidRDPRenderFrame(64, 64)
	pkt, err := EncodeRDPRenderPacketAdaptive(frame, map[byte]bool{})
	if err != nil {
		t.Fatalf("EncodeRDPRenderPacketAdaptive: %v", err)
	}
	if got := pkt[42]; got != rdpRenderFormatRawRGBA {
		t.Fatalf("without client opt-in format = %d, want raw", got)
	}
	if got := binary.LittleEndian.Uint32(pkt[50:54]); got != uint32(len(frame.RGBA)) {
		t.Fatalf("raw payload length = %d", got)
	}
}

func TestRDPRenderPacketAdaptiveStaysRawEvenWhenClientAdvertisesJPEG(t *testing.T) {
	frame := solidRDPRenderFrame(160, 100)
	pkt, err := EncodeRDPRenderPacketAdaptive(frame, map[byte]bool{2: true})
	if err != nil {
		t.Fatalf("EncodeRDPRenderPacketAdaptive: %v", err)
	}
	if got := pkt[42]; got != rdpRenderFormatRawRGBA {
		t.Fatalf("format = %d, want raw; synchronous raw is required until a real low-CPU codec path exists", got)
	}
	if got := int(binary.LittleEndian.Uint32(pkt[50:54])); got != len(frame.RGBA) {
		t.Fatalf("payload = %d, want raw length %d", got, len(frame.RGBA))
	}
}

func solidRDPRenderFrame(width, height int) RDPRenderFrame {
	rgba := make([]byte, width*height*4)
	for i := 0; i < len(rgba); i += 4 {
		rgba[i], rgba[i+1], rgba[i+2], rgba[i+3] = 32, 128, 220, 255
	}
	return RDPRenderFrame{SessionID: "s", Seq: 9, Left: 0, Top: 0, Width: width, Height: height, SurfaceWidth: width, SurfaceHeight: height, Stride: width * 4, RGBA: rgba}
}

func TestRDPRenderHubCoalescesFullSnapshotsToLatestFrameWithoutBlocking(t *testing.T) {
	h := &RDPRenderHub{sessions: map[string]*rdpRenderSession{"s": {id: "s", token: "t", ch: make(chan RDPRenderFrame, 1)}}}
	h.Publish(RDPRenderFrame{SessionID: "s", Seq: 1, Left: 0, Top: 0, Width: 2, Height: 1, SurfaceWidth: 2, SurfaceHeight: 1, RGBA: []byte{1, 1, 1, 1, 1, 1, 1, 1}})
	start := time.Now()
	h.Publish(RDPRenderFrame{SessionID: "s", Seq: 2, Left: 0, Top: 0, Width: 2, Height: 1, SurfaceWidth: 2, SurfaceHeight: 1, RGBA: []byte{2, 2, 2, 2, 2, 2, 2, 2}})
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("Publish blocked on stale frontend full snapshot for %s", elapsed)
	}
	latest := <-h.sessions["s"].ch
	if latest.Seq != 2 {
		t.Fatalf("latest full snapshot not retained: got seq %d", latest.Seq)
	}
}

func TestRDPRenderHubKeepsDirtyFramesOrderedWhileQueueHasRoom(t *testing.T) {
	h := &RDPRenderHub{sessions: map[string]*rdpRenderSession{"s": {id: "s", token: "t", ch: make(chan RDPRenderFrame, 2)}}}
	h.Publish(RDPRenderFrame{SessionID: "s", Seq: 1, Left: 1, Top: 0, Width: 1, Height: 1, SurfaceWidth: 4, SurfaceHeight: 2, RGBA: []byte{1, 1, 1, 255}})
	h.Publish(RDPRenderFrame{SessionID: "s", Seq: 2, Left: 2, Top: 0, Width: 1, Height: 1, SurfaceWidth: 4, SurfaceHeight: 2, RGBA: []byte{2, 2, 2, 255}})
	first := <-h.sessions["s"].ch
	second := <-h.sessions["s"].ch
	if first.Seq != 1 || second.Seq != 2 {
		t.Fatalf("dirty frames must stay ordered, got %d then %d", first.Seq, second.Seq)
	}
}

func TestRDPRenderHubCoalescesDirtyBackpressureToLatestFrame(t *testing.T) {
	h := &RDPRenderHub{sessions: map[string]*rdpRenderSession{"s": {id: "s", token: "t", ch: make(chan RDPRenderFrame, 1)}}}
	dirty1 := RDPRenderFrame{SessionID: "s", Seq: 1, Left: 1, Top: 0, Width: 1, Height: 1, SurfaceWidth: 4, SurfaceHeight: 2, RGBA: []byte{1, 1, 1, 255}}
	dirty2 := RDPRenderFrame{SessionID: "s", Seq: 2, Left: 2, Top: 0, Width: 1, Height: 1, SurfaceWidth: 4, SurfaceHeight: 2, RGBA: []byte{2, 2, 2, 255}}
	if !h.Publish(dirty1) {
		t.Fatalf("first dirty publish rejected")
	}
	start := time.Now()
	if !h.Publish(dirty2) {
		t.Fatalf("second dirty publish rejected")
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("dirty publish blocked under backpressure for %s", elapsed)
	}
	latest := <-h.sessions["s"].ch
	if latest.Seq != 2 {
		t.Fatalf("latest dirty frame not retained: got seq %d", latest.Seq)
	}
}

func TestRDPFullSnapshotStartsSmallDirtyKeyframeTimer(t *testing.T) {
	r := &rdpRec{state: SessionState{ID: "s"}, fbWidth: 4, fbHeight: 4, fb: make([]byte, 4*4*4)}
	if _, ok := r.rdpFullSnapshot(); !ok {
		t.Fatalf("missing full snapshot")
	}
	if r.lastFullAt.IsZero() {
		t.Fatalf("full snapshot must update keyframe timer")
	}
	r.markDirty(0, 0, 1, 1)
	frame, ok := r.rdpAdaptiveSnapshot(r.lastFullAt.Add(rdpFullKeyframeInterval + time.Millisecond))
	if !ok || !frame.IsFullSurface() {
		t.Fatalf("small dirty after keyframe interval must publish full heal frame, got ok=%v frame=%#v", ok, frame)
	}
}

func TestRDPFramebufferMotionPumpPublishesFullSnapshotForCoalescing(t *testing.T) {
	svc := NewAppService()
	id := "rdp-motion-full-snapshot"
	r := &rdpRec{state: SessionState{ID: id}, width: 4, height: 2, closed: make(chan struct{})}
	svc.mu.Lock()
	svc.rdps[id] = r
	svc.mu.Unlock()
	red := client.Bitmap{DestLeft: 0, DestTop: 0, DestRight: 1, DestBottom: 0, Width: 2, Height: 1, BitsPerPixel: 4, Data: []byte{0, 0, 255, 0, 0, 0, 255, 0}}
	blue := client.Bitmap{DestLeft: 2, DestTop: 0, DestRight: 3, DestBottom: 0, Width: 2, Height: 1, BitsPerPixel: 4, Data: []byte{255, 0, 0, 0, 255, 0, 0, 0}}
	if err := svc.rdpApplyBitmaps(id, []client.Bitmap{red, blue}); err != nil {
		t.Fatalf("rdpApplyBitmaps: %v", err)
	}
	frame, ok := r.rdpFullSnapshot()
	if !ok {
		t.Fatalf("missing full snapshot")
	}
	if frame.Left != 0 || frame.Top != 0 || frame.Width != 4 || frame.Height != 2 {
		t.Fatalf("motion pump snapshot geometry = %#v", frame)
	}
	if !frame.IsFullSurface() {
		t.Fatalf("motion pump must publish full surface so RenderHub can coalesce stale frames")
	}
}

func TestRDPFramebufferCompositePublishesCompactDirtyUnion(t *testing.T) {
	svc := NewAppService()
	id := "rdp-fb"
	svc.mu.Lock()
	svc.rdps[id] = &rdpRec{width: 4, height: 2, closed: make(chan struct{})}
	svc.mu.Unlock()
	red := client.Bitmap{DestLeft: 0, DestTop: 0, DestRight: 1, DestBottom: 0, Width: 2, Height: 1, BitsPerPixel: 4, Data: []byte{0, 0, 255, 0, 0, 0, 255, 0}}
	blue := client.Bitmap{DestLeft: 2, DestTop: 0, DestRight: 3, DestBottom: 0, Width: 2, Height: 1, BitsPerPixel: 4, Data: []byte{255, 0, 0, 0, 255, 0, 0, 0}}
	frame, err := svc.rdpBitmapsToRenderFrame(id, []client.Bitmap{red, blue})
	if err != nil {
		t.Fatalf("rdpBitmapsToRenderFrame: %v", err)
	}
	if frame.Left != 0 || frame.Top != 0 || frame.Width != 4 || frame.Height != 1 {
		t.Fatalf("frame must be compact dirty union, got %#v", frame)
	}
	wantPrefix := []byte{
		255, 0, 0, 255, 255, 0, 0, 255,
		0, 0, 255, 255, 0, 0, 255, 255,
	}
	if string(frame.RGBA[:len(wantPrefix)]) != string(wantPrefix) {
		t.Fatalf("top row rgba = %v, want %v", frame.RGBA[:len(wantPrefix)], wantPrefix)
	}
	if len(frame.RGBA) != 4*1*4 {
		t.Fatalf("dirty union bytes = %d", len(frame.RGBA))
	}
}
