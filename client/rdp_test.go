package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tomatome/grdp/client"
	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/plugin"
)

func TestRDPHostDefaultsAndSecretScrub(t *testing.T) {
	withTempConfig(t)
	svc := NewAppService()
	unlockTestVault(t, svc)

	hosts, err := svc.SaveHost(HostConfig{
		Name:        "winbox",
		Address:     "192.0.2.115",
		Port:        22,
		Username:    "sshuser",
		AuthMode:    "agent",
		RDPEnabled:  true,
		RDPUsername: "rdpuser",
		RDPPassword: "test-password",
	})
	if err != nil {
		t.Fatalf("SaveHost: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(hosts))
	}
	listed := hosts[0]
	if !listed.RDPEnabled {
		t.Fatalf("RDPEnabled lost: %#v", listed)
	}
	if listed.RDPPort != 3389 {
		t.Fatalf("RDPPort = %d, want default 3389", listed.RDPPort)
	}
	if listed.RDPKeyboardLayout != "en-US" {
		t.Fatalf("RDPKeyboardLayout = %q, want en-US", listed.RDPKeyboardLayout)
	}
	if listed.RDPPassword != "" {
		t.Fatalf("RDP password exposed to renderer: %#v", listed)
	}
	if !listed.RDPPasswordSaved {
		t.Fatalf("RDP password saved flag missing: %#v", listed)
	}

	raw, err := svc.readHostsRaw()
	if err != nil {
		t.Fatalf("readHostsRaw: %v", err)
	}
	if len(raw) != 1 {
		t.Fatalf("raw hosts = %d, want 1", len(raw))
	}
	if raw[0].RDPPassword == "test-password" || !strings.HasPrefix(raw[0].RDPPassword, encPrefix) {
		t.Fatalf("RDP password not encrypted at rest: %#v", raw[0])
	}
	dec, err := svc.decryptHostSecrets(raw[0], false)
	if err != nil {
		t.Fatalf("decryptHostSecrets: %v", err)
	}
	if dec.RDPPassword != "test-password" {
		t.Fatalf("RDP password did not round-trip: %#v", dec)
	}
}

func TestRDPProtocolHostDefaultsAndSecretScrub(t *testing.T) {
	withTempConfig(t)
	svc := NewAppService()
	unlockTestVault(t, svc)

	hosts, err := svc.SaveHost(HostConfig{
		Protocol:    "rdp",
		Name:        "winbox-protocol",
		Address:     "rdp.example.test",
		RDPUsername: "rdpuser",
		RDPPassword: "test-password",
	})
	if err != nil {
		t.Fatalf("SaveHost: %v", err)
	}
	listed := hosts[0]
	if listed.Protocol != "rdp" || !listed.RDPEnabled {
		t.Fatalf("protocol/RDPEnabled not normalized: %#v", listed)
	}
	if listed.RDPPort != 3389 {
		t.Fatalf("RDPPort = %d, want default 3389", listed.RDPPort)
	}
	if listed.RDPKeyboardLayout != "en-US" {
		t.Fatalf("RDPKeyboardLayout = %q, want en-US", listed.RDPKeyboardLayout)
	}
	if listed.RDPPassword != "" || !listed.RDPPasswordSaved {
		t.Fatalf("RDP password not scrubbed/saved: %#v", listed)
	}
}

func TestSwitchingRDPHostToSSHClearsRDPSecret(t *testing.T) {
	withTempConfig(t)
	svc := NewAppService()
	unlockTestVault(t, svc)

	hosts, err := svc.SaveHost(HostConfig{Protocol: "rdp", Name: "box", Address: "rdp.example.test", RDPUsername: "rdpuser", RDPPassword: "test-password"})
	if err != nil {
		t.Fatalf("SaveHost rdp: %v", err)
	}
	id := hosts[0].ID
	_, err = svc.SaveHost(HostConfig{ID: id, Protocol: "ssh", Name: "box", Address: "ssh.example.test", Port: 22, Username: "sshuser", AuthMode: "agent"})
	if err != nil {
		t.Fatalf("SaveHost ssh: %v", err)
	}
	raw, err := svc.readHostsRaw()
	if err != nil {
		t.Fatalf("readHostsRaw: %v", err)
	}
	if len(raw) != 1 {
		t.Fatalf("raw hosts = %d", len(raw))
	}
	if raw[0].Protocol != "ssh" || raw[0].RDPEnabled || raw[0].RDPPassword != "" || raw[0].RDPUsername != "" || raw[0].RDPKeyboardLayout != "" {
		t.Fatalf("RDP state leaked after switch to SSH: %#v", raw[0])
	}
}

func TestRDPKeyboardLayoutNormalizesAndPersists(t *testing.T) {
	withTempConfig(t)
	svc := NewAppService()
	unlockTestVault(t, svc)
	hosts, err := svc.SaveHost(HostConfig{Protocol: "rdp", Name: "debox", Address: "rdp.example.test", RDPUsername: "rdpuser", RDPPassword: "test-password", RDPKeyboardLayout: "de"})
	if err != nil {
		t.Fatalf("SaveHost: %v", err)
	}
	if got := hosts[0].RDPKeyboardLayout; got != "de-DE" {
		t.Fatalf("RDPKeyboardLayout = %q, want de-DE", got)
	}
	if code := rdpKeyboardLayoutCode(hosts[0].RDPKeyboardLayout); code != 0x00000407 {
		t.Fatalf("German keyboard layout code = %#x, want 0x407", code)
	}
	if code := rdpKeyboardLayoutCode(""); code != 0x00000409 {
		t.Fatalf("default keyboard layout code = %#x, want 0x409", code)
	}
}

func TestRDPFrameIncludesSessionSize(t *testing.T) {
	svc := NewAppService()
	id := "rdp-test-session"
	svc.mu.Lock()
	svc.rdps[id] = &rdpRec{width: 1454, height: 480}
	svc.mu.Unlock()
	bm := client.Bitmap{DestLeft: 20, DestTop: 10, Width: 2, Height: 1, BitsPerPixel: 4, Data: []byte{0, 0, 255, 0, 0, 255, 0, 0}}
	frame, err := svc.rdpBitmapToRenderFrame(id, bm)
	if err != nil {
		t.Fatalf("rdpBitmapToRenderFrame: %v", err)
	}
	if frame.SurfaceWidth != 1454 || frame.SurfaceHeight != 480 {
		t.Fatalf("session size = %dx%d", frame.SurfaceWidth, frame.SurfaceHeight)
	}
	if frame.Width != 2 || frame.Height != 1 || frame.Left != 20 || frame.Top != 10 || frame.Stride != 2*4 {
		t.Fatalf("frame must be compact dirty rect: left=%d top=%d size=%dx%d stride=%d", frame.Left, frame.Top, frame.Width, frame.Height, frame.Stride)
	}
	want := []byte{255, 0, 0, 255, 0, 255, 0, 255}
	if string(frame.RGBA) != string(want) {
		t.Fatalf("dirty pixels = %v, want %v", frame.RGBA, want)
	}
}

func TestRDPFullSnapshotPreservesCompositeFramebuffer(t *testing.T) {
	svc := NewAppService()
	id := "rdp-full-snapshot"
	r := &rdpRec{state: SessionState{ID: id}, width: 4, height: 2}
	svc.mu.Lock()
	svc.rdps[id] = r
	svc.mu.Unlock()
	bm := client.Bitmap{DestLeft: 1, DestTop: 1, Width: 2, Height: 1, BitsPerPixel: 4, Data: []byte{0, 0, 255, 0, 0, 255, 0, 0}}
	if _, err := svc.rdpBitmapToRenderFrame(id, bm); err != nil {
		t.Fatalf("rdpBitmapToRenderFrame: %v", err)
	}
	snap, ok := r.rdpFullSnapshot()
	if !ok {
		t.Fatalf("missing full snapshot")
	}
	if snap.Left != 0 || snap.Top != 0 || snap.Width != 4 || snap.Height != 2 || snap.Stride != 16 {
		t.Fatalf("snapshot geometry = %#v", snap)
	}
	px := ((1 * snap.Width) + 1) * 4
	want := []byte{255, 0, 0, 255, 0, 255, 0, 255}
	if string(snap.RGBA[px:px+len(want)]) != string(want) {
		t.Fatalf("snapshot pixels = %v, want %v", snap.RGBA[px:px+len(want)], want)
	}
}

func TestRDPAdaptiveSnapshotUsesDirtyRectForSmallDamage(t *testing.T) {
	id := "rdp-adaptive-dirty"
	r := &rdpRec{state: SessionState{ID: id}, width: 1280, height: 800}
	svc := NewAppService()
	svc.mu.Lock()
	svc.rdps[id] = r
	svc.mu.Unlock()
	bm := client.Bitmap{DestLeft: 10, DestTop: 20, Width: 64, Height: 64, BitsPerPixel: 4, Data: make([]byte, 64*64*4)}
	if err := svc.rdpApplyBitmaps(id, []client.Bitmap{bm}); err != nil {
		t.Fatalf("rdpApplyBitmaps: %v", err)
	}
	frame, ok := r.rdpAdaptiveSnapshot(time.Unix(10, 0))
	if !ok {
		t.Fatalf("missing adaptive snapshot")
	}
	if frame.IsFullSurface() {
		t.Fatalf("small damage must stay dirty rect, got full %dx%d payload=%d", frame.Width, frame.Height, len(frame.RGBA))
	}
	if frame.Left != 10 || frame.Top != 20 || frame.Width != 64 || frame.Height != 64 || len(frame.RGBA) != 64*64*4 {
		t.Fatalf("dirty frame = %#v payload=%d", frame, len(frame.RGBA))
	}
}

func TestRDPAdaptiveSnapshotUsesFullForLargeDamageAndKeyframes(t *testing.T) {
	id := "rdp-adaptive-full"
	r := &rdpRec{state: SessionState{ID: id}, width: 900, height: 600}
	svc := NewAppService()
	svc.mu.Lock()
	svc.rdps[id] = r
	svc.mu.Unlock()
	large := client.Bitmap{DestLeft: 0, DestTop: 0, Width: 700, Height: 600, BitsPerPixel: 4, Data: make([]byte, 700*600*4)}
	if err := svc.rdpApplyBitmaps(id, []client.Bitmap{large}); err != nil {
		t.Fatalf("rdpApplyBitmaps large: %v", err)
	}
	frame, ok := r.rdpAdaptiveSnapshot(time.Unix(20, 0))
	if !ok || !frame.IsFullSurface() {
		t.Fatalf("large damage must publish full latest-wins frame, ok=%v frame=%#v", ok, frame)
	}
	small := client.Bitmap{DestLeft: 1, DestTop: 1, Width: 8, Height: 8, BitsPerPixel: 4, Data: make([]byte, 8*8*4)}
	if err := svc.rdpApplyBitmaps(id, []client.Bitmap{small}); err != nil {
		t.Fatalf("rdpApplyBitmaps small: %v", err)
	}
	frame, ok = r.rdpAdaptiveSnapshot(time.Unix(21, 200_000_000))
	if !ok || !frame.IsFullSurface() {
		t.Fatalf("dirty update after keyframe interval must repair with full frame, ok=%v frame=%#v", ok, frame)
	}
}

func TestRDPAdaptiveSnapshotUsesFullForWin11TileBurstMotion(t *testing.T) {
	id := "rdp-win11-tile-burst"
	r := &rdpRec{state: SessionState{ID: id}, width: 1280, height: 720}
	svc := NewAppService()
	svc.mu.Lock()
	svc.rdps[id] = r
	svc.mu.Unlock()
	tiles := make([]client.Bitmap, 0, 8)
	for i := 0; i < 8; i++ {
		tiles = append(tiles, client.Bitmap{DestLeft: i * 80, DestTop: 90, Width: 80, Height: 120, BitsPerPixel: 4, Data: make([]byte, 80*120*4)})
	}
	if err := svc.rdpApplyBitmaps(id, tiles); err != nil {
		t.Fatalf("rdpApplyBitmaps: %v", err)
	}
	frame, ok := r.rdpAdaptiveSnapshot(time.Unix(30, 0))
	if !ok {
		t.Fatalf("missing adaptive snapshot")
	}
	if !frame.IsFullSurface() {
		t.Fatalf("Win11 tile-burst motion should publish full latest-wins frame, not visible dirty sweep: frame=%#v payload=%d", frame, len(frame.RGBA))
	}
	if r.pendingBitmapRects != 0 {
		t.Fatalf("pending tile counter not reset after snapshot: %d", r.pendingBitmapRects)
	}
}

func TestRDPPixelRGB16BppUsesLittleEndianRGB565(t *testing.T) {
	r, g, b := rdpPixelRGBWithDepth(2, 16, []byte{0x00, 0xf8}, 0)
	if r < 250 || g != 0 || b != 0 {
		t.Fatalf("RGB565 red decoded as r=%d g=%d b=%d", r, g, b)
	}
}

func TestRDPPixelRGB15BppUsesRGB555NotRGB565(t *testing.T) {
	// RGB555 red is 0x7c00 little-endian. If treated as RGB565 it becomes
	// muddy yellow/green, the same class of server-colour bug as bad RLE endian.
	r, g, b := rdpPixelRGBWithDepth(2, 15, []byte{0x00, 0x7c}, 0)
	if r < 250 || g != 0 || b != 0 {
		t.Fatalf("RGB555 red decoded as r=%d g=%d b=%d", r, g, b)
	}
}

func TestRDPBitmapRGBAHonorsBitmapColorDepth(t *testing.T) {
	bm := client.Bitmap{DestLeft: 0, DestTop: 0, Width: 1, Height: 1, BitsPerPixel: 2, ColorDepth: 15, Data: []byte{0x00, 0x7c}}
	rgba, err := rdpBitmapRGBA(bm)
	if err != nil {
		t.Fatalf("rdpBitmapRGBA: %v", err)
	}
	want := []byte{255, 0, 0, 255}
	if string(rgba) != string(want) {
		t.Fatalf("15bpp bitmap rgba = %v, want %v", rgba, want)
	}
}

func TestRDPCompressed16BppRLEDecodesToCorrectRGBA(t *testing.T) {
	// Windows Server can negotiate 16bpp compressed bitmap updates. The RLE
	// decoder must keep RGB565 bytes little-endian for rdpBitmapRGBA; big-endian
	// output makes server desktops look neon/posterized.
	stream := core.Decompress([]byte{0xf3, 0x01, 0x00, 0x00, 0xf8}, 1, 1, 2)
	bm := client.Bitmap{DestLeft: 0, DestTop: 0, Width: 1, Height: 1, BitsPerPixel: 2, ColorDepth: 16, Data: stream}
	rgba, err := rdpBitmapRGBA(bm)
	if err != nil {
		t.Fatalf("rdpBitmapRGBA: %v", err)
	}
	want := []byte{255, 0, 0, 255}
	if string(rgba) != string(want) {
		t.Fatalf("16bpp compressed RGBA = %v, want %v", rgba, want)
	}
}

func TestRDPDiagnosticsTracksFormatAndRenderBackpressureStats(t *testing.T) {
	svc := NewAppService()
	id := "rdp-diag"
	r := &rdpRec{state: SessionState{ID: id}, width: 4, height: 4}
	svc.rdps[id] = r
	bm := client.Bitmap{DestLeft: 0, DestTop: 0, Width: 1, Height: 1, BitsPerPixel: 2, ColorDepth: 15, IsCompress: true, Data: []byte{0x00, 0x7c}}
	if err := svc.rdpApplyBitmaps(id, []client.Bitmap{bm}); err != nil {
		t.Fatalf("rdpApplyBitmaps: %v", err)
	}
	if _, ok := r.rdpAdaptiveSnapshot(time.Unix(42, 0)); !ok {
		t.Fatalf("missing adaptive snapshot")
	}
	diag, err := svc.RDPDiagnostics(id)
	if err != nil {
		t.Fatalf("RDPDiagnostics: %v", err)
	}
	if diag.SessionID != id || diag.BitmapUpdates != 1 || diag.CompressedUpdates != 1 || diag.DirtyFrames != 1 || diag.LastPixelFormat != "rgb555-15bpp" {
		t.Fatalf("diagnostics = %#v", diag)
	}
	if diag.ColorDepths["15"] != 1 || diag.BytesApplied != 4 || diag.LastFrameAt == 0 {
		t.Fatalf("diagnostics counters = %#v", diag)
	}
}

func TestRDPFrameUsesRawRGBAForBinaryWebGLTransport(t *testing.T) {
	svc := NewAppService()
	id := "rdp-binary-frame"
	svc.mu.Lock()
	svc.rdps[id] = &rdpRec{width: 2, height: 1}
	svc.mu.Unlock()
	bm := client.Bitmap{DestLeft: 0, DestTop: 0, Width: 2, Height: 1, BitsPerPixel: 4, Data: []byte{0, 0, 255, 0, 0, 255, 0, 0}}
	frame, err := svc.rdpBitmapToRenderFrame(id, bm)
	if err != nil {
		t.Fatalf("rdpBitmapToRenderFrame: %v", err)
	}
	if frame.Stride != 8 || frame.SurfaceWidth != 2 || frame.SurfaceHeight != 1 || frame.Seq != 1 {
		t.Fatalf("binary RGBA metadata missing: %#v", frame)
	}
	want := []byte{255, 0, 0, 255, 0, 255, 0, 255}
	if string(frame.RGBA) != string(want) {
		t.Fatalf("rgba = %v, want %v", frame.RGBA, want)
	}
}
func TestRDPBitmapCallbackOnlySignalsRenderPump(t *testing.T) {
	body, err := os.ReadFile("rdp.go")
	if err != nil {
		t.Fatalf("read rdp.go: %v", err)
	}
	src := string(body)
	if !strings.Contains(src, "s.rdpApplyBitmaps(id, bitmaps)") || !strings.Contains(src, "r.signalRender()") || !strings.Contains(src, "runRDPRenderPump") {
		t.Fatalf("RDP bitmap callback must update framebuffer and signal the 60fps render pump")
	}
	callback := src[strings.Index(src, "cli.OnBitmap(func(bitmaps []client.Bitmap)"):strings.Index(src, "if err := cli.Login()")]
	if strings.Contains(callback, "s.render.Publish") || strings.Contains(callback, "rdpBitmapsToRenderFrame") {
		t.Fatalf("bitmap callback must not publish/copy render frames synchronously: %s", callback)
	}
	if strings.Contains(src, "RDPFramePayload") || strings.Contains(src, "rdpFramesEvent") || strings.Contains(src, "RGBABase64") {
		t.Fatalf("legacy Wails/base64 RDP render path must not remain")
	}
}
func TestRDPWailsRegistersStatusOnlyNoRenderFrames(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(body)
	if !strings.Contains(src, "application.RegisterEvent[SessionState](rdpStatusEvent)") {
		t.Fatalf("missing RDP status event registration")
	}
	if strings.Contains(src, "RDPFramePayload") || strings.Contains(src, "rdpFrameEvent") || strings.Contains(src, "rdpFramesEvent") {
		t.Fatalf("RDP render frames must not use Wails events")
	}
}
func TestRDPControlPlaneUsesEngineInterface(t *testing.T) {
	body, err := os.ReadFile("rdp_control_plane.go")
	if err != nil {
		t.Fatalf("read rdp_control_plane.go: %v", err)
	}
	control := string(body)
	for _, want := range []string{"type rdpEngineControl interface", "Login() error", "OnBitmap(func([]client.Bitmap))", "MouseMove(x, y int)", "KeyDown(scancode int, code string)", "var _ rdpEngineControl = (*client.Client)(nil)"} {
		if !strings.Contains(control, want) {
			t.Fatalf("RDP engine control-plane missing %q", want)
		}
	}
	body, err = os.ReadFile("rdp.go")
	if err != nil {
		t.Fatalf("read rdp.go: %v", err)
	}
	src := string(body)
	if !regexp.MustCompile(`(?m)^\s*client\s+rdpEngineControl\s*$`).MatchString(src) {
		t.Fatalf("AppService RDP path should depend on rdpEngineControl")
	}
	if !strings.Contains(src, "newRDPClientEngine(addr, user, h.RDPPassword, width, height, rdpKeyboardLayoutCode(layout))") {
		t.Fatalf("AppService RDP path should use factory")
	}
}

type fakeRDPEngineControl struct {
	calls []string
}

func (f *fakeRDPEngineControl) Login() error                   { f.calls = append(f.calls, "login"); return nil }
func (f *fakeRDPEngineControl) Close()                         { f.calls = append(f.calls, "close") }
func (f *fakeRDPEngineControl) OnReady(func())                 {}
func (f *fakeRDPEngineControl) OnSuccess(func())               {}
func (f *fakeRDPEngineControl) OnClose(func())                 {}
func (f *fakeRDPEngineControl) OnError(func(error))            {}
func (f *fakeRDPEngineControl) OnBitmap(func([]client.Bitmap)) {}
func (f *fakeRDPEngineControl) MouseMove(x, y int) {
	f.calls = append(f.calls, fmt.Sprintf("move:%d:%d", x, y))
}
func (f *fakeRDPEngineControl) MouseDown(button, x, y int) {
	f.calls = append(f.calls, fmt.Sprintf("down:%d:%d:%d", button, x, y))
}
func (f *fakeRDPEngineControl) MouseUp(button, x, y int) {
	f.calls = append(f.calls, fmt.Sprintf("up:%d:%d:%d", button, x, y))
}
func (f *fakeRDPEngineControl) MouseWheel(delta, x, y int) {
	f.calls = append(f.calls, fmt.Sprintf("wheel:%d:%d:%d", delta, x, y))
}
func (f *fakeRDPEngineControl) KeyDown(scancode int, code string) {
	f.calls = append(f.calls, fmt.Sprintf("keydown:%d:%s", scancode, code))
}
func (f *fakeRDPEngineControl) KeyUp(scancode int, code string) {
	f.calls = append(f.calls, fmt.Sprintf("keyup:%d:%s", scancode, code))
}
func (f *fakeRDPEngineControl) TypeText(text string) {
	f.calls = append(f.calls, "type:"+text)
}
func (f *fakeRDPEngineControl) SetClipboardTextProvider(func() string)                        {}
func (f *fakeRDPEngineControl) SetClipboardFileProvider(func() []plugin.ClipboardFile)        {}
func (f *fakeRDPEngineControl) SetClipboardFileServedCallback(func(index int, complete bool)) {}
func (f *fakeRDPEngineControl) RefreshClipboard()                                             { f.calls = append(f.calls, "refresh-clipboard") }
func (f *fakeRDPEngineControl) SetAudioSink(func(plugin.RDPSNDAudioChunk))                    {}

func TestRDPControlPlaneUsesScancodeKeyboardAndMouseWheelInput(t *testing.T) {
	body, err := os.ReadFile("third_party/grdp/client/rdp.go")
	if err != nil {
		t.Fatalf("read grdp rdp.go: %v", err)
	}
	src := string(body)
	keyUp := src[strings.Index(src, "func (c *RdpClient) KeyUp"):strings.Index(src, "func (c *RdpClient) KeyDown")]
	if !strings.Contains(keyUp, "pdu.INPUT_EVENT_SCANCODE") || strings.Contains(keyUp, "pdu.INPUT_EVENT_MOUSE") {
		t.Fatalf("KeyUp must send INPUT_EVENT_SCANCODE, not mouse: %s", keyUp)
	}
	wheel := src[strings.Index(src, "func (c *RdpClient) MouseWheel"):strings.Index(src, "func (c *RdpClient) MouseUp")]
	if !strings.Contains(wheel, "pdu.INPUT_EVENT_MOUSE") || strings.Contains(wheel, "pdu.INPUT_EVENT_SCANCODE") {
		t.Fatalf("MouseWheel must send INPUT_EVENT_MOUSE, not scancode: %s", wheel)
	}
	if !strings.Contains(wheel, "scroll & 0xff") || !strings.Contains(wheel, "PTRFLAGS_WHEEL_NEGATIVE") {
		t.Fatalf("MouseWheel must encode wheel delta into PointerFlags including negative direction: %s", wheel)
	}
}

func TestRDPInputControlPlaneDispatchesThroughEngine(t *testing.T) {
	svc := NewAppService()
	fake := &fakeRDPEngineControl{}
	svc.rdps["rdp-input"] = &rdpRec{client: fake, closed: make(chan struct{})}
	if err := svc.RDPMouse("rdp-input", "move", -4, -9, 0); err != nil {
		t.Fatalf("RDPMouse move: %v", err)
	}
	if err := svc.RDPMouse("rdp-input", "leftdown", 10, 11, 0); err != nil {
		t.Fatalf("RDPMouse leftdown: %v", err)
	}
	if err := svc.RDPMouse("rdp-input", "wheel", 12, 13, 120); err != nil {
		t.Fatalf("RDPMouse wheel: %v", err)
	}
	if err := svc.RDPKey("rdp-input", "KeyA", true); err != nil {
		t.Fatalf("RDPKey down: %v", err)
	}
	if err := svc.RDPKey("rdp-input", "KeyA", false); err != nil {
		t.Fatalf("RDPKey up: %v", err)
	}
	if err := svc.RDPTypeText("rdp-input", "hi"); err != nil {
		t.Fatalf("RDPTypeText: %v", err)
	}
	want := []string{"move:0:0", "down:0:10:11", "wheel:120:12:13", "keydown:30:KeyA", "keyup:30:KeyA", "type:hi"}
	if strings.Join(fake.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("engine calls = %#v, want %#v", fake.calls, want)
	}
}

func TestRDPCleanupClosesEngineControlOnce(t *testing.T) {
	svc := NewAppService()
	fake := &fakeRDPEngineControl{}
	svc.rdps["rdp-close"] = &rdpRec{client: fake, closed: make(chan struct{})}
	if err := svc.CloseRDP("rdp-close"); err != nil {
		t.Fatalf("CloseRDP: %v", err)
	}
	if err := svc.CloseRDP("rdp-close"); err != nil {
		t.Fatalf("CloseRDP second call: %v", err)
	}
	if strings.Join(fake.calls, "|") != "close" {
		t.Fatalf("engine close calls = %#v, want one close", fake.calls)
	}
}

func TestRDPStageClipboardFilesStoresCleanDecodedFiles(t *testing.T) {
	svc := NewAppService()
	id := "rdp-files"
	svc.rdps[id] = &rdpRec{client: &fakeRDPEngineControl{}, closed: make(chan struct{})}
	if err := svc.RDPStageClipboardFiles(id, []RDPClipboardFileUpload{{Name: `folder/sub/demo.txt`, Base64: "SGVsbG8="}}); err != nil {
		t.Fatalf("RDPStageClipboardFiles: %v", err)
	}
	r := svc.rdps[id]
	r.clipMu.Lock()
	defer r.clipMu.Unlock()
	if len(r.clipFiles) != 1 || r.clipFiles[0].Name != "folder/sub/demo.txt" || string(r.clipFiles[0].Data) != "Hello" {
		t.Fatalf("staged files = %#v", r.clipFiles)
	}
	if r.clipDone == nil || len(r.clipDone) != 0 {
		t.Fatalf("staged files should initialize one-shot tracking, got %#v", r.clipDone)
	}
}

func TestRDPStageClipboardFilesRejectsUnsafeRelativePaths(t *testing.T) {
	svc := NewAppService()
	svc.rdps["s"] = &rdpRec{client: &fakeRDPEngineControl{}, closed: make(chan struct{})}
	for _, name := range []string{"../bad.txt", "folder/../../bad.txt", "/absolute.txt", `C:	mp\bad.txt`, `\\server\share\bad.txt`, "folder/.hidden/../bad.txt"} {
		if err := svc.RDPStageClipboardFiles("s", []RDPClipboardFileUpload{{Name: name, Base64: "QQ=="}}); err == nil {
			t.Fatalf("unsafe name accepted: %q", name)
		}
	}
}

func TestRDPFileClipboardIsClearedAfterRemoteConsumesAllFiles(t *testing.T) {
	body, err := os.ReadFile("rdp.go")
	if err != nil {
		t.Fatalf("read rdp.go: %v", err)
	}
	src := string(body)
	for _, want := range []string{"SetClipboardFileServedCallback", "r.clipDone[index] = true", "clear = len(r.clipDone) >= len(r.clipFiles)", "r.clipFiles = nil", "r.client.RefreshClipboard()"} {
		if !strings.Contains(src, want) {
			t.Fatalf("missing one-shot file clipboard cleanup fragment %q", want)
		}
	}
}

func TestRDPStageClipboardFilesRejectsBadSessionAndTooLargePayload(t *testing.T) {
	svc := NewAppService()
	if err := svc.RDPStageClipboardFiles("missing", []RDPClipboardFileUpload{{Name: "a.txt", Base64: "QQ=="}}); err == nil {
		t.Fatalf("missing session accepted")
	}
	svc.rdps["s"] = &rdpRec{client: &fakeRDPEngineControl{}, closed: make(chan struct{})}
	if err := svc.RDPStageClipboardFiles("s", []RDPClipboardFileUpload{{Name: "../bad", Base64: "***"}}); err == nil {
		t.Fatalf("bad base64 accepted")
	}
}

func TestRDPInputDoesNotShareFramebufferMutex(t *testing.T) {
	body, err := os.ReadFile("rdp.go")
	if err != nil {
		t.Fatalf("read rdp.go: %v", err)
	}
	src := string(body)
	for _, fn := range []string{"func (s *AppService) RDPMouse", "func (s *AppService) RDPKey", "func (s *AppService) RDPTypeText"} {
		idx := strings.Index(src, fn)
		if idx < 0 {
			t.Fatalf("missing %s", fn)
		}
		end := strings.Index(src[idx+len(fn):], "\nfunc ")
		block := src[idx:]
		if end >= 0 {
			block = src[idx : idx+len(fn)+end]
		}
		if !strings.Contains(block, "r.inputMu.Lock()") {
			t.Fatalf("%s must use inputMu instead of framebuffer mu", fn)
		}
		if strings.Contains(block, "r.mu.Lock()") {
			t.Fatalf("%s still uses framebuffer mutex for input", fn)
		}
	}
}

func TestRDPCallbacksRegisteredBeforeLogin(t *testing.T) {
	body, err := os.ReadFile("rdp.go")
	if err != nil {
		t.Fatalf("read rdp.go: %v", err)
	}
	src := string(body)
	bitmap := strings.Index(src, "cli.OnBitmap(func")
	login := strings.Index(src, "if err := cli.Login(); err != nil")
	if bitmap < 0 || login < 0 {
		t.Fatalf("missing RDP callback/login wiring")
	}
	if bitmap > login {
		t.Fatalf("RDP bitmap callback is registered after Login; initial frames can be lost")
	}
}

func TestReadHostsRawGivesStableIDForInvalidJSONID(t *testing.T) {
	withTempConfig(t)
	svc := NewAppService()
	p, err := hostsPath()
	if err != nil {
		t.Fatalf("hostsPath: %v", err)
	}
	raw := `[{"id":"qa134-rdp","protocol":"rdp","name":"ADC RDP QA 134","address":"192.0.2.115","port":22,"username":"qa-user","authMode":"agent","rdpEnabled":true,"rdpPort":3389,"rdpUsername":"qa-user","rdpPassword":"qa-user","rdpScaleMode":"fit"}]`
	if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
		t.Fatalf("write hosts: %v", err)
	}
	first, err := svc.readHostsRaw()
	if err != nil || len(first) != 1 {
		t.Fatalf("first read = %#v err=%v", first, err)
	}
	second, err := svc.readHostsRaw()
	if err != nil || len(second) != 1 {
		t.Fatalf("second read = %#v err=%v", second, err)
	}
	if !validUUID(first[0].ID) || first[0].ID != second[0].ID {
		t.Fatalf("normalized IDs not stable: first=%q second=%q", first[0].ID, second[0].ID)
	}
}

func TestSaveRDPHostPersistsScaleMode(t *testing.T) {
	withTempConfig(t)
	svc := NewAppService()
	hosts, err := svc.SaveHost(HostConfig{Protocol: "rdp", Name: "scale", Address: "192.0.2.115", RDPUsername: "qa-user", RDPScaleMode: "fit"})
	if err != nil {
		t.Fatalf("SaveHost: %v", err)
	}
	if len(hosts) != 1 || hosts[0].RDPScaleMode != "fit" {
		t.Fatalf("rdp scale not persisted: %#v", hosts)
	}
	hosts, err = svc.SaveHost(HostConfig{ID: hosts[0].ID, Protocol: "rdp", Name: "scale", Address: "192.0.2.115", RDPUsername: "qa-user", RDPScaleMode: "invalid"})
	if err != nil {
		t.Fatalf("SaveHost invalid mode: %v", err)
	}
	if hosts[0].RDPScaleMode != "smart" {
		t.Fatalf("invalid rdp scale not normalized to smart: %#v", hosts[0])
	}
}

func TestConnectRDPRejectsNonRDPHost(t *testing.T) {
	withTempConfig(t)
	svc := NewAppService()
	unlockTestVault(t, svc)
	hosts, err := svc.SaveHost(HostConfig{Name: "ssh-only", Address: "127.0.0.1", Port: 22, Username: "me", AuthMode: "agent"})
	if err != nil {
		t.Fatalf("SaveHost: %v", err)
	}
	_, err = svc.ConnectRDP(hosts[0].ID, 1024, 768)
	if err == nil || !strings.Contains(err.Error(), "RDP") {
		t.Fatalf("ConnectRDP error = %v, want RDP-specific rejection", err)
	}
}
