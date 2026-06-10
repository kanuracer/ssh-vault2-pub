package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tomatome/grdp/client"
	"github.com/tomatome/grdp/plugin"
)

type RDPClipboardFileUpload struct {
	Name        string `json:"name"`
	Base64      string `json:"base64"`
	IsDirectory bool   `json:"isDirectory,omitempty"`
}

const (
	rdpDirtyFullAreaThresholdNumerator   = 1
	rdpDirtyFullAreaThresholdDenominator = 3
	rdpFullKeyframeInterval              = time.Second
)

type rdpRec struct {
	state              SessionState
	client             rdpEngineControl
	width              int
	height             int
	closeOnce          sync.Once
	closed             chan struct{}
	mu                 sync.Mutex
	inputMu            sync.Mutex
	clipMu             sync.Mutex
	clipTextSet        bool
	clipText           string
	clipFiles          []plugin.ClipboardFile
	clipDone           map[int]bool
	seq                int
	fb                 []byte
	fbWidth            int
	fbHeight           int
	fbDirty            bool
	dirtyLeft          int
	dirtyTop           int
	dirtyRight         int
	dirtyBottom        int
	pendingBitmapRects int
	lastFullAt         time.Time
	renderWake         chan struct{}
	stats              rdpDiagnosticsCounters
	keyboardLayout     string
}

type rdpDiagnosticsCounters struct {
	bitmapUpdates     uint64
	compressedUpdates uint64
	bytesApplied      uint64
	dirtyFrames       uint64
	fullFrames        uint64
	lastFrameAt       int64
	lastPixelFormat   string
	colorDepths       map[int]uint64
}

type RDPDiagnostics struct {
	SessionID         string            `json:"sessionId"`
	BitmapUpdates     uint64            `json:"bitmapUpdates"`
	CompressedUpdates uint64            `json:"compressedUpdates"`
	BytesApplied      uint64            `json:"bytesApplied"`
	DirtyFrames       uint64            `json:"dirtyFrames"`
	FullFrames        uint64            `json:"fullFrames"`
	LastFrameAt       int64             `json:"lastFrameAt"`
	LastPixelFormat   string            `json:"lastPixelFormat"`
	ColorDepths       map[string]uint64 `json:"colorDepths"`
}

func rdpDialAddress(h HostConfig) (string, error) {
	addr := strings.TrimSpace(h.Address)
	if addr == "" {
		return "", fmt.Errorf("Adresse fehlt")
	}
	port := h.RDPPort
	if port == 0 {
		port = 3389
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("ungültiger RDP-Port: %d", port)
	}
	return net.JoinHostPort(addr, strconv.Itoa(port)), nil
}

func rdpUsername(h HostConfig) string {
	u := strings.TrimSpace(h.RDPUsername)
	if u == "" {
		u = strings.TrimSpace(h.Username)
	}
	if d := strings.TrimSpace(h.RDPDomain); d != "" && !strings.Contains(u, `\\`) && !strings.Contains(u, "@") {
		return d + `\\` + u
	}
	return u
}

func (s *AppService) emitRDPStatus(st SessionState) {
	if s.app != nil {
		s.app.Event.Emit(rdpStatusEvent, st)
	}
}

func (s *AppService) ConnectRDP(hostID string, width int, height int) (SessionState, error) {
	h, err := s.hostByID(hostID)
	if err != nil {
		return SessionState{}, err
	}
	if !h.RDPEnabled {
		return SessionState{}, fmt.Errorf("RDP ist für diesen Host nicht aktiviert")
	}
	if width < 640 {
		width = h.RDPWidth
	}
	if height < 480 {
		height = h.RDPHeight
	}
	if width < 640 {
		width = 1280
	}
	if height < 480 {
		height = 720
	}
	addr, err := rdpDialAddress(h)
	if err != nil {
		return SessionState{}, err
	}
	user := rdpUsername(h)
	if strings.TrimSpace(user) == "" {
		return SessionState{}, fmt.Errorf("RDP-Benutzer fehlt")
	}
	if strings.TrimSpace(h.RDPPassword) == "" {
		return SessionState{}, fmt.Errorf("RDP-Passwort fehlt")
	}
	id := uuid.NewString()
	st := SessionState{ID: id, HostID: h.ID, Title: h.Name + " RDP", Status: "connecting", StartedAt: time.Now().UnixMilli()}
	layout := normalizeRDPKeyboardLayout(h.RDPKeyboardLayout)
	cli := newRDPClientEngine(addr, user, h.RDPPassword, width, height, rdpKeyboardLayoutCode(layout))
	r := &rdpRec{state: st, client: cli, width: width, height: height, closed: make(chan struct{}), renderWake: make(chan struct{}, 1), keyboardLayout: layout}
	cli.SetClipboardTextProvider(func() string {
		r.clipMu.Lock()
		if r.clipTextSet {
			text := r.clipText
			r.clipMu.Unlock()
			return text
		}
		r.clipMu.Unlock()
		text, err := s.RDPClipboardText()
		if err != nil {
			return ""
		}
		return text
	})
	cli.SetClipboardFileProvider(func() []plugin.ClipboardFile {
		r.clipMu.Lock()
		defer r.clipMu.Unlock()
		out := make([]plugin.ClipboardFile, 0, len(r.clipFiles))
		for _, f := range r.clipFiles {
			out = append(out, plugin.ClipboardFile{Name: f.Name, Data: append([]byte(nil), f.Data...), IsDirectory: f.IsDirectory})
		}
		return out
	})
	cli.SetClipboardFileServedCallback(func(index int, complete bool) {
		if !complete {
			return
		}
		clear := false
		r.clipMu.Lock()
		if index >= 0 && index < len(r.clipFiles) {
			if r.clipDone == nil {
				r.clipDone = make(map[int]bool, len(r.clipFiles))
			}
			r.clipDone[index] = true
			clear = len(r.clipDone) >= len(r.clipFiles)
		}
		if clear {
			r.clipFiles = nil
			r.clipDone = nil
			r.clipTextSet = false
			r.clipText = ""
		}
		r.clipMu.Unlock()
		if clear {
			r.client.RefreshClipboard()
		}
	})
	cli.SetAudioSink(func(chunk plugin.RDPSNDAudioChunk) {
		if s.app != nil {
			s.app.Event.Emit("rdp:audio", map[string]any{
				"sessionID":     id,
				"channels":      chunk.Channels,
				"sampleRate":    chunk.SampleRate,
				"bitsPerSample": chunk.BitsPerSample,
				"base64":        chunk.Base64,
			})
		}
	})
	s.mu.Lock()
	s.rdps[id] = r
	s.mu.Unlock()
	go s.runRDPRenderPump(r)
	s.emitRDPStatus(st)

	go func() {
		markConnected := func(status string) {
			st.Status = status
			s.mu.Lock()
			if rr := s.rdps[id]; rr != nil {
				rr.state = st
			}
			s.mu.Unlock()
			s.emitRDPStatus(st)
		}
		cli.OnReady(func() { markConnected("connected") })
		cli.OnSuccess(func() { markConnected("connected") })
		cli.OnClose(func() { _ = s.cleanupRDP(id, true) })
		cli.OnError(func(e error) {
			appLog("RDP runtime error session=%s: %v", id, e)
			st.Status = "error"
			if e != nil {
				st.Error = e.Error()
			}
			s.emitRDPStatus(st)
			_ = s.cleanupRDP(id, true)
		})
		cli.OnBitmap(func(bitmaps []client.Bitmap) {
			if err := s.rdpApplyBitmaps(id, bitmaps); err != nil {
				appLog("RDP bitmap apply error session=%s: %v", id, err)
				return
			}
			r.signalRender()
		})
		if err := cli.Login(); err != nil {
			appLog("RDP login error session=%s target=%s: %v", id, addr, err)
			_ = s.cleanupRDP(id, false)
			st.Status = "error"
			st.Error = err.Error()
			s.emitRDPStatus(st)
			return
		}
		markConnected("connected")
	}()
	return st, nil
}

func (r *rdpRec) signalRender() {
	if r == nil || r.renderWake == nil {
		return
	}
	select {
	case r.renderWake <- struct{}{}:
	default:
	}
}

func (r *rdpRec) markDirtyLocked(left, top, right, bottom int) {
	if r == nil || r.fbWidth <= 0 || r.fbHeight <= 0 {
		return
	}
	if left < 0 {
		left = 0
	}
	if top < 0 {
		top = 0
	}
	if right > r.fbWidth {
		right = r.fbWidth
	}
	if bottom > r.fbHeight {
		bottom = r.fbHeight
	}
	if right <= left || bottom <= top {
		return
	}
	if !r.fbDirty {
		r.fbDirty = true
		r.dirtyLeft = left
		r.dirtyTop = top
		r.dirtyRight = right
		r.dirtyBottom = bottom
		return
	}
	if left < r.dirtyLeft {
		r.dirtyLeft = left
	}
	if top < r.dirtyTop {
		r.dirtyTop = top
	}
	if right > r.dirtyRight {
		r.dirtyRight = right
	}
	if bottom > r.dirtyBottom {
		r.dirtyBottom = bottom
	}
}

func (r *rdpRec) markDirty(left, top, right, bottom int) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.markDirtyLocked(left, top, right, bottom)
}

func rdpBitmapColorDepth(bm client.Bitmap) int {
	if bm.ColorDepth > 0 {
		return bm.ColorDepth
	}
	switch bm.BitsPerPixel {
	case 2:
		return 16
	case 3:
		return 24
	case 4:
		return 32
	default:
		return bm.BitsPerPixel * 8
	}
}

func rdpPixelFormatName(bytesPerPixel, colorDepth int) string {
	switch {
	case bytesPerPixel == 2 && colorDepth == 15:
		return "rgb555-15bpp"
	case bytesPerPixel == 2:
		return "rgb565-16bpp"
	case bytesPerPixel == 3:
		return "bgr24"
	case bytesPerPixel == 4:
		return "bgra32"
	default:
		return fmt.Sprintf("%dbpp/%d-byte", colorDepth, bytesPerPixel)
	}
}

func (r *rdpRec) recordBitmapStatsLocked(bm client.Bitmap, rgbaBytes int) {
	if r == nil {
		return
	}
	depth := rdpBitmapColorDepth(bm)
	r.stats.bitmapUpdates++
	if bm.IsCompress {
		r.stats.compressedUpdates++
	}
	r.stats.bytesApplied += uint64(rgbaBytes)
	r.stats.lastPixelFormat = rdpPixelFormatName(bm.BitsPerPixel, depth)
	if r.stats.colorDepths == nil {
		r.stats.colorDepths = map[int]uint64{}
	}
	r.stats.colorDepths[depth]++
}

func (r *rdpRec) recordFrameStatsLocked(full bool, at time.Time) {
	if r == nil {
		return
	}
	if full {
		r.stats.fullFrames++
	} else {
		r.stats.dirtyFrames++
	}
	if !at.IsZero() {
		r.stats.lastFrameAt = at.UnixMilli()
	}
}

func (s *AppService) RDPDiagnostics(id string) (RDPDiagnostics, error) {
	s.mu.Lock()
	r := s.rdps[id]
	s.mu.Unlock()
	if r == nil {
		return RDPDiagnostics{}, fmt.Errorf("RDP-Session nicht gefunden")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := RDPDiagnostics{
		SessionID:         id,
		BitmapUpdates:     r.stats.bitmapUpdates,
		CompressedUpdates: r.stats.compressedUpdates,
		BytesApplied:      r.stats.bytesApplied,
		DirtyFrames:       r.stats.dirtyFrames,
		FullFrames:        r.stats.fullFrames,
		LastFrameAt:       r.stats.lastFrameAt,
		LastPixelFormat:   r.stats.lastPixelFormat,
		ColorDepths:       map[string]uint64{},
	}
	for depth, count := range r.stats.colorDepths {
		out.ColorDepths[strconv.Itoa(depth)] = count
	}
	return out, nil
}

func (s *AppService) runRDPRenderPump(r *rdpRec) {
	if s == nil || r == nil {
		return
	}
	ticker := time.NewTicker(time.Second / 60)
	defer ticker.Stop()
	pending := false
	for {
		select {
		case <-r.closed:
			return
		case <-r.renderWake:
			pending = true
		case <-ticker.C:
			if !pending {
				continue
			}
			frame, ok := r.rdpAdaptiveSnapshot(time.Now())
			if ok && s.render != nil {
				_ = s.render.Publish(frame)
			}
			pending = false
		}
	}
}

func (r *rdpRec) rdpAdaptiveSnapshot(now time.Time) (RDPRenderFrame, bool) {
	if r == nil {
		return RDPRenderFrame{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.fbDirty || r.fbWidth <= 0 || r.fbHeight <= 0 || len(r.fb) != r.fbWidth*r.fbHeight*4 {
		return RDPRenderFrame{}, false
	}
	left, top := r.dirtyLeft, r.dirtyTop
	right, bottom := r.dirtyRight, r.dirtyBottom
	if left < 0 {
		left = 0
	}
	if top < 0 {
		top = 0
	}
	if right > r.fbWidth {
		right = r.fbWidth
	}
	if bottom > r.fbHeight {
		bottom = r.fbHeight
	}
	if right <= left || bottom <= top {
		r.fbDirty = false
		r.dirtyLeft, r.dirtyTop, r.dirtyRight, r.dirtyBottom = 0, 0, 0, 0
		return RDPRenderFrame{}, false
	}
	dirtyW, dirtyH := right-left, bottom-top
	surfaceArea := r.fbWidth * r.fbHeight
	dirtyArea := dirtyW * dirtyH
	forceFull := dirtyArea*rdpDirtyFullAreaThresholdDenominator > surfaceArea*rdpDirtyFullAreaThresholdNumerator
	if !forceFull && r.pendingBitmapRects >= 4 && dirtyArea*16 >= surfaceArea {
		forceFull = true
	}
	if !forceFull && !r.lastFullAt.IsZero() && now.Sub(r.lastFullAt) >= rdpFullKeyframeInterval {
		forceFull = true
	}
	r.fbDirty = false
	r.dirtyLeft, r.dirtyTop, r.dirtyRight, r.dirtyBottom = 0, 0, 0, 0
	r.pendingBitmapRects = 0
	r.seq++
	if forceFull {
		r.lastFullAt = now
		r.recordFrameStatsLocked(true, now)
		out := append([]byte(nil), r.fb...)
		return RDPRenderFrame{SessionID: r.state.ID, Seq: uint64(r.seq), Left: 0, Top: 0, Width: r.fbWidth, Height: r.fbHeight, SurfaceWidth: r.fbWidth, SurfaceHeight: r.fbHeight, Stride: r.fbWidth * 4, RGBA: out}, true
	}
	out := make([]byte, dirtyW*dirtyH*4)
	for y := 0; y < dirtyH; y++ {
		src := ((top+y)*r.fbWidth + left) * 4
		dst := y * dirtyW * 4
		copy(out[dst:dst+dirtyW*4], r.fb[src:src+dirtyW*4])
	}
	r.recordFrameStatsLocked(false, now)
	return RDPRenderFrame{SessionID: r.state.ID, Seq: uint64(r.seq), Left: left, Top: top, Width: dirtyW, Height: dirtyH, SurfaceWidth: r.fbWidth, SurfaceHeight: r.fbHeight, Stride: dirtyW * 4, RGBA: out}, true
}

func (s *AppService) RDPRenderEndpoint(id string) (RDPRenderEndpoint, error) {
	s.mu.Lock()
	r := s.rdps[id]
	s.mu.Unlock()
	if r == nil {
		return RDPRenderEndpoint{}, fmt.Errorf("RDP-Session nicht gefunden")
	}
	endpoint, err := s.render.Register(id, r.width, r.height)
	if err != nil {
		return RDPRenderEndpoint{}, err
	}
	if snap, ok := r.rdpFullSnapshot(); ok {
		s.render.Publish(snap)
	}
	return endpoint, nil
}

func (s *AppService) rdpBitmapToRenderFrame(id string, bm client.Bitmap) (RDPRenderFrame, error) {
	return s.rdpBitmapsToRenderFrame(id, []client.Bitmap{bm})
}

func (s *AppService) rdpApplyBitmaps(id string, bitmaps []client.Bitmap) error {
	if len(bitmaps) == 0 {
		return fmt.Errorf("keine RDP-Bitmaps empfangen")
	}
	s.mu.Lock()
	r := s.rdps[id]
	s.mu.Unlock()
	if r == nil {
		return fmt.Errorf("RDP-Session nicht gefunden")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.width <= 0 || r.height <= 0 {
		r.width = 1280
		r.height = 720
	}
	if r.fbWidth != r.width || r.fbHeight != r.height || len(r.fb) != r.width*r.height*4 {
		r.fbWidth = r.width
		r.fbHeight = r.height
		r.fb = make([]byte, r.fbWidth*r.fbHeight*4)
	}
	for _, bm := range bitmaps {
		rgba, err := rdpBitmapRGBA(bm)
		if err != nil {
			return err
		}
		r.recordBitmapStatsLocked(bm, len(rgba))
		r.pendingBitmapRects++
		rectW, rectH := rdpBitmapRectSize(bm)
		if rectW <= 0 || rectH <= 0 {
			return fmt.Errorf("ungültiges RDP-Bitmaprechteck %dx%d", rectW, rectH)
		}
		if rectW != bm.Width || rectH != bm.Height {
			return fmt.Errorf("RDP-Bitmaprechteck passt nicht zu Daten: rect=%dx%d data=%dx%d", rectW, rectH, bm.Width, bm.Height)
		}
		if bm.DestLeft < 0 || bm.DestTop < 0 || bm.DestLeft+rectW > r.fbWidth || bm.DestTop+rectH > r.fbHeight {
			return fmt.Errorf("RDP-Bitmap außerhalb der Oberfläche: %d,%d %dx%d auf %dx%d", bm.DestLeft, bm.DestTop, rectW, rectH, r.fbWidth, r.fbHeight)
		}
		for y := 0; y < rectH; y++ {
			src := y * rectW * 4
			dst := ((bm.DestTop+y)*r.fbWidth + bm.DestLeft) * 4
			copy(r.fb[dst:dst+rectW*4], rgba[src:src+rectW*4])
		}
		r.markDirtyLocked(bm.DestLeft, bm.DestTop, bm.DestLeft+rectW, bm.DestTop+rectH)
	}
	return nil
}

func (s *AppService) rdpBitmapsToRenderFrame(id string, bitmaps []client.Bitmap) (RDPRenderFrame, error) {
	if len(bitmaps) == 0 {
		return RDPRenderFrame{}, fmt.Errorf("keine RDP-Bitmaps empfangen")
	}
	s.mu.Lock()
	r := s.rdps[id]
	s.mu.Unlock()
	if r == nil {
		return RDPRenderFrame{}, fmt.Errorf("RDP-Session nicht gefunden")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.width <= 0 || r.height <= 0 {
		r.width = 1280
		r.height = 720
	}
	if r.fbWidth != r.width || r.fbHeight != r.height || len(r.fb) != r.width*r.height*4 {
		r.fbWidth = r.width
		r.fbHeight = r.height
		r.fb = make([]byte, r.fbWidth*r.fbHeight*4)
	}
	dirtyLeft, dirtyTop := r.fbWidth, r.fbHeight
	dirtyRight, dirtyBottom := -1, -1
	for _, bm := range bitmaps {
		rgba, err := rdpBitmapRGBA(bm)
		if err != nil {
			return RDPRenderFrame{}, err
		}
		rectW, rectH := rdpBitmapRectSize(bm)
		if rectW <= 0 || rectH <= 0 {
			return RDPRenderFrame{}, fmt.Errorf("ungültiges RDP-Bitmaprechteck %dx%d", rectW, rectH)
		}
		if rectW != bm.Width || rectH != bm.Height {
			return RDPRenderFrame{}, fmt.Errorf("RDP-Bitmaprechteck passt nicht zu Daten: rect=%dx%d data=%dx%d", rectW, rectH, bm.Width, bm.Height)
		}
		if bm.DestLeft < 0 || bm.DestTop < 0 || bm.DestLeft+rectW > r.fbWidth || bm.DestTop+rectH > r.fbHeight {
			return RDPRenderFrame{}, fmt.Errorf("RDP-Bitmap außerhalb der Oberfläche: %d,%d %dx%d auf %dx%d", bm.DestLeft, bm.DestTop, rectW, rectH, r.fbWidth, r.fbHeight)
		}
		for y := 0; y < rectH; y++ {
			src := y * rectW * 4
			dst := ((bm.DestTop+y)*r.fbWidth + bm.DestLeft) * 4
			copy(r.fb[dst:dst+rectW*4], rgba[src:src+rectW*4])
		}
		if bm.DestLeft < dirtyLeft {
			dirtyLeft = bm.DestLeft
		}
		if bm.DestTop < dirtyTop {
			dirtyTop = bm.DestTop
		}
		if right := bm.DestLeft + rectW; right > dirtyRight {
			dirtyRight = right
		}
		if bottom := bm.DestTop + rectH; bottom > dirtyBottom {
			dirtyBottom = bottom
		}
	}
	if dirtyRight <= dirtyLeft || dirtyBottom <= dirtyTop {
		return RDPRenderFrame{}, fmt.Errorf("keine gültige RDP-Dirty-Region")
	}
	dirtyW := dirtyRight - dirtyLeft
	dirtyH := dirtyBottom - dirtyTop
	out := make([]byte, dirtyW*dirtyH*4)
	for y := 0; y < dirtyH; y++ {
		src := ((dirtyTop+y)*r.fbWidth + dirtyLeft) * 4
		dst := y * dirtyW * 4
		copy(out[dst:dst+dirtyW*4], r.fb[src:src+dirtyW*4])
	}
	r.seq++
	return RDPRenderFrame{SessionID: id, Seq: uint64(r.seq), Left: dirtyLeft, Top: dirtyTop, Width: dirtyW, Height: dirtyH, SurfaceWidth: r.fbWidth, SurfaceHeight: r.fbHeight, Stride: dirtyW * 4, RGBA: out}, nil
}

func (r *rdpRec) rdpDirtySnapshot() (RDPRenderFrame, bool) {
	if r == nil {
		return RDPRenderFrame{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.fbDirty || r.fbWidth <= 0 || r.fbHeight <= 0 || len(r.fb) != r.fbWidth*r.fbHeight*4 {
		return RDPRenderFrame{}, false
	}
	left, top := r.dirtyLeft, r.dirtyTop
	right, bottom := r.dirtyRight, r.dirtyBottom
	if left < 0 {
		left = 0
	}
	if top < 0 {
		top = 0
	}
	if right > r.fbWidth {
		right = r.fbWidth
	}
	if bottom > r.fbHeight {
		bottom = r.fbHeight
	}
	r.fbDirty = false
	r.dirtyLeft, r.dirtyTop, r.dirtyRight, r.dirtyBottom = 0, 0, 0, 0
	if right <= left || bottom <= top {
		return RDPRenderFrame{}, false
	}
	dirtyW := right - left
	dirtyH := bottom - top
	out := make([]byte, dirtyW*dirtyH*4)
	for y := 0; y < dirtyH; y++ {
		src := ((top+y)*r.fbWidth + left) * 4
		dst := y * dirtyW * 4
		copy(out[dst:dst+dirtyW*4], r.fb[src:src+dirtyW*4])
	}
	r.seq++
	return RDPRenderFrame{SessionID: r.state.ID, Seq: uint64(r.seq), Left: left, Top: top, Width: dirtyW, Height: dirtyH, SurfaceWidth: r.fbWidth, SurfaceHeight: r.fbHeight, Stride: dirtyW * 4, RGBA: out}, true
}

func (r *rdpRec) rdpFullSnapshot() (RDPRenderFrame, bool) {
	if r == nil {
		return RDPRenderFrame{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fbWidth <= 0 || r.fbHeight <= 0 || len(r.fb) != r.fbWidth*r.fbHeight*4 {
		return RDPRenderFrame{}, false
	}
	r.seq++
	now := time.Now()
	r.lastFullAt = now
	r.recordFrameStatsLocked(true, now)
	out := append([]byte(nil), r.fb...)
	return RDPRenderFrame{SessionID: r.state.ID, Seq: uint64(r.seq), Left: 0, Top: 0, Width: r.fbWidth, Height: r.fbHeight, SurfaceWidth: r.fbWidth, SurfaceHeight: r.fbHeight, Stride: r.fbWidth * 4, RGBA: out}, true
}

func rdpBitmapRectSize(bm client.Bitmap) (int, int) {
	if bm.DestRight == 0 && bm.DestBottom == 0 && (bm.Width > 1 || bm.Height > 1) {
		return bm.Width, bm.Height
	}
	w := bm.DestRight - bm.DestLeft + 1
	h := bm.DestBottom - bm.DestTop + 1
	if w <= 0 || h <= 0 {
		return bm.Width, bm.Height
	}
	return w, h
}

func rdpBitmapRGBA(bm client.Bitmap) ([]byte, error) {
	if bm.Width <= 0 || bm.Height <= 0 {
		return nil, fmt.Errorf("ungültige RDP-Bitmapgröße %dx%d", bm.Width, bm.Height)
	}
	pixel := bm.BitsPerPixel
	colorDepth := rdpBitmapColorDepth(bm)
	if pixel <= 0 {
		return nil, fmt.Errorf("ungültige RDP-Pixeltiefe %d", bm.BitsPerPixel)
	}
	need := bm.Width * bm.Height * pixel
	if len(bm.Data) < need {
		return nil, fmt.Errorf("RDP-Bitmapdaten zu kurz: %d < %d", len(bm.Data), need)
	}
	if bm.BitsPerPixel == 4 && strings.EqualFold(strings.TrimSpace(bm.PixelFormat), "rgba32") {
		return append([]byte(nil), bm.Data[:need]...), nil
	}
	out := make([]byte, bm.Width*bm.Height*4)
	for src, dst := 0, 0; dst < len(out); src, dst = src+pixel, dst+4 {
		r, g, b := rdpPixelRGBWithDepth(pixel, colorDepth, bm.Data, src)
		out[dst] = r
		out[dst+1] = g
		out[dst+2] = b
		out[dst+3] = 255
	}
	return out, nil
}

func rdpPixelRGB(pixel int, data []byte, i int) (uint8, uint8, uint8) {
	return rdpPixelRGBWithDepth(pixel, 0, data, i)
}

func rdpPixelRGBWithDepth(pixel int, colorDepth int, data []byte, i int) (uint8, uint8, uint8) {
	switch pixel {
	case 2:
		v := uint16(data[i]) | uint16(data[i+1])<<8
		if colorDepth == 15 {
			r := uint8(((v >> 10) & 0x1f) * 255 / 31)
			g := uint8(((v >> 5) & 0x1f) * 255 / 31)
			b := uint8((v & 0x1f) * 255 / 31)
			return r, g, b
		}
		r := uint8(((v >> 11) & 0x1f) * 255 / 31)
		g := uint8(((v >> 5) & 0x3f) * 255 / 63)
		b := uint8((v & 0x1f) * 255 / 31)
		return r, g, b
	case 3, 4:
		return data[i+2], data[i+1], data[i]
	default:
		if i+2 < len(data) {
			return data[i+2], data[i+1], data[i]
		}
		return 0, 0, 0
	}
}

func (s *AppService) cleanupRDP(id string, emit bool) error {
	s.mu.Lock()
	r := s.rdps[id]
	delete(s.rdps, id)
	s.mu.Unlock()
	if s.render != nil {
		s.render.Unregister(id)
	}
	if r != nil {
		r.closeOnce.Do(func() {
			close(r.closed)
			if r.client != nil {
				r.client.Close()
			}
		})
		if emit {
			st := r.state
			st.Status = "closed"
			s.emitRDPStatus(st)
		}
	}
	return nil
}

func (s *AppService) CloseRDP(id string) error { return s.cleanupRDP(id, true) }

func (s *AppService) RDPMouse(id string, action string, x int, y int, delta int) error {
	s.mu.Lock()
	r := s.rdps[id]
	s.mu.Unlock()
	if r == nil || r.client == nil {
		return fmt.Errorf("RDP-Session nicht gefunden")
	}
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	r.inputMu.Lock()
	defer r.inputMu.Unlock()
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "move":
		r.client.MouseMove(x, y)
	case "leftdown":
		r.client.MouseDown(0, x, y)
	case "leftup":
		r.client.MouseUp(0, x, y)
	case "rightdown":
		r.client.MouseDown(2, x, y)
	case "rightup":
		r.client.MouseUp(2, x, y)
	case "wheel":
		if delta != 0 {
			r.client.MouseWheel(delta, x, y)
		}
	default:
		return fmt.Errorf("unbekannte RDP-Mausaktion: %s", action)
	}
	return nil
}

func (s *AppService) RDPClipboardText() (string, error) {
	if s == nil || s.app == nil || s.app.Clipboard == nil {
		return "", nil
	}
	text, ok := s.app.Clipboard.Text()
	if !ok {
		return "", nil
	}
	if len([]rune(text)) > 8192 {
		return "", fmt.Errorf("Clipboard-Text zu groß")
	}
	return text, nil
}

func (s *AppService) RDPKey(id string, code string, down bool) error {
	s.mu.Lock()
	r := s.rdps[id]
	s.mu.Unlock()
	if r == nil || r.client == nil {
		return fmt.Errorf("RDP-Session nicht gefunden")
	}
	scan, _, ok := browserCodeToRDPScancode(code)
	if !ok {
		return nil
	}
	r.inputMu.Lock()
	defer r.inputMu.Unlock()
	if down {
		r.client.KeyDown(int(scan), code)
	} else {
		r.client.KeyUp(int(scan), code)
	}
	return nil
}

func (s *AppService) RDPStageClipboardText(id string, text string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("RDP-Sitzung fehlt")
	}
	if len([]rune(text)) > 8192 {
		return fmt.Errorf("Clipboard-Text zu groß")
	}
	s.mu.Lock()
	r := s.rdps[id]
	s.mu.Unlock()
	if r == nil || r.client == nil {
		return fmt.Errorf("RDP-Sitzung nicht gefunden")
	}
	r.clipMu.Lock()
	r.clipTextSet = true
	r.clipText = text
	r.clipFiles = nil
	r.clipMu.Unlock()
	r.client.RefreshClipboard()
	return nil
}

func (s *AppService) RDPStageClipboardFiles(id string, files []RDPClipboardFileUpload) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("RDP-Sitzung fehlt")
	}
	if len(files) == 0 {
		return fmt.Errorf("keine Dateien")
	}
	if len(files) > 512 {
		return fmt.Errorf("zu viele Dateien (max. 512)")
	}
	s.mu.Lock()
	r := s.rdps[id]
	s.mu.Unlock()
	if r == nil {
		return fmt.Errorf("RDP-Sitzung nicht gefunden")
	}
	staged := make([]plugin.ClipboardFile, 0, len(files))
	var total int64
	for _, file := range files {
		name := cleanRDPClipboardFileName(file.Name)
		if name == "" {
			return fmt.Errorf("ungültiger Dateiname")
		}
		var data []byte
		if !file.IsDirectory {
			var err error
			data, err = base64.StdEncoding.DecodeString(file.Base64)
			if err != nil {
				return fmt.Errorf("Datei %s konnte nicht dekodiert werden", name)
			}
			total += int64(len(data))
			if total > 128*1024*1024 {
				return fmt.Errorf("RDP-Dateiablage zu groß (max. 128 MB)")
			}
		}
		staged = append(staged, plugin.ClipboardFile{Name: name, Data: data, IsDirectory: file.IsDirectory})
	}
	if err := plugin.ValidateClipboardFiles(staged, 512, 128*1024*1024); err != nil {
		return err
	}
	r.clipMu.Lock()
	r.clipTextSet = false
	r.clipText = ""
	r.clipFiles = staged
	r.clipDone = make(map[int]bool, len(staged))
	for i, f := range staged {
		if f.IsDirectory {
			r.clipDone[i] = true
		}
	}
	r.clipMu.Unlock()
	r.client.RefreshClipboard()
	return nil
}

func cleanRDPClipboardFileName(name string) string {
	name = strings.TrimSpace(strings.ReplaceAll(name, "\\", "/"))
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, ":") {
		return ""
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return ""
		}
	}
	cleaned := path.Clean(name)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "/../") {
		return ""
	}
	for _, part := range strings.Split(cleaned, "/") {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "<>:\"|?*") {
			return ""
		}
	}
	return cleaned
}

func (s *AppService) RDPTypeText(id string, text string) error {
	s.mu.Lock()
	r := s.rdps[id]
	s.mu.Unlock()
	if r == nil || r.client == nil {
		return fmt.Errorf("RDP-Session nicht gefunden")
	}
	if len([]rune(text)) > 8192 {
		return fmt.Errorf("RDP-Paste zu groß")
	}
	r.inputMu.Lock()
	defer r.inputMu.Unlock()
	r.client.TypeText(text)
	return nil
}

func normalizeRDPKeyboardLayout(layout string) string {
	switch strings.ToLower(strings.TrimSpace(layout)) {
	case "de", "de-de", "german", "deutsch", "0x00000407":
		return "de-DE"
	case "us", "en", "en-us", "english", "eng", "0x00000409":
		return "en-US"
	default:
		return "en-US"
	}
}

func rdpKeyboardLayoutCode(layout string) uint32 {
	switch normalizeRDPKeyboardLayout(layout) {
	case "de-DE":
		return 0x00000407
	default:
		return 0x00000409
	}
}

func browserCodeToRDPScancode(code string) (uint8, bool, bool) {
	if len(code) == 4 && strings.HasPrefix(code, "Key") {
		m := map[byte]uint8{'A': 0x1e, 'B': 0x30, 'C': 0x2e, 'D': 0x20, 'E': 0x12, 'F': 0x21, 'G': 0x22, 'H': 0x23, 'I': 0x17, 'J': 0x24, 'K': 0x25, 'L': 0x26, 'M': 0x32, 'N': 0x31, 'O': 0x18, 'P': 0x19, 'Q': 0x10, 'R': 0x13, 'S': 0x1f, 'T': 0x14, 'U': 0x16, 'V': 0x2f, 'W': 0x11, 'X': 0x2d, 'Y': 0x15, 'Z': 0x2c}
		v, ok := m[code[3]]
		return v, false, ok
	}
	m := map[string]struct {
		sc uint8
		ex bool
	}{
		"Digit1": {0x02, false}, "Digit2": {0x03, false}, "Digit3": {0x04, false}, "Digit4": {0x05, false}, "Digit5": {0x06, false}, "Digit6": {0x07, false}, "Digit7": {0x08, false}, "Digit8": {0x09, false}, "Digit9": {0x0a, false}, "Digit0": {0x0b, false},
		"Enter": {0x1c, false}, "NumpadEnter": {0x1c, true}, "Escape": {0x01, false}, "Backspace": {0x0e, false}, "Tab": {0x0f, false}, "Space": {0x39, false},
		"Minus": {0x0c, false}, "Equal": {0x0d, false}, "BracketLeft": {0x1a, false}, "BracketRight": {0x1b, false}, "Backslash": {0x2b, false}, "Semicolon": {0x27, false}, "Quote": {0x28, false}, "Backquote": {0x29, false}, "Comma": {0x33, false}, "Period": {0x34, false}, "Slash": {0x35, false},
		"ShiftLeft": {0x2a, false}, "ShiftRight": {0x36, false}, "ControlLeft": {0x1d, false}, "ControlRight": {0x1d, true}, "AltLeft": {0x38, false}, "AltRight": {0x38, true},
		"ArrowUp": {0x48, true}, "ArrowDown": {0x50, true}, "ArrowLeft": {0x4b, true}, "ArrowRight": {0x4d, true}, "Insert": {0x52, true}, "Delete": {0x53, true}, "Home": {0x47, true}, "End": {0x4f, true}, "PageUp": {0x49, true}, "PageDown": {0x51, true},
		"F1": {0x3b, false}, "F2": {0x3c, false}, "F3": {0x3d, false}, "F4": {0x3e, false}, "F5": {0x3f, false}, "F6": {0x40, false}, "F7": {0x41, false}, "F8": {0x42, false}, "F9": {0x43, false}, "F10": {0x44, false}, "F11": {0x57, false}, "F12": {0x58, false},
	}
	v, ok := m[code]
	return v.sc, v.ex, ok
}
