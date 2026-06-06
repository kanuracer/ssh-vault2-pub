package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const rdpRenderMagic = "SVRDP1"
const rdpRenderQueueSize = 16

const (
	rdpRenderFormatRawRGBA byte = 1
)

type RDPRenderEndpoint struct {
	SessionID string `json:"sessionId"`
	URL       string `json:"url"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
}

type RDPRenderFrame struct {
	SessionID     string
	Seq           uint64
	Left          int
	Top           int
	Width         int
	Height        int
	SurfaceWidth  int
	SurfaceHeight int
	Stride        int
	RGBA          []byte
}

type rdpRenderSession struct {
	id     string
	token  string
	width  int
	height int
	ch     chan RDPRenderFrame
}

type RDPRenderHub struct {
	mu       sync.Mutex
	listener net.Listener
	server   *http.Server
	baseURL  string
	sessions map[string]*rdpRenderSession
}

func NewRDPRenderHub() (*RDPRenderHub, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	h := &RDPRenderHub{listener: ln, baseURL: "ws://" + ln.Addr().String(), sessions: map[string]*rdpRenderSession{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/rdp/render/", h.serveWS)
	h.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := h.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			appLog("RDP render websocket server error: %v", err)
		}
	}()
	return h, nil
}

func (h *RDPRenderHub) Close() error {
	if h == nil || h.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return h.server.Shutdown(ctx)
}

func (h *RDPRenderHub) Register(sessionID string, width, height int) (RDPRenderEndpoint, error) {
	if h == nil {
		return RDPRenderEndpoint{}, fmt.Errorf("RDP-Renderer nicht verfügbar")
	}
	token, err := randomRenderToken()
	if err != nil {
		return RDPRenderEndpoint{}, err
	}
	h.mu.Lock()
	old := h.sessions[sessionID]
	if old != nil {
		close(old.ch)
	}
	h.sessions[sessionID] = &rdpRenderSession{id: sessionID, token: token, width: width, height: height, ch: make(chan RDPRenderFrame, rdpRenderQueueSize)}
	h.mu.Unlock()
	return RDPRenderEndpoint{SessionID: sessionID, URL: fmt.Sprintf("%s/rdp/render/%s?token=%s", h.baseURL, sessionID, token), Width: width, Height: height}, nil
}

func (h *RDPRenderHub) Unregister(sessionID string) {
	if h == nil || sessionID == "" {
		return
	}
	h.mu.Lock()
	if s := h.sessions[sessionID]; s != nil {
		delete(h.sessions, sessionID)
		close(s.ch)
	}
	h.mu.Unlock()
}

func (h *RDPRenderHub) Publish(frame RDPRenderFrame) (accepted bool) {
	if h == nil || frame.SessionID == "" || len(frame.RGBA) == 0 {
		return true
	}
	h.mu.Lock()
	s := h.sessions[frame.SessionID]
	h.mu.Unlock()
	if s == nil {
		return true
	}
	defer func() {
		if recover() != nil {
			appLog("RDP render publish ignored closed session=%s seq=%d", frame.SessionID, frame.Seq)
			accepted = false
		}
	}()
	// Latest-wins for both full and dirty frames. A stale queue is worse than a
	// skipped intermediate dirty rect for interactive RDP: it creates visible
	// input lag and choppy motion. Periodic full keyframes heal any dirty rects
	// skipped during backpressure.
	select {
	case s.ch <- frame:
		return true
	default:
	}
	for {
		select {
		case _, ok := <-s.ch:
			if !ok {
				return false
			}
			continue
		default:
			select {
			case s.ch <- frame:
				return true
			default:
				return false
			}
		}
	}
}

func (frame RDPRenderFrame) IsFullSurface() bool {
	sw := frame.SurfaceWidth
	if sw <= 0 {
		sw = frame.Left + frame.Width
	}
	sh := frame.SurfaceHeight
	if sh <= 0 {
		sh = frame.Top + frame.Height
	}
	return frame.Left == 0 && frame.Top == 0 && frame.Width == sw && frame.Height == sh
}

func (h *RDPRenderHub) serveWS(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/rdp/render/")
	token := r.URL.Query().Get("token")
	h.mu.Lock()
	s := h.sessions[id]
	ok := s != nil && token != "" && token == s.token
	h.mu.Unlock()
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "rdp render closed")
	for frame := range s.ch {
		pkt, err := EncodeRDPRenderPacketAdaptive(frame, nil)
		if err != nil {
			appLog("RDP render packet encode error session=%s: %v", id, err)
			continue
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		err = conn.Write(ctx, websocket.MessageBinary, pkt)
		cancel()
		if err != nil {
			return
		}
	}
}

func EncodeRDPRenderPacket(frame RDPRenderFrame) ([]byte, error) {
	return encodeRDPRenderPacket(frame, rdpRenderFormatRawRGBA, nil)
}

func EncodeRDPRenderPacketAdaptive(frame RDPRenderFrame, formats map[byte]bool) ([]byte, error) {
	_ = formats
	// Keep the render path synchronous raw RGBA. The 1.2.53 JPEG opt-in
	// compressed bytes but moved expensive encoding into the RDP render thread,
	// causing severe motion/video regressions (~2fps). A future codec path must
	// be asynchronous/GPU-backed or otherwise proven low-CPU before opt-in.
	return EncodeRDPRenderPacket(frame)
}

func encodeRDPRenderPacket(frame RDPRenderFrame, format byte, encodedPayload []byte) ([]byte, error) {
	if frame.Width <= 0 || frame.Height <= 0 {
		return nil, fmt.Errorf("invalid RDP render frame size %dx%d", frame.Width, frame.Height)
	}
	stride := frame.Stride
	if stride <= 0 {
		stride = frame.Width * 4
	}
	need := stride * frame.Height
	if len(frame.RGBA) < need {
		return nil, fmt.Errorf("RDP render frame buffer too short: %d < %d", len(frame.RGBA), need)
	}
	sw := frame.SurfaceWidth
	if sw <= 0 {
		sw = frame.Left + frame.Width
	}
	sh := frame.SurfaceHeight
	if sh <= 0 {
		sh = frame.Top + frame.Height
	}
	payload := frame.RGBA[:need]
	if encodedPayload != nil {
		payload = encodedPayload
	}
	var b bytes.Buffer
	b.Grow(50 + len(payload))
	b.WriteString(rdpRenderMagic)
	_ = binary.Write(&b, binary.LittleEndian, frame.Seq)
	for _, v := range []uint32{uint32(frame.Left), uint32(frame.Top), uint32(frame.Width), uint32(frame.Height), uint32(sw), uint32(sh), uint32(stride)} {
		_ = binary.Write(&b, binary.LittleEndian, v)
	}
	b.WriteByte(format)
	b.Write(make([]byte, 7))
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(payload)))
	b.Write(payload)
	return b.Bytes(), nil
}

func randomRenderToken() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
