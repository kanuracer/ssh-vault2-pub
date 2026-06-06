package media

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"time"
)

const (
	// MaxRawFrameBytes keeps the post-CredSSP render path bounded while still
	// allowing large high-DPI dirty rects. It applies before compression.
	MaxRawFrameBytes = 64 * 1024 * 1024
)

type PixelFormat string

const (
	PixelFormatRGBA PixelFormat = "rgba8888"
)

type FrameCodec string

const (
	FrameCodecZlibRGBA FrameCodec = "zlib.rgba8888"
)

// RawFrame is a dirty rectangle from the native RDP decoder. Pixels are binary
// RGBA bytes, never base64 text and never a Wails renderer pixel blob.
type RawFrame struct {
	SessionID     string
	Seq           uint64
	Left          int
	Top           int
	Width         int
	Height        int
	SurfaceWidth  int
	SurfaceHeight int
	Format        PixelFormat
	Stride        int
	Pixels        []byte
	CapturedAt    time.Time
}

// CompressedFrame is the render transport unit emitted after decode and before
// any platform/frontend bridge. Payload is compressed binary data.
type CompressedFrame struct {
	SessionID       string
	Seq             uint64
	Left            int
	Top             int
	Width           int
	Height          int
	SurfaceWidth    int
	SurfaceHeight   int
	Format          PixelFormat
	Codec           FrameCodec
	Payload         []byte
	UncompressedLen int
	CapturedAt      time.Time
	EncodedAt       time.Time
}

type FrameEncoder struct {
	now func() time.Time
}

func NewFrameEncoder() *FrameEncoder { return &FrameEncoder{now: time.Now} }

func NewFrameEncoderWithClock(now func() time.Time) *FrameEncoder {
	if now == nil {
		now = time.Now
	}
	return &FrameEncoder{now: now}
}

func (e *FrameEncoder) Encode(raw RawFrame) (CompressedFrame, error) {
	if raw.Format != PixelFormatRGBA {
		return CompressedFrame{}, fmt.Errorf("unsupported RDP frame pixel format %q", raw.Format)
	}
	rowBytes, rawLen, err := validateRawFrameGeometry(raw.Width, raw.Height, raw.Stride, len(raw.Pixels))
	if err != nil {
		return CompressedFrame{}, err
	}
	stride := raw.Stride
	if stride <= 0 {
		stride = rowBytes
	}

	pixels := raw.Pixels[:rawLen]
	if stride != rowBytes {
		pixels = make([]byte, 0, raw.Width*raw.Height*4)
		for y := 0; y < raw.Height; y++ {
			start := y * stride
			pixels = append(pixels, raw.Pixels[start:start+rowBytes]...)
		}
	}

	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(pixels); err != nil {
		_ = zw.Close()
		return CompressedFrame{}, err
	}
	if err := zw.Close(); err != nil {
		return CompressedFrame{}, err
	}

	surfaceWidth := raw.SurfaceWidth
	if surfaceWidth <= 0 {
		surfaceWidth = raw.Left + raw.Width
	}
	surfaceHeight := raw.SurfaceHeight
	if surfaceHeight <= 0 {
		surfaceHeight = raw.Top + raw.Height
	}
	encodedAt := time.Time{}
	if e != nil && e.now != nil {
		encodedAt = e.now()
	}
	return CompressedFrame{
		SessionID:       raw.SessionID,
		Seq:             raw.Seq,
		Left:            raw.Left,
		Top:             raw.Top,
		Width:           raw.Width,
		Height:          raw.Height,
		SurfaceWidth:    surfaceWidth,
		SurfaceHeight:   surfaceHeight,
		Format:          raw.Format,
		Codec:           FrameCodecZlibRGBA,
		Payload:         buf.Bytes(),
		UncompressedLen: raw.Width * raw.Height * 4,
		CapturedAt:      raw.CapturedAt,
		EncodedAt:       encodedAt,
	}, nil
}

func validateRawFrameGeometry(width, height, stride, dataLen int) (rowBytes int, rawLen int, err error) {
	if width <= 0 || height <= 0 {
		return 0, 0, fmt.Errorf("invalid RDP frame size %dx%d", width, height)
	}
	rowBytes64 := int64(width) * 4
	rawLen64 := rowBytes64 * int64(height)
	if rowBytes64 > int64(MaxRawFrameBytes) || rawLen64 > int64(MaxRawFrameBytes) {
		return 0, 0, fmt.Errorf("RDP frame too large: %d bytes", rawLen64)
	}
	rowBytes = int(rowBytes64)
	rawLen = int(rawLen64)
	if stride <= 0 {
		stride = rowBytes
	}
	if stride < rowBytes {
		return 0, 0, fmt.Errorf("RDP frame stride %d smaller than row bytes %d", stride, rowBytes)
	}
	needed64 := int64(stride)*int64(height-1) + int64(rowBytes)
	if needed64 > int64(MaxRawFrameBytes) {
		return 0, 0, fmt.Errorf("RDP frame stride envelope too large: %d bytes", needed64)
	}
	if int64(dataLen) < needed64 {
		return 0, 0, fmt.Errorf("RDP frame pixel buffer too short: %d < %d", dataLen, needed64)
	}
	return rowBytes, rawLen, nil
}

// FramePacer bounds render delivery rate and coalesces bursts to the latest
// frame. It is deterministic and goroutine-free so callers can drive it from
// their own event loop after the RDP handshake completes.
type FramePacer struct {
	interval time.Duration
	next     time.Time
	pending  *CompressedFrame
}

func NewFramePacer(maxFPS int) *FramePacer {
	if maxFPS <= 0 {
		maxFPS = 60
	}
	return &FramePacer{interval: time.Second / time.Duration(maxFPS)}
}

func (p *FramePacer) Submit(now time.Time, frame CompressedFrame) []CompressedFrame {
	if p == nil {
		return []CompressedFrame{frame}
	}
	if p.interval <= 0 {
		p.interval = time.Second / 60
	}
	if p.next.IsZero() || !now.Before(p.next) {
		p.pending = nil
		p.next = now.Add(p.interval)
		return []CompressedFrame{frame}
	}
	copyFrame := frame
	p.pending = &copyFrame
	return nil
}

func (p *FramePacer) Flush(now time.Time) []CompressedFrame {
	if p == nil || p.pending == nil || now.Before(p.next) {
		return nil
	}
	frame := *p.pending
	p.pending = nil
	p.next = now.Add(p.interval)
	return []CompressedFrame{frame}
}

func (p *FramePacer) Interval() time.Duration {
	if p == nil || p.interval <= 0 {
		return 0
	}
	return p.interval
}

type PCMFormat struct {
	SampleRate    int
	Channels      int
	BitsPerSample int
}

type AudioPacket struct {
	SessionID  string
	Seq        uint64
	PCM        []byte
	CapturedAt time.Time
}

type AudioStamp struct {
	SessionID string
	Seq       uint64
	PTS       time.Time
	Duration  time.Duration
	Buffered  time.Duration
	Format    PCMFormat
}

type AudioClock struct {
	format        PCMFormat
	bytesPerFrame int
	nextPTS       time.Time
}

func NewAudioClock(format PCMFormat) (*AudioClock, error) {
	if format.SampleRate <= 0 {
		return nil, fmt.Errorf("invalid PCM sample rate %d", format.SampleRate)
	}
	if format.Channels <= 0 {
		return nil, fmt.Errorf("invalid PCM channel count %d", format.Channels)
	}
	if format.BitsPerSample <= 0 || format.BitsPerSample%8 != 0 {
		return nil, fmt.Errorf("invalid PCM bits per sample %d", format.BitsPerSample)
	}
	bytesPerFrame := format.Channels * (format.BitsPerSample / 8)
	return &AudioClock{format: format, bytesPerFrame: bytesPerFrame}, nil
}

func (c *AudioClock) Push(now time.Time, packet AudioPacket) (AudioStamp, error) {
	if c == nil || c.bytesPerFrame <= 0 || c.format.SampleRate <= 0 {
		return AudioStamp{}, fmt.Errorf("audio clock is not initialized")
	}
	if len(packet.PCM)%c.bytesPerFrame != 0 {
		return AudioStamp{}, fmt.Errorf("PCM payload length %d is not a whole number of sample frames (%d bytes each)", len(packet.PCM), c.bytesPerFrame)
	}
	sampleFrames := len(packet.PCM) / c.bytesPerFrame
	duration := time.Duration(sampleFrames) * time.Second / time.Duration(c.format.SampleRate)
	pts := c.nextPTS
	if pts.IsZero() || now.After(pts) {
		pts = now
	}
	c.nextPTS = pts.Add(duration)
	buffered := c.nextPTS.Sub(now)
	if buffered < 0 {
		buffered = 0
	}
	return AudioStamp{SessionID: packet.SessionID, Seq: packet.Seq, PTS: pts, Duration: duration, Buffered: buffered, Format: c.format}, nil
}

func (c *AudioClock) Format() PCMFormat {
	if c == nil {
		return PCMFormat{}
	}
	return c.format
}
