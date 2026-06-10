package media

import (
	"bytes"
	"compress/zlib"
	"io"
	"testing"
	"time"
)

func inflate(t *testing.T, payload []byte) []byte {
	t.Helper()
	r, err := zlib.NewReader(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("zlib reader: %v", err)
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("inflate: %v", err)
	}
	return out
}

func TestFrameEncoderProducesCompressedBinaryPayload(t *testing.T) {
	enc := NewFrameEncoder()
	raw := RawFrame{
		SessionID:     "s1",
		Seq:           7,
		Left:          10,
		Top:           20,
		Width:         2,
		Height:        2,
		SurfaceWidth:  1280,
		SurfaceHeight: 720,
		Format:        PixelFormatRGBA,
		Stride:        8,
		Pixels: []byte{
			255, 0, 0, 255, 0, 255, 0, 255,
			0, 0, 255, 255, 255, 255, 255, 255,
		},
	}

	frame, err := enc.Encode(raw)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if frame.Codec != FrameCodecZlibRGBA {
		t.Fatalf("codec = %q, want %q", frame.Codec, FrameCodecZlibRGBA)
	}
	if len(frame.Payload) == 0 {
		t.Fatalf("missing compressed payload")
	}
	if frame.UncompressedLen != len(raw.Pixels) {
		t.Fatalf("uncompressed len = %d, want %d", frame.UncompressedLen, len(raw.Pixels))
	}
	if got := inflate(t, frame.Payload); !bytes.Equal(got, raw.Pixels) {
		t.Fatalf("inflated payload = %v, want %v", got, raw.Pixels)
	}
	if frame.SessionID != raw.SessionID || frame.Seq != raw.Seq || frame.Left != raw.Left || frame.Top != raw.Top || frame.Width != raw.Width || frame.Height != raw.Height || frame.SurfaceWidth != raw.SurfaceWidth || frame.SurfaceHeight != raw.SurfaceHeight {
		t.Fatalf("metadata not preserved: %#v", frame)
	}
}

func TestFrameEncoderRejectsMalformedFrame(t *testing.T) {
	enc := NewFrameEncoder()
	_, err := enc.Encode(RawFrame{SessionID: "s1", Width: 2, Height: 2, Format: PixelFormatRGBA, Stride: 8, Pixels: []byte{1, 2, 3}})
	if err == nil {
		t.Fatalf("expected short pixel buffer error")
	}
	_, err = enc.Encode(RawFrame{SessionID: "s1", Width: 1, Height: 1, Format: PixelFormat("bgra"), Stride: 4, Pixels: []byte{1, 2, 3, 4}})
	if err == nil {
		t.Fatalf("expected unsupported pixel format error")
	}
}

func TestFrameEncoderAcceptsImplicitTightStride(t *testing.T) {
	enc := NewFrameEncoder()
	raw := RawFrame{SessionID: "s1", Width: 2, Height: 2, Format: PixelFormatRGBA, Pixels: []byte{
		1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15, 16,
	}}
	frame, err := enc.Encode(raw)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if got := inflate(t, frame.Payload); !bytes.Equal(got, raw.Pixels) {
		t.Fatalf("inflated payload = %v, want %v", got, raw.Pixels)
	}
}

func TestFrameEncoderNormalizesStridedRGBA(t *testing.T) {
	enc := NewFrameEncoder()
	raw := RawFrame{SessionID: "s1", Width: 2, Height: 2, Format: PixelFormatRGBA, Stride: 12, Pixels: []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 99, 99, 99, 99,
		9, 10, 11, 12, 13, 14, 15, 16, 88, 88, 88, 88,
	}}
	frame, err := enc.Encode(raw)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	if got := inflate(t, frame.Payload); !bytes.Equal(got, want) {
		t.Fatalf("inflated normalized rows = %v, want %v", got, want)
	}
}

func TestFramePacerEmitsImmediatelyThenCoalescesToLatestFrame(t *testing.T) {
	pacer := NewFramePacer(30)
	now := time.Unix(100, 0)
	first := CompressedFrame{Seq: 1, Payload: []byte{1}}
	second := CompressedFrame{Seq: 2, Payload: []byte{2}}
	third := CompressedFrame{Seq: 3, Payload: []byte{3}}

	out := pacer.Submit(now, first)
	if len(out) != 1 || out[0].Seq != 1 {
		t.Fatalf("first submit = %#v, want immediate seq 1", out)
	}
	out = pacer.Submit(now.Add(time.Millisecond), second)
	if len(out) != 0 {
		t.Fatalf("second submit emitted early: %#v", out)
	}
	out = pacer.Submit(now.Add(2*time.Millisecond), third)
	if len(out) != 0 {
		t.Fatalf("third submit emitted early: %#v", out)
	}
	if out = pacer.Flush(now.Add(30 * time.Millisecond)); len(out) != 0 {
		t.Fatalf("flush before frame interval emitted: %#v", out)
	}
	out = pacer.Flush(now.Add(34 * time.Millisecond))
	if len(out) != 1 || out[0].Seq != 3 {
		t.Fatalf("flush after interval = %#v, want latest seq 3", out)
	}
}

func TestAudioClockTimestampsPCMBySampleFrames(t *testing.T) {
	clock, err := NewAudioClock(PCMFormat{SampleRate: 48000, Channels: 2, BitsPerSample: 16})
	if err != nil {
		t.Fatalf("NewAudioClock: %v", err)
	}
	now := time.Unix(200, 0)
	packet := AudioPacket{Seq: 1, PCM: make([]byte, 480*2*2)} // 480 sample frames = 10ms at 48kHz.
	first, err := clock.Push(now, packet)
	if err != nil {
		t.Fatalf("first Push: %v", err)
	}
	if first.PTS != now || first.Duration != 10*time.Millisecond || first.Buffered != 10*time.Millisecond {
		t.Fatalf("first stamp = %#v", first)
	}
	second, err := clock.Push(now.Add(time.Millisecond), AudioPacket{Seq: 2, PCM: make([]byte, 480*2*2)})
	if err != nil {
		t.Fatalf("second Push: %v", err)
	}
	if second.PTS != now.Add(10*time.Millisecond) || second.Duration != 10*time.Millisecond || second.Buffered != 19*time.Millisecond {
		t.Fatalf("second stamp = %#v", second)
	}
}

func TestAudioClockRejectsInvalidPCMGeometry(t *testing.T) {
	if _, err := NewAudioClock(PCMFormat{SampleRate: 0, Channels: 2, BitsPerSample: 16}); err == nil {
		t.Fatalf("expected invalid sample rate error")
	}
	clock, err := NewAudioClock(PCMFormat{SampleRate: 48000, Channels: 2, BitsPerSample: 16})
	if err != nil {
		t.Fatalf("NewAudioClock: %v", err)
	}
	if _, err := clock.Push(time.Unix(0, 0), AudioPacket{Seq: 1, PCM: []byte{1, 2, 3}}); err == nil {
		t.Fatalf("expected non-integral PCM frame error")
	}
}
