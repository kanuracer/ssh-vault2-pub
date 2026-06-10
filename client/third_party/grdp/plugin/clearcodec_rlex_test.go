package plugin

import "testing"

func TestClearCodecDecodesRLEXSubcodec(t *testing.T) {
	// 2x1 rect, palette red, one run pixel + one suite pixel.
	body := []byte{
		1,                // palette count
		0x00, 0x00, 0xff, // BGR red
		0x00, 0x01, // tmp: stop=0 depth=0, run=1
	}
	payload := clearCodecPayloadWithSubcodec(2, 1, 2, body)
	rgba, err := NewClearCodecDecoder().Decode(payload, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{255, 0, 0, 255, 255, 0, 0, 255}
	for i := range want {
		if rgba[i] != want[i] {
			t.Fatalf("rgba=%v want=%v", rgba, want)
		}
	}
}

func clearCodecPayloadWithSubcodec(width, height uint16, subcodec byte, data []byte) []byte {
	out := []byte{0, 0}
	out = append(out, 0, 0, 0, 0) // residual len
	out = append(out, 0, 0, 0, 0) // bands len
	subLen := uint32(13 + len(data))
	out = append(out, byte(subLen), byte(subLen>>8), byte(subLen>>16), byte(subLen>>24))
	out = append(out, 0, 0, 0, 0) // x y
	out = append(out, byte(width), byte(width>>8), byte(height), byte(height>>8))
	dl := uint32(len(data))
	out = append(out, byte(dl), byte(dl>>8), byte(dl>>16), byte(dl>>24), subcodec)
	out = append(out, data...)
	return out
}
