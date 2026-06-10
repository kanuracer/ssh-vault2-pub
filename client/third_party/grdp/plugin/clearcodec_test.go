package plugin

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func clearCodecUncompressedPayload(width, height uint16, bgr []byte) []byte {
	body := bytes.NewBuffer(nil)
	body.WriteByte(0) // glyphFlags
	body.WriteByte(0) // seq
	binary.Write(body, binary.LittleEndian, uint32(0))
	binary.Write(body, binary.LittleEndian, uint32(0))
	subLen := uint32(13 + len(bgr))
	binary.Write(body, binary.LittleEndian, subLen)
	binary.Write(body, binary.LittleEndian, uint16(0))
	binary.Write(body, binary.LittleEndian, uint16(0))
	binary.Write(body, binary.LittleEndian, width)
	binary.Write(body, binary.LittleEndian, height)
	binary.Write(body, binary.LittleEndian, uint32(len(bgr)))
	body.WriteByte(0) // subcodec: uncompressed BGR24
	body.Write(bgr)
	return body.Bytes()
}

func TestClearCodecDecodesUncompressedBGR24SubcodecToRGBA(t *testing.T) {
	payload := clearCodecUncompressedPayload(2, 1, []byte{
		0x00, 0x00, 0xff, // red in BGR24
		0x00, 0xff, 0x00, // green in BGR24
	})
	dec := NewClearCodecDecoder()

	rgba, err := dec.Decode(payload, 2, 1)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	want := []byte{255, 0, 0, 255, 0, 255, 0, 255}
	if !bytes.Equal(rgba, want) {
		t.Fatalf("rgba=%v, want %v", rgba, want)
	}
}
