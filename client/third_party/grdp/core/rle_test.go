package core

import "testing"

func TestDecompress16BppKeepsRGB565LittleEndianBytes(t *testing.T) {
	// One-pixel RLE colour packet: opcode 3 (Colour), count 1, RGB565 red 0xf800.
	// RDP bitmap consumers in this app decode 16bpp streams as little-endian RGB565.
	got := Decompress([]byte{0xf3, 0x01, 0x00, 0x00, 0xf8}, 1, 1, 2)
	want := []byte{0x00, 0xf8}
	if string(got) != string(want) {
		t.Fatalf("16bpp RLE bytes = % x, want little-endian RGB565 % x", got, want)
	}
}
