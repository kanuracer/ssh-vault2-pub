package client

import "testing"

func TestNormalizeUncompressedBitmapStreamConvertsBottomUpPadded24BPPToTopDownTight(t *testing.T) {
	// 3 px * 3 bytes = 9 bytes, padded to a 4-byte aligned 12-byte RDP row.
	// Source order is bottom row first. Output contract is top row first, tightly packed.
	bottom := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9,
		0xaa, 0xbb, 0xcc,
	}
	top := []byte{
		10, 11, 12, 13, 14, 15, 16, 17, 18,
		0xdd, 0xee, 0xff,
	}
	src := append(append([]byte{}, bottom...), top...)

	got := normalizeUncompressedBitmapStream(src, 3, 2, 3)
	want := []byte{
		10, 11, 12, 13, 14, 15, 16, 17, 18,
		1, 2, 3, 4, 5, 6, 7, 8, 9,
	}
	if string(got) != string(want) {
		t.Fatalf("normalized stream = %v, want %v", got, want)
	}
}

func TestNormalizeUncompressedBitmapStreamKeeps32BPPTightRowsTopDown(t *testing.T) {
	src := []byte{
		1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15, 16,
	}
	got := normalizeUncompressedBitmapStream(src, 2, 2, 4)
	want := []byte{
		9, 10, 11, 12, 13, 14, 15, 16,
		1, 2, 3, 4, 5, 6, 7, 8,
	}
	if string(got) != string(want) {
		t.Fatalf("normalized 32bpp stream = %v, want %v", got, want)
	}
}
