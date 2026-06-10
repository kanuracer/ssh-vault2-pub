package plugin

import "testing"

func TestZGFXDecodesSegmentedSingleUncompressed(t *testing.T) {
	d := NewZGFXDecoder()
	got, err := d.Decompress([]byte{zgfxSegmentedSingle, 0x04, 'a', 'b', 'c'})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc" {
		t.Fatalf("got %q", got)
	}
}
