package native

import (
	"encoding/binary"
	"testing"
)

func TestNTLMTargetInfoWithMICFlagAddsAvFlagsBeforeEOL(t *testing.T) {
	// NbDomainName + EOL, no MsvAvFlags present.
	info := []byte{2, 0, 2, 0, 'A', 0, 0, 0, 0, 0}
	got := ntlmTargetInfoWithMICFlag(info)
	if len(got) != len(info)+8 {
		t.Fatalf("len = %d, want %d (%x)", len(got), len(info)+8, got)
	}
	if binary.LittleEndian.Uint16(got[6:8]) != 6 || binary.LittleEndian.Uint16(got[8:10]) != 4 {
		t.Fatalf("MsvAvFlags not inserted before EOL: %x", got)
	}
	if binary.LittleEndian.Uint32(got[10:14]) != 2 {
		t.Fatalf("MIC_PRESENT flag = %x, want 2", got[10:14])
	}
	if binary.LittleEndian.Uint16(got[14:16]) != 0 {
		t.Fatalf("EOL not preserved at end: %x", got)
	}
}

func TestNTLMTargetInfoWithMICFlagUpdatesExistingAvFlags(t *testing.T) {
	info := []byte{6, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	got := ntlmTargetInfoWithMICFlag(info)
	if binary.LittleEndian.Uint32(got[4:8]) != 2 {
		t.Fatalf("flags = %x, want MIC_PRESENT", got[4:8])
	}
}
