package native

import (
	"bytes"
	"testing"
)

func TestBuildNTLMv2BlobDoesNotAppendDuplicateEOLWhenTargetInfoIsTerminated(t *testing.T) {
	targetInfoAlreadyTerminated := []byte{2, 0, 2, 0, 'A', 0, 0, 0, 0, 0}
	blob := buildNTLMv2Blob(0x1122334455667788, []byte{1, 2, 3, 4, 5, 6, 7, 8}, targetInfoAlreadyTerminated)
	if !bytes.HasSuffix(blob, targetInfoAlreadyTerminated) {
		t.Fatalf("blob should preserve existing terminated targetInfo without duplicate EOL: %x", blob)
	}
	if bytes.HasSuffix(blob, []byte{0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("blob appended duplicate EOL after terminated targetInfo: %x", blob)
	}
}

func TestAuthenticateTargetInfoAddsCredSSPEPAPairsAndPadding(t *testing.T) {
	serverInfo := []byte{2, 0, 2, 0, 'A', 0, 0, 0, 0, 0}
	got := ntlmAuthenticateTargetInfo(serverInfo, "TERMSRV/192.0.2.115", true)
	for _, want := range [][]byte{
		{6, 0, 4, 0, 2, 0, 0, 0},
		{10, 0, 16, 0},
		{9, 0, 38, 0},
	} {
		if !bytes.Contains(got, want) {
			t.Fatalf("authenticate targetInfo missing %x in %x", want, got)
		}
	}
	if !bytes.HasSuffix(got, make([]byte, 12)) {
		t.Fatalf("authenticate targetInfo should end with EOL + 8 byte padding: %x", got)
	}
}
