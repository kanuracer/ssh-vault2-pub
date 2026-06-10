package native

import (
	"bytes"
	"testing"
)

func TestSPNEGONegTokenInitWrapsNTLM(t *testing.T) {
	ntlm := []byte("NTLMSSP\x00type1")
	got, err := EncodeSPNEGONegTokenInit(ntlm)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range [][]byte{
		{0x60},
		{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02},       // SPNEGO OID
		{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37}, // NTLMSSP OID prefix
		ntlm,
	} {
		if !bytes.Contains(got, needle) {
			t.Fatalf("SPNEGO init missing % x in % x", needle, got)
		}
	}
}

func TestSPNEGONegTokenRespRoundTrip(t *testing.T) {
	ntlm := []byte("NTLMSSP\x00type3")
	resp, err := EncodeSPNEGONegTokenResp(ntlm)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeSPNEGONegTokenResp(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, ntlm) {
		t.Fatalf("response token mismatch: %q", got)
	}
}

func TestDecodeSPNEGONegTokenRespRejectsMissingToken(t *testing.T) {
	if _, err := DecodeSPNEGONegTokenResp(derExplicit(1, derSeq(nil))); err == nil {
		t.Fatal("expected missing response token error")
	}
}
