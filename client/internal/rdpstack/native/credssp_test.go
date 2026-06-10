package native

import (
	"bytes"
	"testing"
)

func TestCredSSPTSRequestRoundTrip(t *testing.T) {
	req := TSRequest{
		Version:     6,
		NegoTokens:  [][]byte{[]byte("NTLMSSP-type1")},
		PubKeyAuth:  []byte{1, 2, 3},
		ClientNonce: []byte{4, 5, 6, 7},
	}
	der, err := EncodeTSRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []byte{0xa0, 0xa1, 0xa3, 0xa5} {
		if !bytes.Contains(der, []byte{tag}) {
			t.Fatalf("missing explicit context tag 0x%02x in % x", tag, der)
		}
	}
	got, err := DecodeTSRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != req.Version || !bytes.Equal(got.NegoTokens[0], req.NegoTokens[0]) || !bytes.Equal(got.PubKeyAuth, req.PubKeyAuth) || !bytes.Equal(got.ClientNonce, req.ClientNonce) {
		t.Fatalf("roundtrip mismatch\ngot  %+v\nwant %+v", got, req)
	}
}

func TestCredSSPPasswordCredentialsEncode(t *testing.T) {
	creds, err := EncodeTSPasswordCredentials("DOM", "hermes", "secret")
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []byte{0xa0, 0xa1, 0xa2} {
		if !bytes.Contains(creds, []byte{tag}) {
			t.Fatalf("password creds missing context tag 0x%02x: % x", tag, creds)
		}
	}
	wrapped, err := EncodeTSCredentials(1, creds)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wrapped, creds) {
		t.Fatalf("TSCredentials did not wrap password creds: % x", wrapped)
	}
	if !bytes.Contains(wrapped, []byte{0xa0, 0x03, 0x02, 0x01, 0x01}) {
		t.Fatalf("TSCredentials credType missing: % x", wrapped)
	}
}

func TestDecodeTSRequestRejectsMalformedDER(t *testing.T) {
	if _, err := DecodeTSRequest([]byte{0x30, 0x82, 0xff}); err == nil {
		t.Fatal("expected malformed DER error")
	}
}
