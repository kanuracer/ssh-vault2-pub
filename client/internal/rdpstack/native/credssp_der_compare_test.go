package native

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

type asn1NegoTokenTest struct {
	Data []byte `asn1:"explicit,tag:0"`
}
type asn1TSRequestTest struct {
	Version    int                 `asn1:"explicit,tag:0"`
	NegoTokens []asn1NegoTokenTest `asn1:"optional,explicit,tag:1"`
	AuthInfo   []byte              `asn1:"optional,explicit,tag:2"`
	PubKeyAuth []byte              `asn1:"optional,explicit,tag:3"`
}

func TestTSRequestDERMatchesStdlibASN1Shape(t *testing.T) {
	tok := []byte("NTLMSSP\x00type1")
	got, err := EncodeTSRequest(TSRequest{Version: 2, NegoTokens: [][]byte{tok}})
	if err != nil {
		t.Fatal(err)
	}
	want, err := asn1.Marshal(asn1TSRequestTest{Version: 2, NegoTokens: []asn1NegoTokenTest{{Data: tok}}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("TSRequest DER mismatch\ngot  % x\nwant % x", got, want)
	}
}
