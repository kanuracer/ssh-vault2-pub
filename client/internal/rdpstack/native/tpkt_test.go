package native

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestTPKTRoundTrip(t *testing.T) {
	payload := []byte{0x02, 0xf0, 0x80}
	pkt, err := EncodeTPKT(payload)
	if err != nil {
		t.Fatalf("EncodeTPKT: %v", err)
	}
	if hex.EncodeToString(pkt) != "0300000702f080" {
		t.Fatalf("packet = %x", pkt)
	}
	got, rest, err := DecodeTPKT(pkt)
	if err != nil {
		t.Fatalf("DecodeTPKT: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected rest: %x", rest)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %x", got)
	}
}

func TestTPKTRejectsShortAndBadVersion(t *testing.T) {
	if _, _, err := DecodeTPKT([]byte{0x03, 0x00, 0x00}); err == nil {
		t.Fatal("expected short header error")
	}
	if _, _, err := DecodeTPKT([]byte{0x02, 0x00, 0x00, 0x04}); err == nil {
		t.Fatal("expected bad version error")
	}
}

func TestEncodeX224ConnectionRequest(t *testing.T) {
	pkt, err := EncodeX224ConnectionRequest("demo-host")
	if err != nil {
		t.Fatalf("EncodeX224ConnectionRequest: %v", err)
	}
	// TPKT header + X.224 CR TPDU + RDP negotiation request must be present.
	if !bytes.HasPrefix(pkt, []byte{0x03, 0x00}) {
		t.Fatalf("missing TPKT header: %x", pkt[:2])
	}
	if !bytes.Contains(pkt, []byte("Cookie: mstshash=demo-host\r\n")) {
		t.Fatalf("missing cookie: %x", pkt)
	}
	if !bytes.HasSuffix(pkt, []byte{0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}) {
		t.Fatalf("missing negotiation request: %x", pkt)
	}
	payload, _, err := DecodeTPKT(pkt)
	if err != nil {
		t.Fatalf("decode CR TPKT: %v", err)
	}
	if len(payload) < 7 || payload[1] != 0xe0 {
		t.Fatalf("not an X224 CR TPDU: %x", payload[:7])
	}
}
