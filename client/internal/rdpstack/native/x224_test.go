package native

import (
	"encoding/hex"
	"errors"
	"testing"
)

func mustPayload(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	payload, rest, err := DecodeTPKT(b)
	if err != nil {
		t.Fatalf("DecodeTPKT: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected rest: %x", rest)
	}
	return payload
}

func TestDecodeX224ConnectionConfirmSelectsTLS(t *testing.T) {
	cc, err := DecodeX224ConnectionConfirm(mustPayload(t, "030000130ed000000000000200080001000000"))
	if err != nil {
		t.Fatalf("DecodeX224ConnectionConfirm: %v", err)
	}
	if !cc.HasNegotiation || cc.SelectedProtocol != ProtocolSSL || cc.FailureCode != 0 {
		t.Fatalf("unexpected confirm: %+v", cc)
	}
	if !cc.SelectedProtocol.NeedsTLS() || cc.SelectedProtocol.NeedsCredSSP() {
		t.Fatalf("TLS protocol flags wrong")
	}
	mode, err := SecurityModeForProtocol(cc.SelectedProtocol)
	if err != nil || mode != SecurityTLS {
		t.Fatalf("security mode = %q err=%v", mode, err)
	}
}

func TestDecodeX224ConnectionConfirmSelectsNLA(t *testing.T) {
	cc, err := DecodeX224ConnectionConfirm(mustPayload(t, "030000130ed000000000000200080002000000"))
	if err != nil {
		t.Fatalf("DecodeX224ConnectionConfirm: %v", err)
	}
	if cc.SelectedProtocol != ProtocolHybrid || !cc.SelectedProtocol.NeedsTLS() || !cc.SelectedProtocol.NeedsCredSSP() {
		t.Fatalf("unexpected protocol flags: %+v", cc)
	}
	mode, err := SecurityModeForProtocol(cc.SelectedProtocol)
	if err != nil || mode != SecurityNLA {
		t.Fatalf("security mode = %q err=%v", mode, err)
	}
}

func TestDecodeX224ConnectionConfirmNegotiationFailure(t *testing.T) {
	cc, err := DecodeX224ConnectionConfirm(mustPayload(t, "030000130ed000000000000300080005000000"))
	var nf NegotiationFailureError
	if !errors.As(err, &nf) {
		t.Fatalf("expected NegotiationFailureError, got %T %v", err, err)
	}
	if cc.FailureCode != 5 || nf.Code != 5 {
		t.Fatalf("failure code mismatch: %+v err=%+v", cc, nf)
	}
}

func TestDecodeX224ConnectionConfirmRejectsMalformed(t *testing.T) {
	cases := [][]byte{
		{},
		{0x06, 0xd0, 0x00},
		{0x0e, 0xe0, 0, 0, 0, 0, 0, 0x02, 0, 0x08, 0, 0x01, 0, 0, 0},
		{0x0e, 0xd0, 0, 0, 0, 0, 0, 0x02, 0, 0x04, 0, 0x01, 0, 0, 0},
		{0x0e, 0xd0, 0, 0, 0, 0, 0, 0x09, 0, 0x08, 0, 0x01, 0, 0, 0},
	}
	for _, tc := range cases {
		if _, err := DecodeX224ConnectionConfirm(tc); err == nil {
			t.Fatalf("expected error for %x", tc)
		}
	}
}

func TestSecurityModeForProtocolRejectsHybridExAndUnknown(t *testing.T) {
	if _, err := SecurityModeForProtocol(ProtocolHybridEx); err == nil {
		t.Fatal("expected HYBRID_EX unsupported error")
	}
	if _, err := SecurityModeForProtocol(RDPProtocol(0x99)); err == nil {
		t.Fatal("expected unknown protocol error")
	}
}
