package native

import (
	"bytes"
	"testing"
)

func TestNTLMSealWrapUnwrapRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef")
	client := NewNTLMSealState(key, true)
	server := NewNTLMSealState(key, false)
	plain := []byte("CredSSP public key bytes")
	wrapped, err := client.Wrap(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wrapped, plain) {
		t.Fatalf("wrapped payload must be sealed, got %x", wrapped)
	}
	got, err := server.Unwrap(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("unwrap mismatch got %q want %q", got, plain)
	}

	reply := []byte("server reply")
	wrappedReply, err := server.Wrap(reply)
	if err != nil {
		t.Fatal(err)
	}
	gotReply, err := client.Unwrap(wrappedReply)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotReply, reply) {
		t.Fatalf("reply mismatch got %q want %q", gotReply, reply)
	}
}

func TestNTLMSealRejectsTamperedSignature(t *testing.T) {
	key := []byte("0123456789abcdef")
	client := NewNTLMSealState(key, true)
	server := NewNTLMSealState(key, false)
	wrapped, err := client.Wrap([]byte("important"))
	if err != nil {
		t.Fatal(err)
	}
	wrapped[4] ^= 0xff
	if _, err := server.Unwrap(wrapped); err == nil {
		t.Fatal("expected signature error")
	}
}
