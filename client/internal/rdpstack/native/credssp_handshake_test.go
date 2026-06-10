package native

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestCredSSPPubKeyAuthV6UsesBindingHash(t *testing.T) {
	key := []byte("0123456789abcdef")
	clientSeal := NewNTLMSealState(key, true)
	serverSeal := NewNTLMSealState(key, false)
	pub := []byte("tls-public-key")
	nonce := []byte("12345678901234567890123456789012")
	wrapped, expect, err := BuildCredSSPClientPubKeyAuth(6, pub, nonce, clientSeal)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := serverSeal.Unwrap(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(append(append([]byte("CredSSP Client-To-Server Binding Hash\x00"), nonce...), pub...))
	if !bytes.Equal(plain, want[:]) {
		t.Fatalf("binding hash mismatch got %x want %x", plain, want)
	}
	if len(expect) != sha256.Size {
		t.Fatalf("server expected binding hash len = %d", len(expect))
	}
}

func TestCredSSPPubKeyAuthLegacyUsesRawPublicKey(t *testing.T) {
	key := []byte("0123456789abcdef")
	clientSeal := NewNTLMSealState(key, true)
	serverSeal := NewNTLMSealState(key, false)
	pub := []byte("tls-public-key")
	wrapped, _, err := BuildCredSSPClientPubKeyAuth(3, pub, nil, clientSeal)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := serverSeal.Unwrap(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, pub) {
		t.Fatalf("legacy pubkey mismatch got %q want %q", plain, pub)
	}
}

func TestReadCredSSPMessageReadsSingleDERObject(t *testing.T) {
	first, _ := EncodeTSRequest(TSRequest{Version: 6})
	second, _ := EncodeTSRequest(TSRequest{Version: 3})
	r := bytes.NewReader(append(first, second...))
	got, err := ReadCredSSPMessage(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("read wrong DER object got %x want %x", got, first)
	}
}

func TestCredSSPAuthenticateRequestV5PlusIncludesClientNonce(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x42}, 32)
	msg, err := BuildCredSSPAuthenticateRequest(6, []byte("type3"), []byte("pubKeyAuth"), nonce)
	if err != nil {
		t.Fatal(err)
	}
	req, err := DecodeTSRequest(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(req.ClientNonce, nonce) {
		t.Fatalf("clientNonce mismatch got %x want %x", req.ClientNonce, nonce)
	}
}
