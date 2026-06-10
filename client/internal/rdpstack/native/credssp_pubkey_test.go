package native

import (
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
)

func TestCredSSPPublicKeyBytesUsesPKCS1RSAWhenAvailable(t *testing.T) {
	pub := &rsa.PublicKey{N: big.NewInt(65537 * 17), E: 65537}
	certPub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := CredSSPPublicKeyBytes(pub, certPub)
	if err != nil {
		t.Fatal(err)
	}
	want := x509.MarshalPKCS1PublicKey(pub)
	if string(got) != string(want) {
		t.Fatalf("public key DER mismatch got %x want %x", got, want)
	}
}
