package native

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

func CredSSPPublicKeyBytes(publicKey any, fallbackSubjectPublicKeyInfo []byte) ([]byte, error) {
	if rsaKey, ok := publicKey.(*rsa.PublicKey); ok && rsaKey != nil && rsaKey.N != nil && rsaKey.E > 0 {
		return x509.MarshalPKCS1PublicKey(rsaKey), nil
	}
	if len(fallbackSubjectPublicKeyInfo) == 0 {
		return nil, fmt.Errorf("CredSSP public key unavailable")
	}
	out := append([]byte{}, fallbackSubjectPublicKeyInfo...)
	return out, nil
}
