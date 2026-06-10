package native

import (
	"encoding/binary"
	"testing"
)

func TestBuildNTLMAuthenticatePayloadOrderMatchesWindowsCredSSPClients(t *testing.T) {
	chal := &NTLMChallenge{Flags: ntlmNegotiateUnicode | ntlmNegotiateTargetInfo | ntlmNegotiateExtendedSessionSecurity | ntlmNegotiateKeyExch | ntlmNegotiateSign | ntlmNegotiateSeal | ntlmNegotiate128 | ntlmNegotiateVersion, TargetInfo: []byte{0, 0, 0, 0}}
	copy(chal.ServerChallenge[:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	auth, err := BuildNTLMAuthenticate(chal, NTLMAuthOptions{Domain: "D", User: "u", Password: "p", ClientChallenge: []byte{8, 7, 6, 5, 4, 3, 2, 1}, ExportedSessionKey: []byte("0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	domLen, domOff := secBufLenOff(auth.Message, 28)
	userLen, userOff := secBufLenOff(auth.Message, 36)
	wkLen, wkOff := secBufLenOff(auth.Message, 44)
	lmLen, lmOff := secBufLenOff(auth.Message, 12)
	ntLen, ntOff := secBufLenOff(auth.Message, 20)
	keyLen, keyOff := secBufLenOff(auth.Message, 52)
	if domOff != 88 || userOff != domOff+uint32(domLen) || wkOff != userOff+uint32(userLen) || lmOff != wkOff+uint32(wkLen) || ntOff != lmOff+uint32(lmLen) || keyOff != ntOff+uint32(ntLen) || keyLen != 16 {
		t.Fatalf("unexpected payload order dom=%d/%d user=%d/%d wk=%d/%d lm=%d/%d nt=%d/%d key=%d/%d", domLen, domOff, userLen, userOff, wkLen, wkOff, lmLen, lmOff, ntLen, ntOff, keyLen, keyOff)
	}
}

func secBufLenOff(msg []byte, at int) (int, uint32) {
	return int(binary.LittleEndian.Uint16(msg[at : at+2])), binary.LittleEndian.Uint32(msg[at+4 : at+8])
}
