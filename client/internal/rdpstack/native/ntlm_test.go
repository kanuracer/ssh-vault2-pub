package native

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestNTOWFv2MatchesMSNLMPVector(t *testing.T) {
	got := NTOWFv2("Password", "User", "Domain")
	want, _ := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	if !bytes.Equal(got, want) {
		t.Fatalf("NTOWFv2 mismatch\ngot  %x\nwant %x", got, want)
	}
}

func TestBuildNTLMNegotiateMessage(t *testing.T) {
	msg, err := BuildNTLMNegotiate("SSHVAULT2", "DOMAIN")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(msg, []byte("NTLMSSP\x00\x01\x00\x00\x00")) {
		t.Fatalf("bad NTLM type1 header: % x", msg[:min(len(msg), 16)])
	}
	flags := binary.LittleEndian.Uint32(msg[12:16])
	for _, flag := range []uint32{ntlmNegotiateUnicode, ntlmRequestTarget, ntlmNegotiateNTLM, ntlmNegotiateExtendedSessionSecurity, ntlmNegotiateTargetInfo, ntlmNegotiate128, ntlmNegotiateKeyExch, ntlmNegotiateSign, ntlmNegotiateSeal} {
		if flags&flag == 0 {
			t.Fatalf("missing negotiate flag 0x%08x in 0x%08x", flag, flags)
		}
	}
	if !bytes.Contains(msg, []byte("DOMAIN")) || !bytes.Contains(msg, []byte("SSHVAULT2")) {
		t.Fatalf("domain/workstation payload missing: % x", msg)
	}
}

func TestParseNTLMChallengeDefensively(t *testing.T) {
	challenge := make([]byte, 56)
	copy(challenge, []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(challenge[8:12], 2)
	binary.LittleEndian.PutUint16(challenge[12:14], 6)
	binary.LittleEndian.PutUint16(challenge[14:16], 6)
	binary.LittleEndian.PutUint32(challenge[16:20], 48)
	binary.LittleEndian.PutUint32(challenge[20:24], ntlmNegotiateUnicode|ntlmNegotiateTargetInfo|ntlmNegotiateExtendedSessionSecurity)
	copy(challenge[24:32], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	binary.LittleEndian.PutUint16(challenge[40:42], 2)
	binary.LittleEndian.PutUint16(challenge[42:44], 2)
	binary.LittleEndian.PutUint32(challenge[44:48], 54)
	copy(challenge[48:], []byte("DOMAIN"))
	copy(challenge[54:], []byte{0, 0})

	got, err := ParseNTLMChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if got.Flags&ntlmNegotiateTargetInfo == 0 {
		t.Fatalf("target info flag not parsed: 0x%08x", got.Flags)
	}
	if string(got.TargetName) != "DOMAIN" {
		t.Fatalf("target mismatch: %q", got.TargetName)
	}
	if !bytes.Equal(got.ServerChallenge[:], []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("challenge mismatch: % x", got.ServerChallenge)
	}
	if len(got.TargetInfo) != 2 {
		t.Fatalf("target info mismatch: % x", got.TargetInfo)
	}

	bad := append([]byte{}, challenge...)
	binary.LittleEndian.PutUint32(bad[44:48], 9999)
	if _, err := ParseNTLMChallenge(bad); err == nil {
		t.Fatal("expected bounds error for malicious security buffer offset")
	}
}
