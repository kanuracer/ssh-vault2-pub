package native

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"testing"
)

func TestBuildNTLMAuthenticateComputesV2Responses(t *testing.T) {
	chal := &NTLMChallenge{Flags: ntlmNegotiateUnicode | ntlmNegotiateExtendedSessionSecurity | ntlmNegotiateTargetInfo | ntlmNegotiate128 | ntlmNegotiateKeyExch}
	copy(chal.ServerChallenge[:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	chal.TargetInfo = []byte{0, 0, 0, 0}
	clientChallenge := []byte{9, 10, 11, 12, 13, 14, 15, 16}
	auth, err := BuildNTLMAuthenticate(chal, NTLMAuthOptions{Domain: "Domain", User: "User", Password: "Password", Workstation: "SSHVAULT2", ClientChallenge: clientChallenge, Timestamp: 0x1122334455667788})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(auth.Message, []byte("NTLMSSP\x00\x03\x00\x00\x00")) {
		t.Fatalf("bad type3 header: % x", auth.Message[:16])
	}
	if len(auth.NTChallengeResponse) < 16+28 {
		t.Fatalf("NT response too short: %d", len(auth.NTChallengeResponse))
	}
	key := NTOWFv2("Password", "User", "Domain")
	mac := hmac.New(md5.New, key)
	mac.Write(chal.ServerChallenge[:])
	mac.Write(auth.NTChallengeResponse[16:])
	if !bytes.Equal(auth.NTChallengeResponse[:16], mac.Sum(nil)) {
		t.Fatal("NT proof string does not verify")
	}
	if !bytes.Equal(auth.LMChallengeResponse[16:], clientChallenge) {
		t.Fatalf("LMv2 client challenge mismatch: % x", auth.LMChallengeResponse)
	}
	if binary.LittleEndian.Uint32(auth.NTChallengeResponse[16:20]) != 0x00000101 {
		t.Fatalf("bad NTLMv2 blob signature: % x", auth.NTChallengeResponse[16:24])
	}
	for _, txt := range [][]byte{utf16leBytes("Domain"), utf16leBytes("User"), utf16leBytes("SSHVAULT2")} {
		if !bytes.Contains(auth.Message, txt) {
			t.Fatalf("type3 missing UTF16 payload % x", txt)
		}
	}
}

func TestBuildNTLMAuthenticateRejectsBadInputs(t *testing.T) {
	_, err := BuildNTLMAuthenticate(&NTLMChallenge{}, NTLMAuthOptions{User: "u", Password: "p", ClientChallenge: []byte{1}})
	if err == nil {
		t.Fatal("expected bad client challenge length error")
	}
}
