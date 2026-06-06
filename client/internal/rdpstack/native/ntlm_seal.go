package native

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
)

type NTLMSealState struct {
	sendSeal *rc4.Cipher
	recvSeal *rc4.Cipher
	sendSign []byte
	recvSign []byte
	sendSeq  uint32
	recvSeq  uint32
}

func NewNTLMSealState(exportedSessionKey []byte, clientSide bool) *NTLMSealState {
	clientSign := ntlmMagicMD5(exportedSessionKey, "session key to client-to-server signing key magic constant\x00")
	serverSign := ntlmMagicMD5(exportedSessionKey, "session key to server-to-client signing key magic constant\x00")
	clientSealKey := ntlmMagicMD5(exportedSessionKey, "session key to client-to-server sealing key magic constant\x00")
	serverSealKey := ntlmMagicMD5(exportedSessionKey, "session key to server-to-client sealing key magic constant\x00")
	clientSeal, _ := rc4.NewCipher(clientSealKey)
	serverSeal, _ := rc4.NewCipher(serverSealKey)
	if clientSide {
		return &NTLMSealState{sendSeal: clientSeal, recvSeal: serverSeal, sendSign: clientSign, recvSign: serverSign}
	}
	return &NTLMSealState{sendSeal: serverSeal, recvSeal: clientSeal, sendSign: serverSign, recvSign: clientSign}
}

func (s *NTLMSealState) Wrap(plain []byte) ([]byte, error) {
	if s == nil || s.sendSeal == nil {
		return nil, fmt.Errorf("NTLM seal state nil")
	}
	sealed := make([]byte, len(plain))
	s.sendSeal.XORKeyStream(sealed, plain)
	sig := s.signature(s.sendSign, s.sendSeq, plain)
	sig[0] = 0x01
	s.sendSeal.XORKeyStream(sig[4:12], sig[4:12])
	binary.LittleEndian.PutUint32(sig[12:16], s.sendSeq)
	s.sendSeq++
	out := append(sig, sealed...)
	return out, nil
}

func (s *NTLMSealState) Unwrap(wrapped []byte) ([]byte, error) {
	if s == nil || s.recvSeal == nil {
		return nil, fmt.Errorf("NTLM seal state nil")
	}
	if len(wrapped) < 16 {
		return nil, fmt.Errorf("NTLM wrapped message too short: %d", len(wrapped))
	}
	sig := append([]byte{}, wrapped[:16]...)
	sealed := wrapped[16:]
	plain := make([]byte, len(sealed))
	s.recvSeal.XORKeyStream(plain, sealed)
	gotSeq := binary.LittleEndian.Uint32(sig[12:16])
	if gotSeq != s.recvSeq {
		return nil, fmt.Errorf("NTLM signature sequence %d, want %d", gotSeq, s.recvSeq)
	}
	s.recvSeal.XORKeyStream(sig[4:12], sig[4:12])
	expect := s.signature(s.recvSign, s.recvSeq, plain)
	if sig[0] != 0x01 || !bytes.Equal(sig[4:12], expect[4:12]) {
		return nil, fmt.Errorf("NTLM signature mismatch")
	}
	s.recvSeq++
	return plain, nil
}

func (s *NTLMSealState) signature(signKey []byte, seq uint32, msg []byte) []byte {
	var seqb [4]byte
	binary.LittleEndian.PutUint32(seqb[:], seq)
	mac := hmacMD5(signKey, append(seqb[:], msg...))
	sig := make([]byte, 16)
	binary.LittleEndian.PutUint32(sig[:4], 1)
	copy(sig[4:12], mac[:8])
	binary.LittleEndian.PutUint32(sig[12:16], seq)
	return sig
}

func ntlmMagicMD5(key []byte, magic string) []byte {
	h := md5.New()
	h.Write(key)
	h.Write([]byte(magic))
	return h.Sum(nil)
}
