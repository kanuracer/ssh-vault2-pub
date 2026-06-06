package native

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

type NTLMAuthOptions struct {
	Domain, User, Password, Workstation string
	ClientChallenge                     []byte
	Timestamp                           uint64
	Type1Message                        []byte
	Type2Message                        []byte
	ExportedSessionKey                  []byte
	ServicePrincipalName                string
}

type NTLMAuthResult struct {
	Message                   []byte
	LMChallengeResponse       []byte
	NTChallengeResponse       []byte
	SessionBaseKey            []byte
	ExportedSessionKey        []byte
	EncryptedRandomSessionKey []byte
}

func BuildNTLMAuthenticate(chal *NTLMChallenge, opt NTLMAuthOptions) (*NTLMAuthResult, error) {
	if chal == nil {
		return nil, fmt.Errorf("NTLM challenge nil")
	}
	clientChallenge := opt.ClientChallenge
	if len(clientChallenge) == 0 {
		clientChallenge = make([]byte, 8)
		if _, err := rand.Read(clientChallenge); err != nil {
			return nil, err
		}
	}
	if len(clientChallenge) != 8 {
		return nil, fmt.Errorf("NTLM client challenge must be 8 bytes, got %d", len(clientChallenge))
	}
	if opt.Timestamp == 0 {
		opt.Timestamp = chal.Timestamp
	}
	if opt.Timestamp == 0 {
		opt.Timestamp = ntTime(time.Now())
	}
	key := NTOWFv2(opt.Password, opt.User, opt.Domain)

	targetInfo := chal.TargetInfo
	withMIC := len(opt.Type1Message) > 0 && len(opt.Type2Message) > 0
	if withMIC {
		targetInfo = ntlmAuthenticateTargetInfo(chal.TargetInfo, opt.ServicePrincipalName, true)
	}
	blob := buildNTLMv2Blob(opt.Timestamp, clientChallenge, targetInfo)
	ntProof := hmacMD5(key, append(chal.ServerChallenge[:], blob...))
	ntResp := append(append([]byte{}, ntProof...), blob...)
	lmProof := hmacMD5(key, append(chal.ServerChallenge[:], clientChallenge...))
	lmResp := append(append([]byte{}, lmProof...), clientChallenge...)
	sessionBaseKey := hmacMD5(key, ntProof)

	exportedSessionKey := opt.ExportedSessionKey
	if len(exportedSessionKey) == 0 {
		exportedSessionKey = make([]byte, 16)
		if _, err := rand.Read(exportedSessionKey); err != nil {
			return nil, err
		}
	}
	if len(exportedSessionKey) != 16 {
		return nil, fmt.Errorf("NTLM exported session key must be 16 bytes, got %d", len(exportedSessionKey))
	}
	encryptedSessionKey := make([]byte, len(exportedSessionKey))
	rc, err := rc4.NewCipher(sessionBaseKey)
	if err != nil {
		return nil, err
	}
	rc.XORKeyStream(encryptedSessionKey, exportedSessionKey)

	domain := utf16leBytes(opt.Domain)
	user := utf16leBytes(opt.User)
	workstation := utf16leBytes(strings.ToUpper(opt.Workstation))
	flags := chal.Flags
	flags &^= ntlmTargetTypeDomain | ntlmTargetTypeServer
	flags |= ntlmNegotiateKeyExch | ntlmNegotiateUnicode | ntlmRequestTarget | ntlmNegotiateNTLM | ntlmNegotiateExtendedSessionSecurity | ntlmNegotiateAlwaysSign | ntlmNegotiateSign | ntlmNegotiateSeal | ntlmNegotiateTargetInfo | ntlmNegotiate128 | ntlmNegotiateVersion
	if strings.TrimSpace(opt.Domain) != "" {
		flags |= ntlmNegotiateDomainSupplied
	}
	if strings.TrimSpace(opt.Workstation) != "" {
		flags |= ntlmNegotiateWorkstationSupplied
	}

	payloadOffset := 88
	payload := bytes.Buffer{}
	payload.Write(domain)
	payload.Write(user)
	payload.Write(workstation)
	payload.Write(lmResp)
	payload.Write(ntResp)
	payload.Write(encryptedSessionKey)
	msg := make([]byte, payloadOffset+payload.Len())
	copy(msg, []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 3)
	off := uint32(payloadOffset)
	putSecBufferAt(msg, 28, uint16(len(domain)), off)
	off += uint32(len(domain))
	putSecBufferAt(msg, 36, uint16(len(user)), off)
	off += uint32(len(user))
	putSecBufferAt(msg, 44, uint16(len(workstation)), off)
	off += uint32(len(workstation))
	putSecBufferAt(msg, 12, uint16(len(lmResp)), off)
	off += uint32(len(lmResp))
	putSecBufferAt(msg, 20, uint16(len(ntResp)), off)
	off += uint32(len(ntResp))
	putSecBufferAt(msg, 52, uint16(len(encryptedSessionKey)), off)
	binary.LittleEndian.PutUint32(msg[60:64], flags)
	copy(msg[64:72], ntlmVersionBytes())
	// bytes 72..88 are MIC, initially zero for MIC calculation.
	copy(msg[payloadOffset:], payload.Bytes())
	if len(opt.Type1Message) > 0 && len(opt.Type2Message) > 0 {
		micInput := bytes.Buffer{}
		micInput.Write(opt.Type1Message)
		micInput.Write(opt.Type2Message)
		micInput.Write(msg)
		copy(msg[72:88], hmacMD5(exportedSessionKey, micInput.Bytes())[:16])
	}
	return &NTLMAuthResult{Message: msg, LMChallengeResponse: lmResp, NTChallengeResponse: ntResp, SessionBaseKey: sessionBaseKey, ExportedSessionKey: exportedSessionKey, EncryptedRandomSessionKey: encryptedSessionKey}, nil
}

func buildNTLMv2Blob(timestamp uint64, clientChallenge, targetInfo []byte) []byte {
	var b bytes.Buffer
	le32(&b, 0x00000101)
	le32(&b, 0)
	var ts [8]byte
	binary.LittleEndian.PutUint64(ts[:], timestamp)
	b.Write(ts[:])
	b.Write(clientChallenge)
	le32(&b, 0)
	b.Write(targetInfo)
	if !ntlmTargetInfoHasEOL(targetInfo) {
		le32(&b, 0)
	}
	return b.Bytes()
}

func ntlmTargetInfoHasEOL(info []byte) bool {
	for i := 0; i+4 <= len(info); {
		id := binary.LittleEndian.Uint16(info[i : i+2])
		ln := int(binary.LittleEndian.Uint16(info[i+2 : i+4]))
		if id == msvAvEOL {
			return true
		}
		value := i + 4
		if value+ln > len(info) {
			return false
		}
		i = value + ln
	}
	return false
}

func putSecBufferAt(msg []byte, at int, ln uint16, off uint32) {
	binary.LittleEndian.PutUint16(msg[at:at+2], ln)
	binary.LittleEndian.PutUint16(msg[at+2:at+4], ln)
	binary.LittleEndian.PutUint32(msg[at+4:at+8], off)
}

func hmacMD5(key, msg []byte) []byte { h := hmac.New(md5.New, key); h.Write(msg); return h.Sum(nil) }
func ntTime(t time.Time) uint64      { return uint64(t.UnixNano()/100) + 116444736000000000 }
