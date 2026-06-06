package native

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
)

type CredSSPOptions struct {
	Domain, User, Password, Workstation string
	TargetHost                          string
}

func BuildCredSSPClientPubKeyAuth(version int, publicKey, clientNonce []byte, seal *NTLMSealState) (wrapped []byte, expectedServerPlain []byte, err error) {
	if seal == nil {
		return nil, nil, fmt.Errorf("CredSSP seal state nil")
	}
	if len(publicKey) == 0 {
		return nil, nil, fmt.Errorf("CredSSP public key empty")
	}
	plain := publicKey
	expected := publicKey
	if version >= 5 {
		if len(clientNonce) == 0 {
			return nil, nil, fmt.Errorf("CredSSP v%d requires client nonce", version)
		}
		clientHash := sha256.Sum256(append(append([]byte("CredSSP Client-To-Server Binding Hash\x00"), clientNonce...), publicKey...))
		serverHash := sha256.Sum256(append(append([]byte("CredSSP Server-To-Client Binding Hash\x00"), clientNonce...), publicKey...))
		plain = clientHash[:]
		expected = serverHash[:]
	}
	wrapped, err = seal.Wrap(plain)
	return wrapped, expected, err
}

func BuildCredSSPAuthenticateRequest(version int, authMessage, pubKeyAuth, clientNonce []byte) ([]byte, error) {
	if len(authMessage) == 0 {
		return nil, fmt.Errorf("CredSSP authenticate message empty")
	}
	if len(pubKeyAuth) == 0 {
		return nil, fmt.Errorf("CredSSP pubKeyAuth empty")
	}
	req := TSRequest{Version: version, NegoTokens: [][]byte{authMessage}, PubKeyAuth: pubKeyAuth}
	if version >= 5 {
		if len(clientNonce) != 32 {
			return nil, fmt.Errorf("CredSSP v%d requires 32-byte client nonce, got %d", version, len(clientNonce))
		}
		req.ClientNonce = clientNonce
	}
	return EncodeTSRequest(req)
}

func ReadCredSSPMessage(r io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	lnByte := header[1]
	lenBytes := []byte(nil)
	ln := int(lnByte)
	if lnByte&0x80 != 0 {
		n := int(lnByte & 0x7f)
		if n == 0 || n > 2 {
			return nil, fmt.Errorf("CredSSP DER unsupported length octets: %d", n)
		}
		lenBytes = make([]byte, n)
		if _, err := io.ReadFull(r, lenBytes); err != nil {
			return nil, err
		}
		ln = 0
		for _, b := range lenBytes {
			ln = (ln << 8) | int(b)
		}
	}
	if ln < 0 || ln > 1<<20 {
		return nil, fmt.Errorf("CredSSP DER message too large: %d", ln)
	}
	body := make([]byte, ln)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	out := append(append([]byte{}, header...), lenBytes...)
	out = append(out, body...)
	return out, nil
}

func AuthenticateCredSSPNTLMv2(ctx context.Context, c *Conn, opt CredSSPOptions) error {
	if c == nil || c.TLSConn == nil {
		return fmt.Errorf("CredSSP requires established TLS connection")
	}
	if opt.User == "" || opt.Password == "" {
		return fmt.Errorf("CredSSP user/password required")
	}
	if opt.Workstation == "" {
		opt.Workstation = "SSHVAULT2"
	}
	clientNonce := make([]byte, 32)
	if _, err := rand.Read(clientNonce); err != nil {
		return err
	}
	type1, err := BuildNTLMNegotiate("", "")
	if err != nil {
		return err
	}
	msg1, _ := EncodeTSRequest(TSRequest{Version: 6, NegoTokens: [][]byte{type1}, ClientNonce: clientNonce})
	if _, err := c.TLSConn.Write(msg1); err != nil {
		return err
	}

	msg2, err := ReadCredSSPMessage(c.TLSConn)
	if err != nil {
		return fmt.Errorf("CredSSP read challenge: %w", err)
	}
	req2, err := DecodeTSRequest(msg2)
	if err != nil {
		return err
	}
	if req2.ErrorCode != nil {
		return fmt.Errorf("CredSSP server error after type1: 0x%x", *req2.ErrorCode)
	}
	if len(req2.NegoTokens) == 0 {
		return fmt.Errorf("CredSSP server challenge missing negoToken")
	}
	if os.Getenv("SSH_VAULT2_RDP_DEBUG") != "" {
		prefix := req2.NegoTokens[0]
		if len(prefix) > 16 {
			prefix = prefix[:16]
		}
		fmt.Fprintf(os.Stderr, "credssp debug: req2 version=%d token_len=%d token_prefix=%x\n", req2.Version, len(req2.NegoTokens[0]), prefix)
	}
	ntlmChallengeToken := req2.NegoTokens[0]
	if !bytes.HasPrefix(ntlmChallengeToken, []byte("NTLMSSP\x00")) {
		ntlmChallengeToken, err = DecodeSPNEGONegTokenResp(req2.NegoTokens[0])
		if err != nil {
			return fmt.Errorf("CredSSP decode SPNEGO challenge: %w", err)
		}
	}
	chal, err := ParseNTLMChallenge(ntlmChallengeToken)
	if err != nil {
		return err
	}
	if os.Getenv("SSH_VAULT2_RDP_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "credssp debug: challenge flags=0x%08x targetInfo=%d timestamp=0x%x targetInfoHex=%x\n", chal.Flags, len(chal.TargetInfo), chal.Timestamp, chal.TargetInfo)
	}
	domain := opt.Domain
	spn := ""
	if strings.TrimSpace(opt.TargetHost) != "" {
		spn = "TERMSRV/" + strings.TrimSpace(opt.TargetHost)
	}
	auth, err := BuildNTLMAuthenticate(chal, NTLMAuthOptions{Domain: domain, User: opt.User, Password: opt.Password, Workstation: opt.Workstation, Type1Message: type1, Type2Message: ntlmChallengeToken, ServicePrincipalName: spn})
	if err != nil {
		return err
	}
	sealClient := NewNTLMSealState(auth.ExportedSessionKey, true)
	state := c.TLSConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("CredSSP TLS peer certificate missing")
	}
	pub, err := CredSSPPublicKeyBytes(state.PeerCertificates[0].PublicKey, state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	if err != nil {
		return err
	}
	version := req2.Version
	if version == 0 {
		version = 6
	}
	pubAuth, expectedServer, err := BuildCredSSPClientPubKeyAuth(version, pub, clientNonce, sealClient)
	if err != nil {
		return err
	}
	msg3, err := BuildCredSSPAuthenticateRequest(version, auth.Message, pubAuth, clientNonce)
	if err != nil {
		return err
	}
	if os.Getenv("SSH_VAULT2_RDP_DEBUG") != "" {
		debugReq3, debugErr := DecodeTSRequest(msg3)
		if debugErr == nil {
			fmt.Fprintf(os.Stderr, "credssp debug: msg3 version=%d type3_len=%d pubKeyAuth_len=%d clientNonce_len=%d\n", version, len(auth.Message), len(pubAuth), len(debugReq3.ClientNonce))
		}
	}
	if _, err := c.TLSConn.Write(msg3); err != nil {
		return err
	}

	msg4, err := ReadCredSSPMessage(c.TLSConn)
	if err != nil {
		return fmt.Errorf("CredSSP read pubKeyAuth: %w", err)
	}
	req4, err := DecodeTSRequest(msg4)
	if err != nil {
		return err
	}
	if req4.ErrorCode != nil {
		return fmt.Errorf("CredSSP server error after type3: 0x%x", *req4.ErrorCode)
	}
	if len(req4.PubKeyAuth) > 0 {
		plain, err := sealClient.Unwrap(req4.PubKeyAuth)
		if err != nil {
			return fmt.Errorf("CredSSP unwrap server pubKeyAuth: %w", err)
		}
		if version >= 5 && string(plain) != string(expectedServer) {
			return fmt.Errorf("CredSSP server binding hash mismatch")
		}
		if version < 5 && (len(plain) == 0 || plain[0] != pub[0]+1) {
			return fmt.Errorf("CredSSP legacy pubKeyAuth mismatch")
		}
	}
	pwd, err := EncodeTSPasswordCredentials(opt.Domain, opt.User, opt.Password)
	if err != nil {
		return err
	}
	creds, err := EncodeTSCredentials(1, pwd)
	if err != nil {
		return err
	}
	wrappedCreds, err := sealClient.Wrap(creds)
	if err != nil {
		return err
	}
	msg5, _ := EncodeTSRequest(TSRequest{Version: version, AuthInfo: wrappedCreds})
	if _, err := c.TLSConn.Write(msg5); err != nil {
		return err
	}
	return nil
}
