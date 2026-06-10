package native

import (
	"context"
	"os"
	"testing"
	"time"

	rdptls "github.com/icodeface/tls"
)

func TestCredSSPIntegrationWindows115(t *testing.T) {
	host := os.Getenv("SSH_VAULT2_RDP_TEST_HOST")
	user := os.Getenv("SSH_VAULT2_RDP_TEST_USER")
	pass := os.Getenv("SSH_VAULT2_RDP_TEST_PASSWORD")
	if host == "" || user == "" || pass == "" {
		t.Skip("set SSH_VAULT2_RDP_TEST_HOST/USER/PASSWORD for live CredSSP")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, cc, err := DialNegotiation(ctx, DialOptions{Address: host + ":3389", CookieHost: "ssh-vault2-test", TLSConfig: &rdptls.Config{InsecureSkipVerify: true, MinVersion: rdptls.VersionTLS10, MaxVersion: rdptls.VersionTLS12, PreferServerCipherSuites: true}, StartTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !cc.SelectedProtocol.NeedsCredSSP() {
		t.Fatalf("server did not require CredSSP: %+v", cc)
	}
	if err := AuthenticateCredSSPNTLMv2(ctx, conn, CredSSPOptions{Domain: os.Getenv("SSH_VAULT2_RDP_TEST_DOMAIN"), User: user, Password: pass, Workstation: "SSHVAULT2", TargetHost: host}); err != nil {
		t.Fatal(err)
	}
}
