package native

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	rdptls "github.com/icodeface/tls"
)

func TestDialNegotiatesX224WithFakeServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 512)
		n, _ := c.Read(buf)
		done <- append([]byte{}, buf[:n]...)
		confirm := []byte{0x0e, 0xd0, 0, 0, 0, 0, 0, 0x02, 0, 0x08, 0, 0x02, 0, 0, 0}
		pkt, _ := EncodeTPKT(confirm)
		_, _ = c.Write(pkt)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, cc, err := DialNegotiation(ctx, DialOptions{Address: ln.Addr().String(), CookieHost: "unit-host"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if cc.SelectedProtocol != ProtocolHybrid {
		t.Fatalf("selected protocol = %v", cc.SelectedProtocol)
	}
	seen := <-done
	if got := string(seen); !strings.Contains(got, "Cookie: mstshash=unit-host\r\n") {
		t.Fatalf("cookie missing in request: %q", got)
	}
}

func TestDialNegotiationIntegrationWindows115(t *testing.T) {
	if os.Getenv("SSH_VAULT2_RDP_TEST_HOST") == "" {
		t.Skip("set SSH_VAULT2_RDP_TEST_HOST for live RDP negotiation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addr := os.Getenv("SSH_VAULT2_RDP_TEST_HOST") + ":3389"
	conn, cc, err := DialNegotiation(ctx, DialOptions{Address: addr, CookieHost: "ssh-vault2-test", TLSConfig: &rdptls.Config{InsecureSkipVerify: true}, StartTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !cc.SelectedProtocol.NeedsTLS() {
		t.Fatalf("server did not select TLS-capable protocol: %+v", cc)
	}
	if cc.SelectedProtocol.NeedsCredSSP() && conn.TLSConn == nil {
		t.Fatal("NLA selected but TLS was not started")
	}
}
