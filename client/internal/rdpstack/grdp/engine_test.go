package grdpstack

import (
	"testing"

	"github.com/example-org/ssh-vault2/internal/rdpstack"
)

func TestEngineCapabilities(t *testing.T) {
	e := New()
	if e.Name() != "grdp" { t.Fatalf("name = %q", e.Name()) }
	caps := e.Capabilities()
	if caps.Backend != "grdp" || !caps.ReconnectResize || !caps.DirtyRects || !caps.FullFrame {
		t.Fatalf("unexpected caps: %#v", caps)
	}
	if caps.DynamicResize { t.Fatalf("grdp must not claim dynamic resize") }
}

func TestOptionsToUsernameAddsDomain(t *testing.T) {
	got := userWithDomain(rdpstack.Options{Username:"alice", Domain:"ACME"})
	if got != `ACME\\alice` { t.Fatalf("domain user = %q", got) }
	got = userWithDomain(rdpstack.Options{Username:`ACME\\bob`, Domain:"OTHER"})
	if got != `ACME\\bob` { t.Fatalf("domain should not double-prefix: %q", got) }
}
