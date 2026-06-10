package rdpstack

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestOptionsNormalize(t *testing.T) {
	o := Options{Host: " test.example ", Port: 0, Width: 100, Height: 200, ColorDepth: 0, ResizeMode: ""}.Normalize()
	if o.Host != "test.example" { t.Fatalf("host not trimmed: %q", o.Host) }
	if o.Port != 3389 { t.Fatalf("port = %d", o.Port) }
	if o.Width != 640 || o.Height != 480 { t.Fatalf("size = %dx%d", o.Width, o.Height) }
	if o.ColorDepth != 32 { t.Fatalf("depth = %d", o.ColorDepth) }
	if o.ResizeMode != ResizeReconnect { t.Fatalf("resize mode = %q", o.ResizeMode) }
}

func TestOptionsValidate(t *testing.T) {
	cases := []Options{
		{},
		{Host:"h", Username:"u"},
		{Host:"h", Password:"p"},
		{Host:"h", Port:70000, Username:"u", Password:"p"},
	}
	for _, c := range cases {
		if err := c.Normalize().Validate(); err == nil { t.Fatalf("expected validation error for %#v", c) }
	}
	if err := (Options{Host:"h", Username:"u", Password:"p"}).Normalize().Validate(); err != nil { t.Fatalf("unexpected valid error: %v", err) }
}

func TestSinkCollectsEvents(t *testing.T) {
	s := NewMemorySink()
	s.Status(Status{SessionID:"s1", State:StateConnecting})
	s.Frame(Frame{SessionID:"s1", Width:2, Height:2, Format:PixelBGRA, Data:[]byte{1,2,3,4}})
	s.Error("s1", errors.New("boom"))
	if len(s.Statuses()) != 1 || s.Statuses()[0].State != StateConnecting { t.Fatalf("bad statuses: %#v", s.Statuses()) }
	if len(s.Frames()) != 1 || s.Frames()[0].Format != PixelBGRA { t.Fatalf("bad frames: %#v", s.Frames()) }
	if len(s.Errors()) != 1 || s.Errors()[0].Err == nil { t.Fatalf("bad errors: %#v", s.Errors()) }
}

func TestUnavailableEngine(t *testing.T) {
	e := NewUnavailableEngine("x", Capabilities{Backend:"x"}, errors.New("missing"))
	if e.Name() != "x" { t.Fatalf("name = %q", e.Name()) }
	if e.Capabilities().Backend != "x" { t.Fatalf("caps = %#v", e.Capabilities()) }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := e.Connect(ctx, Options{Host:"h", Username:"u", Password:"p"}, NewMemorySink())
	if err == nil { t.Fatal("expected connect error") }
}
