package client

import "testing"

func TestRdpClientQueuesCallbacksBeforeLogin(t *testing.T) {
	c := newRdpClient(NewSetting())
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("pre-login callback registration panicked: %v", r)
		}
	}()
	c.On("update", func(interface{}) {})
	c.On("ready", func() {})
	if got := len(c.pending); got != 2 {
		t.Fatalf("pending handlers = %d, want 2", got)
	}
}
