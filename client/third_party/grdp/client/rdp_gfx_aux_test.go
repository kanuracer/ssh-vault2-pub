package client

import "testing"

func TestRdpClientRegistersAuxiliaryGraphicsDynamicChannels(t *testing.T) {
	c := &RdpClient{}
	d := c.newGraphicsDrdynvc()
	for _, name := range []string{
		"Microsoft::Windows::RDS::Graphics",
		"Microsoft::Windows::RDS::CoreInput",
		"Microsoft::Windows::RDS::MouseCursor",
	} {
		if _, ok := d.State().OpenChannels[0]; ok {
			t.Fatalf("unexpected open state before create")
		}
		if !d.HasDynamic(name) {
			t.Fatalf("dynamic channel %q not registered", name)
		}
	}
}
