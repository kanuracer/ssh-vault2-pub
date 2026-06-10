package gcc

import (
	"testing"

	"github.com/tomatome/grdp/plugin"
)

func TestClientCoreDataDoesNotAdvertiseDynvcGfxByDefault(t *testing.T) {
	t.Setenv("SSH_VAULT2_EXPERIMENTAL_RDPGFX", "")
	core := NewClientCoreData()
	if core.EarlyCapabilityFlags&RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL != 0 {
		t.Fatalf("EarlyCapabilityFlags=0x%04x, did not expect DYNVC_GFX_PROTOCOL by default", core.EarlyCapabilityFlags)
	}
}

func TestClientNetworkDataDoesNotIncludeDrdynvcByDefault(t *testing.T) {
	t.Setenv("SSH_VAULT2_EXPERIMENTAL_RDPGFX", "")
	net := NewClientNetworkData()
	for _, ch := range net.ChannelDefArray {
		if ch.Name == plugin.DRDYNVC_SVC_CHANNEL_NAME {
			t.Fatalf("unexpected default drdynvc channel: %+v", net.ChannelDefArray)
		}
	}
	if net.ChannelCount != uint32(len(net.ChannelDefArray)) {
		t.Fatalf("ChannelCount=%d len=%d", net.ChannelCount, len(net.ChannelDefArray))
	}
}

func TestClientCoreDataAdvertisesDynvcGfxSupportWhenExperimental(t *testing.T) {
	t.Setenv("SSH_VAULT2_EXPERIMENTAL_RDPGFX", "1")
	core := NewClientCoreData()
	if core.EarlyCapabilityFlags&RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL == 0 {
		t.Fatalf("EarlyCapabilityFlags=0x%04x, want DYNVC_GFX_PROTOCOL bit", core.EarlyCapabilityFlags)
	}
}

func TestClientNetworkDataIncludesDrdynvcStaticChannelWhenExperimental(t *testing.T) {
	t.Setenv("SSH_VAULT2_EXPERIMENTAL_RDPGFX", "1")
	net := NewClientNetworkData()
	found := false
	for _, ch := range net.ChannelDefArray {
		if ch.Name == plugin.DRDYNVC_SVC_CHANNEL_NAME {
			found = true
			if ch.Options&CHANNEL_OPTION_COMPRESS_RDP == 0 {
				t.Fatalf("drdynvc options=0x%08x, want compression", ch.Options)
			}
		}
	}
	if !found {
		t.Fatalf("channels=%+v, missing drdynvc", net.ChannelDefArray)
	}
	if net.ChannelCount != uint32(len(net.ChannelDefArray)) {
		t.Fatalf("ChannelCount=%d len=%d", net.ChannelCount, len(net.ChannelDefArray))
	}
}
