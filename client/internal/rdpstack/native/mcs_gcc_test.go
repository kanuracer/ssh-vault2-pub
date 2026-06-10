package native

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEncodeBERDomainParameters(t *testing.T) {
	got := EncodeBERDomainParameters(DomainParameters{
		MaxChannelIDs: 34, MaxUserIDs: 2, MaxTokenIDs: 0, NumPriorities: 1,
		MinThroughput: 0, MaxHeight: 1, MaxMCSPDUSize: 0xffff, ProtocolVersion: 2,
	})
	wantPrefix := []byte{0x30, 0x19, 0x02, 0x01, 0x22, 0x02, 0x01, 0x02}
	if !bytes.HasPrefix(got, wantPrefix) {
		t.Fatalf("domain params prefix mismatch\ngot  % x\nwant % x", got[:min(len(got), len(wantPrefix))], wantPrefix)
	}
	if !bytes.Contains(got, []byte{0x02, 0x02, 0xff, 0xff}) {
		t.Fatalf("max MCS PDU size not encoded as BER integer: % x", got)
	}
}

func TestEncodeGCCConferenceCreateRequestMinimalBlocks(t *testing.T) {
	got, err := EncodeGCCConferenceCreateRequest(GCCClientSettings{
		Width: 1920, Height: 1080, ColorDepth: 32, ClientName: "ssh-vault2-test", SelectedProtocol: ProtocolHybrid,
		Channels: []GCCChannel{{Name: "rdpsnd", Options: ChannelOptionInitialized | ChannelOptionEncryptRDP | ChannelOptionShowProtocol}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 64 {
		t.Fatalf("GCC request too short: %d", len(got))
	}
	for _, needle := range [][]byte{
		{0x05, 0x00, 0x14, 0x7c, 0x00, 0x01}, // T.124 object id
		[]byte("Duca"),
		{0x01, 0xc0}, // CS_CORE little-endian
		{0x02, 0xc0}, // CS_SECURITY
		{0x03, 0xc0}, // CS_NET
		[]byte("rdpsnd\x00\x00"),
	} {
		if !bytes.Contains(got, needle) {
			t.Fatalf("GCC request missing % x in\n% x", needle, got)
		}
	}
	if bytes.Contains(got, []byte("Microsoft::Windows::RDS::Graphics")) {
		t.Fatal("RDPEGFX must not be advertised before own drdynvc/rdpegfx stack exists")
	}
	core := findBlock(t, got, 0xc001)
	if binary.LittleEndian.Uint16(core[8:10]) != 1920 || binary.LittleEndian.Uint16(core[10:12]) != 1080 {
		t.Fatalf("desktop geometry not encoded in CS_CORE: % x", core[:16])
	}
}

func TestEncodeMCSConnectInitialWrapsGCC(t *testing.T) {
	gcc, err := EncodeGCCConferenceCreateRequest(GCCClientSettings{Width: 1280, Height: 800, ClientName: "sshv", SelectedProtocol: ProtocolHybrid})
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeMCSConnectInitial(gcc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(got, []byte{0x7f, 0x65}) {
		t.Fatalf("ConnectInitial must start with BER application tag 101, got % x", got[:min(4, len(got))])
	}
	if !bytes.Contains(got, gcc) {
		t.Fatal("MCS ConnectInitial did not include GCC user data")
	}
	if !bytes.Contains(got, []byte{0x04, 0x01, 0x01, 0x04, 0x01, 0x01, 0x01, 0x01, 0xff}) {
		t.Fatalf("ConnectInitial missing selectors/upward flag: % x", got[:min(32, len(got))])
	}
}

func findBlock(t *testing.T, p []byte, typ uint16) []byte {
	t.Helper()
	needle := []byte{byte(typ), byte(typ >> 8)}
	for off := 0; off < len(p); {
		i := bytes.Index(p[off:], needle)
		if i < 0 {
			break
		}
		i += off
		if i+4 <= len(p) {
			ln := int(binary.LittleEndian.Uint16(p[i+2 : i+4]))
			if ln >= 4 && i+ln <= len(p) {
				return p[i : i+ln]
			}
		}
		off = i + 1
	}
	t.Fatalf("block 0x%04x missing", typ)
	return nil
}
