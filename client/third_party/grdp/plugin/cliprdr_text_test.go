package plugin

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"
)

type captureSender struct{ packets [][]byte }

func (c *captureSender) SendToChannel(channel string, s []byte) (int, error) {
	if channel != CLIPRDR_SVC_CHANNEL_NAME {
		panic(channel)
	}
	c.packets = append(c.packets, append([]byte(nil), s...))
	return len(s), nil
}

func clipPacket(msgType uint16, flags uint16, payload []byte) []byte {
	b := &bytes.Buffer{}
	_ = binary.Write(b, binary.LittleEndian, msgType)
	_ = binary.Write(b, binary.LittleEndian, flags)
	_ = binary.Write(b, binary.LittleEndian, uint32(len(payload)))
	b.Write(payload)
	return b.Bytes()
}

func packetOf(t *testing.T, packets [][]byte, msgType uint16) []byte {
	t.Helper()
	for _, packet := range packets {
		if len(packet) >= 8 && binary.LittleEndian.Uint16(packet[0:2]) == msgType {
			return packet
		}
	}
	t.Fatalf("packet type %#x not found in %d packets", msgType, len(packets))
	return nil
}

func utf16Bytes(s string) []byte {
	b := &bytes.Buffer{}
	for _, unit := range utf16.Encode([]rune(s)) {
		_ = binary.Write(b, binary.LittleEndian, unit)
	}
	return b.Bytes()
}

func TestCliprdrClientSendsCapabilitiesAndLongFormatListOnMonitorReady(t *testing.T) {
	cap := &captureSender{}
	cli := NewCliprdrTextClient(func() string { return "hello" })
	cli.Sender(cap)
	cli.Process(clipPacket(cliprdrMonitorReady, 0, nil))
	if len(cap.packets) != 2 {
		t.Fatalf("packets=%d", len(cap.packets))
	}
	caps := packetOf(t, cap.packets, cliprdrCaps)
	if binary.LittleEndian.Uint16(caps[8:10]) != 1 || binary.LittleEndian.Uint32(caps[16:20]) != cliprdrCapsVersion2 {
		t.Fatalf("bad caps payload=%v", caps[8:])
	}
	formats := packetOf(t, cap.packets, cliprdrFormatList)
	if binary.LittleEndian.Uint32(formats[8:12]) != cliprdrCFUnicodeText {
		t.Fatalf("format=%d", binary.LittleEndian.Uint32(formats[8:12]))
	}
	st := cli.State()
	if !st.MonitorReady || !st.LocalFormatsSent || st.LocalFormatsAcked || !st.LocalFormatsDirty || !st.UseLongFormatNames {
		t.Fatalf("state=%+v", st)
	}
}

func TestCliprdrRefreshWaitsForMonitorReadyThenAdvertisesDirtyClipboard(t *testing.T) {
	cap := &captureSender{}
	cli := NewCliprdrTextClient(func() string { return "hello" })
	cli.Sender(cap)
	cli.RefreshLocalClipboard()
	if len(cap.packets) != 0 {
		t.Fatalf("refresh before MonitorReady sent packets=%d", len(cap.packets))
	}
	if !cli.State().LocalFormatsDirty {
		t.Fatalf("refresh should mark local formats dirty")
	}
	cli.Process(clipPacket(cliprdrMonitorReady, 0, nil))
	packetOf(t, cap.packets, cliprdrFormatList)
	cli.Process(clipPacket(cliprdrFormatListResponse, cliprdrResponseOK, nil))
	st := cli.State()
	if !st.LocalFormatsAcked || st.LocalFormatsDirty {
		t.Fatalf("ack state=%+v", st)
	}
}

func TestCliprdrClientAnswersUnicodeTextRequest(t *testing.T) {
	cap := &captureSender{}
	cli := NewCliprdrTextClient(func() string { return "Miez" })
	cli.Sender(cap)
	req := make([]byte, 4)
	binary.LittleEndian.PutUint32(req, cliprdrCFUnicodeText)
	cli.Process(clipPacket(cliprdrFormatDataRequest, 0, req))
	payload := packetOf(t, cap.packets, cliprdrFormatDataResponse)
	if binary.LittleEndian.Uint16(payload[2:4]) != cliprdrResponseOK {
		t.Fatalf("flags=%#x", binary.LittleEndian.Uint16(payload[2:4]))
	}
	data := payload[8:]
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[i*2 : i*2+2])
	}
	text := string(utf16.Decode(units))
	if text != "Miez\x00" {
		t.Fatalf("text=%q", text)
	}
}

func TestCliprdrClientAdvertisesFilesWhenProviderHasFiles(t *testing.T) {
	cap := &captureSender{}
	cli := NewCliprdrTextClient(func() string { return "hello" })
	cli.SetFileProvider(func() []ClipboardFile { return []ClipboardFile{{Name: "a.txt", Data: []byte("abc")}} })
	cli.Sender(cap)
	cli.Process(clipPacket(cliprdrMonitorReady, 0, nil))
	payload := packetOf(t, cap.packets, cliprdrFormatList)
	if !bytes.Contains(payload[8:], utf16Bytes("FileGroupDescriptorW\x00")) || !bytes.Contains(payload[8:], utf16Bytes("FileContents\x00")) {
		t.Fatalf("file formats missing from long format list: %q", payload[8:])
	}
}

func TestCliprdrClientAnswersFileGroupDescriptorW(t *testing.T) {
	cap := &captureSender{}
	cli := NewCliprdrTextClient(func() string { return "" })
	cli.SetFileProvider(func() []ClipboardFile { return []ClipboardFile{{Name: "a.txt", Data: []byte("abc")}} })
	cli.Sender(cap)
	req := make([]byte, 4)
	binary.LittleEndian.PutUint32(req, cliprdrFileGroupDescriptorW)
	cli.Process(clipPacket(cliprdrFormatDataRequest, 0, req))
	payload := packetOf(t, cap.packets, cliprdrFormatDataResponse)
	if binary.LittleEndian.Uint16(payload[2:4]) != cliprdrResponseOK {
		t.Fatalf("bad response header: %v", payload[:8])
	}
	data := payload[8:]
	if len(data) != 4+592 || binary.LittleEndian.Uint32(data[:4]) != 1 {
		t.Fatalf("descriptor len/count = %d/%d", len(data), binary.LittleEndian.Uint32(data[:4]))
	}
	if binary.LittleEndian.Uint32(data[4+64:4+68]) != 0 {
		t.Fatalf("file size high must be at FILEDESCRIPTORW offset 64")
	}
	if binary.LittleEndian.Uint32(data[4+68:4+72]) != 3 {
		t.Fatalf("file size low must be at FILEDESCRIPTORW offset 68")
	}
	nameBytes := data[4+72 : 4+72+10]
	units := make([]uint16, len(nameBytes)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(nameBytes[i*2 : i*2+2])
	}
	if got := string(utf16.Decode(units)); got != "a.txt" {
		t.Fatalf("name prefix=%q", got)
	}
}

func descriptorName(data []byte, index int) string {
	off := 4 + index*592 + 72
	units := make([]uint16, 0, 260)
	for i := 0; i < 260; i++ {
		unit := binary.LittleEndian.Uint16(data[off+i*2 : off+i*2+2])
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	return string(utf16.Decode(units))
}

func descriptorAttributes(data []byte, index int) uint32 {
	off := 4 + index*592 + 36
	return binary.LittleEndian.Uint32(data[off : off+4])
}

func TestCliprdrFileGroupDescriptorPreservesRelativePath(t *testing.T) {
	data := fileGroupDescriptorW([]ClipboardFile{{Name: "folder/sub/demo.txt", Data: []byte("abc")}})
	if got := descriptorName(data, 0); got != `folder\sub\demo.txt` {
		t.Fatalf("descriptor name=%q", got)
	}
	if got := descriptorAttributes(data, 0); got != 0x80 {
		t.Fatalf("file attrs=%#x, want FILE_ATTRIBUTE_NORMAL", got)
	}
}

func TestCliprdrRejectsUnsafeClipboardRelativePaths(t *testing.T) {
	for _, name := range []string{"../bad.txt", "folder/../../bad.txt", "/absolute.txt", `C:	mp\bad.txt`, `\\server\share\bad.txt`} {
		if cleanClipboardFileName(name) != "" {
			t.Fatalf("unsafe name accepted: %q -> %q", name, cleanClipboardFileName(name))
		}
	}
}

func TestCliprdrClientAnswersFileContentsSizeAndRange(t *testing.T) {
	cap := &captureSender{}
	cli := NewCliprdrTextClient(func() string { return "" })
	cli.SetFileProvider(func() []ClipboardFile { return []ClipboardFile{{Name: "a.txt", Data: []byte("abcdef")}} })
	cli.Sender(cap)
	req := make([]byte, 24)
	binary.LittleEndian.PutUint32(req[0:4], 7)
	binary.LittleEndian.PutUint32(req[4:8], 0)
	binary.LittleEndian.PutUint32(req[8:12], cliprdrFileContentsSize)
	cli.Process(clipPacket(cliprdrFileContentsRequest, 0, req))
	payload := packetOf(t, cap.packets, cliprdrFileContentsResponse)
	if binary.LittleEndian.Uint64(payload[12:20]) != 6 {
		t.Fatalf("size response=%v", payload)
	}
	cap.packets = nil
	binary.LittleEndian.PutUint32(req[8:12], cliprdrFileContentsRange)
	binary.LittleEndian.PutUint32(req[12:16], 2)
	binary.LittleEndian.PutUint32(req[20:24], 3)
	cli.Process(clipPacket(cliprdrFileContentsRequest, 0, req))
	payload = packetOf(t, cap.packets, cliprdrFileContentsResponse)
	if string(payload[12:]) != "cde" {
		t.Fatalf("range=%q", payload[12:])
	}
}

func TestCliprdrClientReportsFileContentsServedOnlyForCompletedRange(t *testing.T) {
	cap := &captureSender{}
	cli := NewCliprdrTextClient(func() string { return "" })
	cli.SetFileProvider(func() []ClipboardFile { return []ClipboardFile{{Name: "a.txt", Data: []byte("abcdef")}} })
	var calls []string
	cli.SetFileServedCallback(func(index int, complete bool) { calls = append(calls, fmt.Sprintf("%d:%v", index, complete)) })
	cli.Sender(cap)
	req := make([]byte, 24)
	binary.LittleEndian.PutUint32(req[0:4], 7)
	binary.LittleEndian.PutUint32(req[4:8], 0)
	binary.LittleEndian.PutUint32(req[8:12], cliprdrFileContentsSize)
	cli.Process(clipPacket(cliprdrFileContentsRequest, 0, req))
	if len(calls) != 0 {
		t.Fatalf("size probe should not consume file bytes, calls=%v", calls)
	}
	binary.LittleEndian.PutUint32(req[8:12], cliprdrFileContentsRange)
	binary.LittleEndian.PutUint32(req[12:16], 0)
	binary.LittleEndian.PutUint32(req[20:24], 3)
	cli.Process(clipPacket(cliprdrFileContentsRequest, 0, req))
	binary.LittleEndian.PutUint32(req[12:16], 3)
	binary.LittleEndian.PutUint32(req[20:24], 3)
	cli.Process(clipPacket(cliprdrFileContentsRequest, 0, req))
	want := []string{"0:false", "0:true"}
	if strings.Join(calls, ",") != strings.Join(want, ",") {
		t.Fatalf("served calls=%v, want %v", calls, want)
	}
}
