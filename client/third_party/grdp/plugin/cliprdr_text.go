package plugin

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path"
	"strings"
	"sync"
	"unicode/utf16"

	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
)

const (
	cliprdrMonitorReady         uint16 = 0x0001
	cliprdrFormatList           uint16 = 0x0002
	cliprdrFormatListResponse   uint16 = 0x0003
	cliprdrFormatDataRequest    uint16 = 0x0004
	cliprdrFormatDataResponse   uint16 = 0x0005
	cliprdrCaps                 uint16 = 0x0007
	cliprdrFileContentsRequest  uint16 = 0x0008
	cliprdrFileContentsResponse uint16 = 0x0009

	cliprdrResponseOK   uint16 = 0x0001
	cliprdrResponseFail uint16 = 0x0002

	cliprdrCFUnicodeText uint32 = 13

	cliprdrFileGroupDescriptorW uint32 = 0xC0A1
	cliprdrFileContents         uint32 = 0xC0A2

	cliprdrFileContentsSize  uint32 = 0x00000001
	cliprdrFileContentsRange uint32 = 0x00000002

	cliprdrFDAttributes uint32 = 0x00000004
	cliprdrFDFileSize   uint32 = 0x00000040
	cliprdrFDWriteTime  uint32 = 0x00000020

	cliprdrCapstypeGeneral     uint16 = 0x0001
	cliprdrCapsVersion2        uint32 = 0x00000002
	cliprdrUseLongFormatNames  uint32 = 0x00000002
	cliprdrStreamFileclip      uint32 = 0x00000004
	cliprdrFileclipNoFilePaths uint32 = 0x00000008
)

// ClipboardTextProvider returns current local text for remote paste requests.
type ClipboardTextProvider func() string

// ClipboardFile is a single in-memory file offered to the remote clipboard.
type ClipboardFile struct {
	Name        string
	Data        []byte
	IsDirectory bool
}

// ClipboardFileProvider returns current local files for remote paste requests.
type ClipboardFileProvider func() []ClipboardFile

// ClipboardFileServedCallback reports that the remote side consumed file bytes.
// complete is true when the served range reached EOF for that file index.
type ClipboardFileServedCallback func(index int, complete bool)

// CliprdrState exposes the negotiated clipboard-channel state for regression tests.
type CliprdrState struct {
	MonitorReady        bool
	CapabilitiesSeen    bool
	LocalFormatsDirty   bool
	LocalFormatsSent    bool
	LocalFormatsAcked   bool
	UseLongFormatNames  bool
	ServerFormatListSeq uint64
}

// CliprdrTextClient implements local-to-remote clipboard paste with real cliprdr state:
// capabilities, MonitorReady gating, format-list acks, local refresh/dirty state,
// CF_UNICODETEXT, and in-memory FileGroupDescriptorW/FileContents.
type CliprdrTextClient struct {
	mu           sync.Mutex
	sender       core.ChannelSender
	provider     ClipboardTextProvider
	fileProvider ClipboardFileProvider
	fileServed   ClipboardFileServedCallback
	state        CliprdrState
}

func NewCliprdrTextClient(provider ClipboardTextProvider) *CliprdrTextClient {
	return &CliprdrTextClient{provider: provider, state: CliprdrState{UseLongFormatNames: true}}
}

func (c *CliprdrTextClient) SetFileProvider(provider ClipboardFileProvider) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fileProvider = provider
}

func (c *CliprdrTextClient) SetFileServedCallback(callback ClipboardFileServedCallback) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fileServed = callback
}

func (c *CliprdrTextClient) State() CliprdrState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *CliprdrTextClient) GetType() (string, uint32) {
	return CLIPRDR_SVC_CHANNEL_NAME, uint32(StaticVirtualChannels[CLIPRDR_SVC_CHANNEL_NAME])
}

func (c *CliprdrTextClient) Sender(sender core.ChannelSender) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sender = sender
}

func (c *CliprdrTextClient) AnnounceFormatList() {
	c.RefreshLocalClipboard()
}

func (c *CliprdrTextClient) RefreshLocalClipboard() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state.LocalFormatsDirty = true
	c.state.LocalFormatsAcked = false
	if !c.state.MonitorReady || c.sender == nil {
		return
	}
	c.sendFormatListLocked()
}

func (c *CliprdrTextClient) Process(s []byte) {
	if len(s) < 8 {
		return
	}
	r := bytes.NewReader(s)
	msgType := readU16(r)
	msgFlags := readU16(r)
	dataLen := readU32(r)
	if int(dataLen) > r.Len() {
		return
	}
	switch msgType {
	case cliprdrMonitorReady:
		c.mu.Lock()
		c.state.MonitorReady = true
		c.state.LocalFormatsDirty = true
		c.sendClientCapabilitiesLocked()
		c.sendFormatListLocked()
		c.mu.Unlock()
	case cliprdrCaps:
		c.mu.Lock()
		c.state.CapabilitiesSeen = true
		c.mu.Unlock()
	case cliprdrFormatList:
		c.mu.Lock()
		c.state.ServerFormatListSeq++
		c.sendFormatListResponseLocked()
		if c.state.LocalFormatsDirty || !c.state.LocalFormatsSent {
			c.sendFormatListLocked()
		}
		c.mu.Unlock()
	case cliprdrFormatListResponse:
		c.mu.Lock()
		if msgFlags == cliprdrResponseOK {
			c.state.LocalFormatsAcked = true
			c.state.LocalFormatsDirty = false
		} else {
			c.state.LocalFormatsAcked = false
		}
		c.mu.Unlock()
	case cliprdrFormatDataRequest:
		formatID := uint32(0)
		if r.Len() >= 4 {
			formatID = readU32(r)
		}
		c.sendFormatDataResponse(formatID)
	case cliprdrFileContentsRequest:
		payload := make([]byte, int(dataLen))
		_, _ = r.Read(payload)
		c.sendFileContentsResponse(payload)
	default:
		glog.Debugf("cliprdr: ignore msgType=0x%04x len=%d", msgType, dataLen)
	}
}

func (c *CliprdrTextClient) sendClientCapabilitiesLocked() {
	b := &bytes.Buffer{}
	writeU16(b, 1) // cCapabilitiesSets
	writeU16(b, 0) // pad
	writeU16(b, cliprdrCapstypeGeneral)
	writeU16(b, 12) // capabilitySetLength
	writeU32(b, cliprdrCapsVersion2)
	writeU32(b, cliprdrUseLongFormatNames|cliprdrStreamFileclip|cliprdrFileclipNoFilePaths)
	c.sendLocked(cliprdrCaps, 0, b.Bytes())
}

func (c *CliprdrTextClient) sendFormatListResponseLocked() {
	c.sendLocked(cliprdrFormatListResponse, cliprdrResponseOK, nil)
}

func (c *CliprdrTextClient) sendFormatListLocked() {
	b := &bytes.Buffer{}
	if c.state.UseLongFormatNames {
		writeFormatNameLong(b, cliprdrCFUnicodeText, "")
		if len(c.filesLocked()) > 0 {
			writeFormatNameLong(b, cliprdrFileGroupDescriptorW, "FileGroupDescriptorW")
			writeFormatNameLong(b, cliprdrFileContents, "FileContents")
		}
	} else {
		writeFormatNameShort(b, cliprdrCFUnicodeText, "")
		if len(c.filesLocked()) > 0 {
			writeFormatNameShort(b, cliprdrFileGroupDescriptorW, "FileGroupDescriptorW")
			writeFormatNameShort(b, cliprdrFileContents, "FileContents")
		}
	}
	c.state.LocalFormatsSent = true
	c.state.LocalFormatsAcked = false
	c.sendLocked(cliprdrFormatList, 0, b.Bytes())
}

func writeFormatNameShort(b *bytes.Buffer, id uint32, name string) {
	writeU32(b, id)
	raw := []byte(name)
	if len(raw) > 31 {
		raw = raw[:31]
	}
	b.Write(raw)
	b.Write(make([]byte, 32-len(raw)))
}

func writeFormatNameLong(b *bytes.Buffer, id uint32, name string) {
	writeU32(b, id)
	units := utf16.Encode([]rune(name + "\x00"))
	for _, unit := range units {
		writeU16(b, unit)
	}
}

func (c *CliprdrTextClient) sendFormatDataResponse(formatID uint32) {
	switch formatID {
	case 0, cliprdrCFUnicodeText:
		text := ""
		provider := c.textProvider()
		if provider != nil {
			text = provider()
		}
		units := utf16.Encode([]rune(text + "\x00"))
		b := &bytes.Buffer{}
		for _, unit := range units {
			writeU16(b, unit)
		}
		c.send(cliprdrFormatDataResponse, cliprdrResponseOK, b.Bytes())
	case cliprdrFileGroupDescriptorW:
		files := c.files()
		if len(files) == 0 {
			c.send(cliprdrFormatDataResponse, cliprdrResponseFail, nil)
			return
		}
		c.send(cliprdrFormatDataResponse, cliprdrResponseOK, fileGroupDescriptorW(files))
	default:
		c.send(cliprdrFormatDataResponse, cliprdrResponseFail, nil)
	}
}

func (c *CliprdrTextClient) sendFileContentsResponse(payload []byte) {
	streamID, index, flags, offset, requested, ok := parseFileContentsRequest(payload)
	if !ok {
		c.send(cliprdrFileContentsResponse, cliprdrResponseFail, nil)
		return
	}
	files := c.files()
	if index < 0 || index >= len(files) {
		c.send(cliprdrFileContentsResponse, cliprdrResponseFail, nil)
		return
	}
	file := files[index]
	b := &bytes.Buffer{}
	writeU32(b, streamID)
	if flags&cliprdrFileContentsSize != 0 {
		writeU64(b, uint64(len(file.Data)))
		c.send(cliprdrFileContentsResponse, cliprdrResponseOK, b.Bytes())
		return
	}
	if flags&cliprdrFileContentsRange == 0 {
		c.send(cliprdrFileContentsResponse, cliprdrResponseFail, nil)
		return
	}
	if offset > uint64(len(file.Data)) {
		c.send(cliprdrFileContentsResponse, cliprdrResponseFail, nil)
		return
	}
	end := offset + uint64(requested)
	if requested == 0 || end > uint64(len(file.Data)) {
		end = uint64(len(file.Data))
	}
	b.Write(file.Data[offset:end])
	c.send(cliprdrFileContentsResponse, cliprdrResponseOK, b.Bytes())
	if cb := c.fileServedCallback(); cb != nil {
		cb(index, end >= uint64(len(file.Data)))
	}
}

func parseFileContentsRequest(payload []byte) (streamID uint32, index int, flags uint32, offset uint64, requested uint32, ok bool) {
	if len(payload) < 24 {
		return 0, 0, 0, 0, 0, false
	}
	streamID = binary.LittleEndian.Uint32(payload[0:4])
	idx := int32(binary.LittleEndian.Uint32(payload[4:8]))
	flags = binary.LittleEndian.Uint32(payload[8:12])
	lo := binary.LittleEndian.Uint32(payload[12:16])
	hi := binary.LittleEndian.Uint32(payload[16:20])
	requested = binary.LittleEndian.Uint32(payload[20:24])
	return streamID, int(idx), flags, (uint64(hi) << 32) | uint64(lo), requested, true
}

func (c *CliprdrTextClient) textProvider() ClipboardTextProvider {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.provider
}

func (c *CliprdrTextClient) fileServedCallback() ClipboardFileServedCallback {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fileServed
}

func (c *CliprdrTextClient) files() []ClipboardFile {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.filesLocked()
}

func (c *CliprdrTextClient) filesLocked() []ClipboardFile {
	if c.fileProvider == nil {
		return nil
	}
	in := c.fileProvider()
	out := make([]ClipboardFile, 0, len(in))
	for _, f := range in {
		name := cleanClipboardFileName(f.Name)
		if name == "" {
			continue
		}
		out = append(out, ClipboardFile{Name: name, Data: append([]byte(nil), f.Data...), IsDirectory: f.IsDirectory})
	}
	return out
}

func cleanClipboardFileName(name string) string {
	name = strings.TrimSpace(strings.ReplaceAll(name, "\\", "/"))
	if name == "" || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "//") || strings.Contains(name, ":") {
		return ""
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return ""
		}
	}
	cleaned := path.Clean(name)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "/../") {
		return ""
	}
	for _, part := range strings.Split(cleaned, "/") {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "<>:\"|?*") {
			return ""
		}
	}
	if len(utf16.Encode([]rune(strings.ReplaceAll(cleaned, "/", `\\`)+"\x00"))) > 260 {
		return ""
	}
	return cleaned
}

func fileGroupDescriptorW(files []ClipboardFile) []byte {
	b := &bytes.Buffer{}
	writeU32(b, uint32(len(files)))
	for _, file := range files {
		name := strings.ReplaceAll(cleanClipboardFileName(file.Name), "/", "\\")
		desc := make([]byte, 592)
		flags := cliprdrFDAttributes | cliprdrFDWriteTime
		attrs := uint32(0x80) // FILE_ATTRIBUTE_NORMAL
		if file.IsDirectory {
			attrs = 0x10 // FILE_ATTRIBUTE_DIRECTORY
		} else {
			flags |= cliprdrFDFileSize
			size := uint64(len(file.Data))
			binary.LittleEndian.PutUint32(desc[64:68], uint32(size>>32))
			binary.LittleEndian.PutUint32(desc[68:72], uint32(size))
		}
		binary.LittleEndian.PutUint32(desc[0:4], flags)
		binary.LittleEndian.PutUint32(desc[36:40], attrs)
		units := utf16.Encode([]rune(name + "\x00"))
		if len(units) > 260 {
			units = units[:260]
		}
		for i, unit := range units {
			binary.LittleEndian.PutUint16(desc[72+i*2:74+i*2], unit)
		}
		b.Write(desc)
	}
	return b.Bytes()
}

func (c *CliprdrTextClient) send(msgType, msgFlags uint16, payload []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sendLocked(msgType, msgFlags, payload)
}

func (c *CliprdrTextClient) sendLocked(msgType, msgFlags uint16, payload []byte) {
	if c.sender == nil {
		return
	}
	b := &bytes.Buffer{}
	writeU16(b, msgType)
	writeU16(b, msgFlags)
	writeU32(b, uint32(len(payload)))
	b.Write(payload)
	_, _ = c.sender.SendToChannel(CLIPRDR_SVC_CHANNEL_NAME, b.Bytes())
}

func readU16(r *bytes.Reader) uint16 {
	var out uint16
	_ = binary.Read(r, binary.LittleEndian, &out)
	return out
}

func readU32(r *bytes.Reader) uint32 {
	var out uint32
	_ = binary.Read(r, binary.LittleEndian, &out)
	return out
}

func writeU16(b *bytes.Buffer, v uint16) { _ = binary.Write(b, binary.LittleEndian, v) }
func writeU32(b *bytes.Buffer, v uint32) { _ = binary.Write(b, binary.LittleEndian, v) }
func writeU64(b *bytes.Buffer, v uint64) { _ = binary.Write(b, binary.LittleEndian, v) }

func ValidateClipboardFiles(files []ClipboardFile, maxFiles int, maxBytes int64) error {
	if len(files) == 0 {
		return fmt.Errorf("keine Dateien")
	}
	if maxFiles > 0 && len(files) > maxFiles {
		return fmt.Errorf("zu viele Dateien (max. %d)", maxFiles)
	}
	var total int64
	for _, f := range files {
		if cleanClipboardFileName(f.Name) == "" {
			return fmt.Errorf("ungültiger Dateiname")
		}
		total += int64(len(f.Data))
		if maxBytes > 0 && total > maxBytes {
			return fmt.Errorf("Dateien zu groß (max. %.1f MB)", float64(maxBytes)/1024/1024)
		}
	}
	return nil
}
