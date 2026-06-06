package client

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/plugin"
	"github.com/tomatome/grdp/protocol/nla"
	"github.com/tomatome/grdp/protocol/pdu"
	"github.com/tomatome/grdp/protocol/sec"
	"github.com/tomatome/grdp/protocol/t125"
	"github.com/tomatome/grdp/protocol/tpkt"
	"github.com/tomatome/grdp/protocol/x224"
)

type RdpClient struct {
	tpkt             *tpkt.TPKT
	x224             *x224.X224
	mcs              *t125.MCSClient
	sec              *sec.Client
	pdu              *pdu.Client
	channels         *plugin.Channels
	cliprdr          *plugin.CliprdrTextClient
	clipProvider     plugin.ClipboardTextProvider
	clipFileProvider plugin.ClipboardFileProvider
	clipFileServed   plugin.ClipboardFileServedCallback
	audioSink        plugin.RDPSNDAudioSink
	drdynvc          *plugin.DrdynvcClient
	rdpgfx           *plugin.RDPGFXClient
	mu               sync.Mutex
	pending          []rdpEventHandler
}

type rdpEventHandler struct {
	event string
	fn    interface{}
}

func newRdpClient(s *Setting) *RdpClient {
	return &RdpClient{}
}

func bitmapDecompress(bitmap *pdu.BitmapData) []byte {
	return core.Decompress(bitmap.BitmapDataStream, int(bitmap.Width), int(bitmap.Height), Bpp(bitmap.BitsPerPixel))
}

func normalizeUncompressedBitmapStream(src []byte, width, height, bytesPerPixel int) []byte {
	if width <= 0 || height <= 0 || bytesPerPixel <= 0 || len(src) == 0 {
		return src
	}
	rowBytes := width * bytesPerPixel
	srcStride := (rowBytes + 3) &^ 3
	if len(src) < srcStride*height {
		if len(src) < rowBytes*height {
			return src
		}
		srcStride = rowBytes
	}
	out := make([]byte, rowBytes*height)
	for y := 0; y < height; y++ {
		srcY := height - 1 - y
		copy(out[y*rowBytes:(y+1)*rowBytes], src[srcY*srcStride:srcY*srcStride+rowBytes])
	}
	return out
}
func split(user string) (domain string, uname string) {
	if strings.Index(user, "\\") != -1 {
		t := strings.Split(user, "\\")
		domain = t[0]
		uname = t[len(t)-1]
	} else if strings.Index(user, "/") != -1 {
		t := strings.Split(user, "/")
		domain = t[0]
		uname = t[len(t)-1]
	} else {
		uname = user
	}
	return
}
func (c *RdpClient) SetClipboardTextProvider(provider func() string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clipProvider = provider
}

func (c *RdpClient) SetClipboardFileProvider(provider func() []plugin.ClipboardFile) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clipFileProvider = provider
}

func (c *RdpClient) SetClipboardFileServedCallback(callback func(index int, complete bool)) {
	c.mu.Lock()
	c.clipFileServed = callback
	cliprdr := c.cliprdr
	c.mu.Unlock()
	if cliprdr != nil {
		cliprdr.SetFileServedCallback(callback)
	}
}

func (c *RdpClient) RefreshClipboard() {
	c.mu.Lock()
	cliprdr := c.cliprdr
	c.mu.Unlock()
	if cliprdr != nil {
		cliprdr.AnnounceFormatList()
	}
}

func (c *RdpClient) SetAudioSink(sink func(RDPAudioChunk)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.audioSink = sink
}

func (c *RdpClient) Login(host, user, pwd string, width, height int) error {
	conn, err := net.DialTimeout("tcp", host, 3*time.Second)
	if err != nil {
		return fmt.Errorf("[dial err] %v", err)
	}

	domain, user := split(user)
	c.tpkt = tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, pwd))
	c.x224 = x224.New(c.tpkt)
	c.mcs = t125.NewMCSClient(c.x224)
	c.sec = sec.NewClient(c.mcs)
	c.pdu = pdu.NewClient(c.sec)
	c.flushPendingHandlers()

	c.mcs.SetClientCoreData(uint16(width), uint16(height))

	c.sec.SetUser(user)
	c.sec.SetPwd(pwd)
	c.sec.SetDomain(domain)

	c.tpkt.SetFastPathListener(c.sec)
	c.sec.SetFastPathListener(c.pdu)
	c.sec.SetChannelSender(c.mcs)
	c.channels = plugin.NewChannels(c.sec)
	c.channels.SetChannelSender(c.sec)
	cliprdr := plugin.NewCliprdrTextClient(func() string {
		c.mu.Lock()
		provider := c.clipProvider
		c.mu.Unlock()
		if provider == nil {
			return ""
		}
		return provider()
	})
	cliprdr.SetFileProvider(func() []plugin.ClipboardFile {
		c.mu.Lock()
		provider := c.clipFileProvider
		c.mu.Unlock()
		if provider == nil {
			return nil
		}
		return provider()
	})
	cliprdr.SetFileServedCallback(func(index int, complete bool) {
		c.mu.Lock()
		callback := c.clipFileServed
		c.mu.Unlock()
		if callback != nil {
			callback(index, complete)
		}
	})
	c.mu.Lock()
	c.cliprdr = cliprdr
	c.mu.Unlock()
	c.channels.Register(cliprdr)
	c.channels.Register(plugin.NewRDPSNDClient(func(chunk plugin.RDPSNDAudioChunk) {
		c.mu.Lock()
		sink := c.audioSink
		c.mu.Unlock()
		if sink != nil {
			sink(chunk)
		}
	}))
	if experimentalRDPGFXEnabled() {
		c.channels.Register(c.newGraphicsDrdynvc())
	}

	//c.x224.SetRequestedProtocol(x224.PROTOCOL_RDP)
	//c.x224.SetRequestedProtocol(x224.PROTOCOL_SSL)

	err = c.x224.Connect()
	if err != nil {
		return fmt.Errorf("[x224 connect err] %v", err)
	}
	return nil
}
func (c *RdpClient) newGraphicsDrdynvc() *plugin.DrdynvcClient {
	gfx := plugin.NewRDPGFXClient(func(u plugin.RDPGFXSurfaceUpdate) {
		c.mu.Lock()
		p := c.pdu
		c.mu.Unlock()
		if p != nil {
			p.Emit("gfx-update", []plugin.RDPGFXSurfaceUpdate{u})
		}
	})
	drdynvc := plugin.NewDrdynvcClient()
	drdynvc.RegisterDynamic(plugin.NewNoopDynamicChannel("Microsoft::Windows::RDS::CoreInput"))
	drdynvc.RegisterDynamic(plugin.NewNoopDynamicChannel("Microsoft::Windows::RDS::MouseCursor"))
	drdynvc.RegisterDynamic(gfx)
	c.mu.Lock()
	c.drdynvc = drdynvc
	c.rdpgfx = gfx
	c.mu.Unlock()
	return drdynvc
}

func experimentalRDPGFXEnabled() bool {
	return os.Getenv("SSH_VAULT2_EXPERIMENTAL_RDPGFX") == "1"
}

func (c *RdpClient) On(event string, f interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pdu == nil {
		c.pending = append(c.pending, rdpEventHandler{event: event, fn: f})
		return
	}
	c.pdu.On(event, f)
}

func (c *RdpClient) flushPendingHandlers() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pdu == nil || len(c.pending) == 0 {
		return
	}
	for _, h := range c.pending {
		c.pdu.On(h.event, h.fn)
	}
	c.pending = nil
}
func (c *RdpClient) KeyUp(sc int, name string) {
	p := &pdu.ScancodeKeyEvent{}
	p.KeyCode = uint16(sc)
	p.KeyboardFlags |= pdu.KBDFLAGS_RELEASE
	c.pdu.SendInputEvents(pdu.INPUT_EVENT_SCANCODE, []pdu.InputEventsInterface{p})
}
func (c *RdpClient) KeyDown(sc int, name string) {
	p := &pdu.ScancodeKeyEvent{}
	p.KeyCode = uint16(sc)
	c.pdu.SendInputEvents(pdu.INPUT_EVENT_SCANCODE, []pdu.InputEventsInterface{p})
}

func (c *RdpClient) TypeText(text string) {
	if c.pdu == nil || text == "" {
		return
	}
	for _, unit := range utf16.Encode([]rune(text)) {
		down := &pdu.UnicodeKeyEvent{Unicode: unit}
		up := &pdu.UnicodeKeyEvent{Unicode: unit, KeyboardFlags: pdu.KBDFLAGS_RELEASE}
		c.pdu.SendInputEvents(pdu.INPUT_EVENT_UNICODE, []pdu.InputEventsInterface{down, up})
	}
}

func (c *RdpClient) MouseMove(x, y int) {
	p := &pdu.PointerEvent{}
	p.PointerFlags |= pdu.PTRFLAGS_MOVE
	p.XPos = uint16(x)
	p.YPos = uint16(y)
	c.pdu.SendInputEvents(pdu.INPUT_EVENT_MOUSE, []pdu.InputEventsInterface{p})
}

func (c *RdpClient) MouseWheel(scroll, x, y int) {
	p := &pdu.PointerEvent{}
	p.PointerFlags |= pdu.PTRFLAGS_WHEEL
	if scroll < 0 {
		p.PointerFlags |= pdu.PTRFLAGS_WHEEL_NEGATIVE
		scroll = -scroll
	}
	p.PointerFlags |= uint16(scroll & 0xff)
	p.XPos = uint16(x)
	p.YPos = uint16(y)
	c.pdu.SendInputEvents(pdu.INPUT_EVENT_MOUSE, []pdu.InputEventsInterface{p})
}

func (c *RdpClient) MouseUp(button int, x, y int) {
	p := &pdu.PointerEvent{}

	switch button {
	case 0:
		p.PointerFlags |= pdu.PTRFLAGS_BUTTON1
	case 2:
		p.PointerFlags |= pdu.PTRFLAGS_BUTTON2
	case 1:
		p.PointerFlags |= pdu.PTRFLAGS_BUTTON3
	default:
		p.PointerFlags |= pdu.PTRFLAGS_MOVE
	}

	p.XPos = uint16(x)
	p.YPos = uint16(y)
	c.pdu.SendInputEvents(pdu.INPUT_EVENT_MOUSE, []pdu.InputEventsInterface{p})
}
func (c *RdpClient) MouseDown(button int, x, y int) {
	p := &pdu.PointerEvent{}

	p.PointerFlags |= pdu.PTRFLAGS_DOWN

	switch button {
	case 0:
		p.PointerFlags |= pdu.PTRFLAGS_BUTTON1
	case 2:
		p.PointerFlags |= pdu.PTRFLAGS_BUTTON2
	case 1:
		p.PointerFlags |= pdu.PTRFLAGS_BUTTON3
	default:
		p.PointerFlags |= pdu.PTRFLAGS_MOVE
	}

	p.XPos = uint16(x)
	p.YPos = uint16(y)
	c.pdu.SendInputEvents(pdu.INPUT_EVENT_MOUSE, []pdu.InputEventsInterface{p})
}
func (c *RdpClient) Close() {
	if c != nil && c.tpkt != nil {
		c.tpkt.Close()
	}
}
