package grdpstack

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tomatome/grdp/client"
	"github.com/tomatome/grdp/glog"

	"github.com/example-org/ssh-vault2/internal/rdpstack"
)

type Engine struct{}

func New() *Engine { return &Engine{} }

func (e *Engine) Name() string { return "grdp" }

func (e *Engine) Capabilities() rdpstack.Capabilities {
	return rdpstack.Capabilities{Backend:"grdp", DynamicResize:false, ReconnectResize:true, DirtyRects:true, FullFrame:true, Clipboard:false, DriveRedirect:false, Audio:false, Cursor:false}
}

func (e *Engine) Connect(ctx context.Context, options rdpstack.Options, sink rdpstack.Sink) (rdpstack.Session, error) {
	o := options.Normalize()
	if err := o.Validate(); err != nil { return nil, err }
	addr := fmt.Sprintf("%s:%d", o.Host, o.Port)
	setting := client.NewSetting()
	setting.Width = o.Width
	setting.Height = o.Height
	setting.LogLevel = glog.ERROR
	cli := client.NewClient(addr, userWithDomain(o), o.Password, client.TC_RDP, setting)
	s := &Session{id: uuid.NewString(), client: cli, sink: sink, options: o, closed: make(chan struct{})}
	if sink != nil { sink.Status(rdpstack.Status{SessionID:s.id, State:rdpstack.StateConnecting}) }
	go s.run()
	return s, nil
}

type Session struct {
	id string
	client *client.Client
	sink rdpstack.Sink
	options rdpstack.Options
	closed chan struct{}
	closeOnce sync.Once
	mu sync.Mutex
	seq int
}

func (s *Session) ID() string { return s.id }

func (s *Session) run() {
	if err := s.client.Login(); err != nil {
		if s.sink != nil { s.sink.Error(s.id, err); s.sink.Status(rdpstack.Status{SessionID:s.id, State:rdpstack.StateError, Message:err.Error()}) }
		return
	}
	if s.sink != nil { s.sink.Status(rdpstack.Status{SessionID:s.id, State:rdpstack.StateConnected}) }
	// grdp panics if callbacks are registered before Login; register after Login.
	s.client.OnBitmap(func(bitmaps []client.Bitmap) {
		for _, bm := range bitmaps { s.emitBitmap(bm) }
	})
	s.client.OnError(func(err error) {
		if s.sink != nil { s.sink.Error(s.id, err); s.sink.Status(rdpstack.Status{SessionID:s.id, State:rdpstack.StateError, Message:StringErr(err)}) }
	})
	s.client.OnClose(func() {
		if s.sink != nil { s.sink.Status(rdpstack.Status{SessionID:s.id, State:rdpstack.StateClosed}) }
	})
}

func (s *Session) Resize(context.Context, int, int) error {
	return fmt.Errorf("grdp backend requires reconnect for resize")
}

func (s *Session) Mouse(ctx context.Context, event rdpstack.MouseEvent) error {
	// TODO(stack): map mouse event into grdp input once AppService migrates from legacy path.
	select { case <-ctx.Done(): return ctx.Err(); default: return nil }
}

func (s *Session) Key(ctx context.Context, event rdpstack.KeyEvent) error {
	// TODO(stack): map keyboard event into grdp input once AppService migrates from legacy path.
	select { case <-ctx.Done(): return ctx.Err(); default: return nil }
}

func (s *Session) Close(context.Context) error {
	s.closeOnce.Do(func(){ s.client.Close(); close(s.closed); if s.sink != nil { s.sink.Status(rdpstack.Status{SessionID:s.id, State:rdpstack.StateClosed}) } })
	return nil
}

func (s *Session) emitBitmap(bm client.Bitmap) {
	if s.sink == nil || bm.Width <= 0 || bm.Height <= 0 { return }
	s.mu.Lock(); s.seq++; seq := s.seq; s.mu.Unlock()
	data := make([]byte, len(bm.Data)); copy(data, bm.Data)
	s.sink.Frame(rdpstack.Frame{SessionID:s.id, Left:bm.DestLeft, Top:bm.DestTop, Width:bm.Width, Height:bm.Height, Stride:bm.Width*bm.BitsPerPixel, Format:rdpstack.PixelBGRA, Data:data, Seq:seq})
}

func userWithDomain(o rdpstack.Options) string {
	u := strings.TrimSpace(o.Username)
	d := strings.TrimSpace(o.Domain)
	if d != "" && !strings.Contains(u, `\\`) && !strings.Contains(u, "@") { return d + `\\` + u }
	return u
}

func StringErr(err error) string { if err == nil { return "" }; return err.Error() }

func init() { _ = time.Second }
