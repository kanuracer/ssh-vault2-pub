// Package rdpstack defines a backend-neutral RDP engine contract for ssh-vault2.
package rdpstack

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

type ResizeMode string

const (
	ResizeReconnect ResizeMode = "reconnect"
	ResizeDynamic   ResizeMode = "dynamic"
	ResizeScaleOnly ResizeMode = "scale-only"
)

type PixelFormat string

const (
	PixelBGRA PixelFormat = "bgra"
	PixelRGBA PixelFormat = "rgba"
	PixelPNG  PixelFormat = "png"
)

type State string

const (
	StateConnecting State = "connecting"
	StateConnected  State = "connected"
	StateClosed     State = "closed"
	StateError      State = "error"
)

type Options struct {
	Host       string
	Port       int
	Username   string
	Password   string
	Domain     string
	Width      int
	Height     int
	ColorDepth int
	ClientName string
	ResizeMode ResizeMode
	InsecureSkipVerify bool
}

func (o Options) Normalize() Options {
	o.Host = strings.TrimSpace(o.Host)
	o.Username = strings.TrimSpace(o.Username)
	o.Domain = strings.TrimSpace(o.Domain)
	if o.Port == 0 { o.Port = 3389 }
	if o.Width < 640 { o.Width = 640 }
	if o.Height < 480 { o.Height = 480 }
	if o.ColorDepth == 0 { o.ColorDepth = 32 }
	if o.ClientName == "" { o.ClientName = "ssh-vault2" }
	if o.ResizeMode == "" { o.ResizeMode = ResizeReconnect }
	return o
}

func (o Options) Validate() error {
	if o.Host == "" { return errors.New("RDP host fehlt") }
	if o.Port < 1 || o.Port > 65535 { return fmt.Errorf("ungültiger RDP-Port: %d", o.Port) }
	if strings.TrimSpace(o.Username) == "" { return errors.New("RDP-Benutzer fehlt") }
	if strings.TrimSpace(o.Password) == "" { return errors.New("RDP-Passwort fehlt") }
	if o.Width < 640 || o.Height < 480 { return fmt.Errorf("RDP-Auflösung zu klein: %dx%d", o.Width, o.Height) }
	return nil
}

type Capabilities struct {
	Backend       string
	DynamicResize bool
	ReconnectResize bool
	DirtyRects    bool
	FullFrame     bool
	Clipboard     bool
	DriveRedirect bool
	Audio         bool
	Cursor        bool
}

type Status struct {
	SessionID string
	State     State
	Message   string
}

type Frame struct {
	SessionID string
	Left      int
	Top       int
	Width     int
	Height    int
	Stride    int
	Format    PixelFormat
	Data      []byte
	Seq       int
}

type MouseEvent struct {
	Action string
	X      int
	Y      int
	Delta  int
	Button int
}

type KeyEvent struct {
	Code string
	Down bool
}

type Sink interface {
	Status(Status)
	Frame(Frame)
	Error(sessionID string, err error)
}

type Engine interface {
	Name() string
	Capabilities() Capabilities
	Connect(ctx context.Context, options Options, sink Sink) (Session, error)
}

type Session interface {
	ID() string
	Resize(ctx context.Context, width int, height int) error
	Mouse(ctx context.Context, event MouseEvent) error
	Key(ctx context.Context, event KeyEvent) error
	Close(ctx context.Context) error
}

type MemoryError struct {
	SessionID string
	Err       error
}

type MemorySink struct {
	mu       sync.Mutex
	statuses []Status
	frames   []Frame
	errors   []MemoryError
}

func NewMemorySink() *MemorySink { return &MemorySink{} }

func (s *MemorySink) Status(v Status) {
	s.mu.Lock(); defer s.mu.Unlock()
	s.statuses = append(s.statuses, v)
}

func (s *MemorySink) Frame(v Frame) {
	s.mu.Lock(); defer s.mu.Unlock()
	if v.Data != nil {
		cp := make([]byte, len(v.Data)); copy(cp, v.Data); v.Data = cp
	}
	s.frames = append(s.frames, v)
}

func (s *MemorySink) Error(sessionID string, err error) {
	s.mu.Lock(); defer s.mu.Unlock()
	s.errors = append(s.errors, MemoryError{SessionID: sessionID, Err: err})
}

func (s *MemorySink) Statuses() []Status { s.mu.Lock(); defer s.mu.Unlock(); return append([]Status(nil), s.statuses...) }
func (s *MemorySink) Frames() []Frame { s.mu.Lock(); defer s.mu.Unlock(); return append([]Frame(nil), s.frames...) }
func (s *MemorySink) Errors() []MemoryError { s.mu.Lock(); defer s.mu.Unlock(); return append([]MemoryError(nil), s.errors...) }

type unavailableEngine struct { name string; caps Capabilities; err error }

func NewUnavailableEngine(name string, caps Capabilities, err error) Engine {
	if caps.Backend == "" { caps.Backend = name }
	if err == nil { err = errors.New("RDP engine unavailable") }
	return unavailableEngine{name:name, caps:caps, err:err}
}

func (e unavailableEngine) Name() string { return e.name }
func (e unavailableEngine) Capabilities() Capabilities { return e.caps }
func (e unavailableEngine) Connect(context.Context, Options, Sink) (Session, error) { return nil, e.err }
