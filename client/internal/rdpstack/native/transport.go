package native

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	rdptls "github.com/icodeface/tls"
)

type DialOptions struct {
	Address    string
	CookieHost string
	TLSConfig  *rdptls.Config
	StartTLS   bool
}

type Conn struct {
	Raw     net.Conn
	TLSConn *rdptls.Conn
	Confirm X224ConnectionConfirm
}

func DialNegotiation(ctx context.Context, opt DialOptions) (*Conn, X224ConnectionConfirm, error) {
	if opt.Address == "" {
		return nil, X224ConnectionConfirm{}, fmt.Errorf("RDP address empty")
	}
	d := net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", opt.Address)
	if err != nil {
		return nil, X224ConnectionConfirm{}, err
	}
	c := &Conn{Raw: raw}
	ok := false
	defer func() {
		if !ok {
			_ = raw.Close()
		}
	}()

	req, err := EncodeX224ConnectionRequest(opt.CookieHost)
	if err != nil {
		return nil, X224ConnectionConfirm{}, err
	}
	if err := c.writeRaw(ctx, req); err != nil {
		return nil, X224ConnectionConfirm{}, err
	}
	payload, err := c.readRawTPKT(ctx)
	if err != nil {
		return nil, X224ConnectionConfirm{}, err
	}
	cc, err := DecodeX224ConnectionConfirm(payload)
	if err != nil {
		return nil, X224ConnectionConfirm{}, err
	}
	c.Confirm = cc
	if opt.StartTLS && cc.SelectedProtocol.NeedsTLS() {
		if err := c.StartTLS(ctx, opt); err != nil {
			return nil, X224ConnectionConfirm{}, err
		}
	}
	ok = true
	return c, cc, nil
}

func (c *Conn) Close() error {
	if c.TLSConn != nil {
		return c.TLSConn.Close()
	}
	if c.Raw != nil {
		return c.Raw.Close()
	}
	return nil
}

func (c *Conn) StartTLS(ctx context.Context, opt DialOptions) error {
	cfg := &rdptls.Config{InsecureSkipVerify: true, MinVersion: rdptls.VersionTLS10, MaxVersion: rdptls.VersionTLS12, PreferServerCipherSuites: true}
	if opt.TLSConfig != nil {
		cfg = opt.TLSConfig.Clone()
	}
	if cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(opt.Address)
		if err == nil {
			cfg.ServerName = host
		}
	}
	tlsConn := rdptls.Client(c.Raw, cfg)
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.Raw.SetDeadline(deadline)
		defer c.Raw.SetDeadline(noDeadline)
	}
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	c.TLSConn = tlsConn
	return nil
}

func (c *Conn) ReadTPKT(ctx context.Context) ([]byte, error) { return c.readRawTPKT(ctx) }
func (c *Conn) WriteTPKT(ctx context.Context, payload []byte) error {
	pkt, err := EncodeTPKT(payload)
	if err != nil {
		return err
	}
	return c.writeRaw(ctx, pkt)
}

func (c *Conn) active() net.Conn {
	if c.TLSConn != nil {
		return c.TLSConn
	}
	return c.Raw
}

func (c *Conn) readRawTPKT(ctx context.Context) ([]byte, error) {
	conn := c.active()
	if conn == nil {
		return nil, fmt.Errorf("RDP connection closed")
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
		defer conn.SetDeadline(noDeadline)
	}
	h := make([]byte, 4)
	if _, err := io.ReadFull(conn, h); err != nil {
		return nil, err
	}
	ln := int(binary.BigEndian.Uint16(h[2:4]))
	if ln < 4 || ln > 0xffff {
		return nil, fmt.Errorf("invalid TPKT length %d", ln)
	}
	pkt := make([]byte, ln)
	copy(pkt, h)
	if _, err := io.ReadFull(conn, pkt[4:]); err != nil {
		return nil, err
	}
	payload, rest, err := DecodeTPKT(pkt)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("unexpected TPKT trailing bytes: %d", len(rest))
	}
	return payload, nil
}

func (c *Conn) writeRaw(ctx context.Context, p []byte) error {
	conn := c.active()
	if conn == nil {
		return fmt.Errorf("RDP connection closed")
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
		defer conn.SetDeadline(noDeadline)
	}
	_, err := conn.Write(p)
	return err
}

var noDeadline time.Time
