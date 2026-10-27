package cftunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/rs/zerolog"
	"go.uber.org/zap"

	"github.com/cloudflare/cloudflared/carrier"
	"github.com/cloudflare/cloudflared/stream"
	"github.com/cloudflare/cloudflared/websocket"
)

func init() {
	caddy.RegisterModule(Access{})
	httpcaddyfile.RegisterHandlerDirective("cf_access", parseAccessDirective)
}

// Access serves `cloudflared access` clients (ssh, tcp, rdp, ...): it accepts
// their WebSocket and pipes it to a TCP upstream, as cloudflared does for a
// tcp:// or bastion ingress rule. Other requests, including the site's own
// WebSockets, go to the next handler.
//
// It does no authentication of its own: put it behind one.
type Access struct {
	// TCP address to connect to, as "tcp://host:port" or "host:port".
	// Placeholders are supported. Required unless bastion is set.
	Upstream string `json:"upstream,omitempty"`

	// Connect to the address the client asks for with --destination
	// (the Cf-Access-Jump-Destination header), like cloudflared's bastion mode.
	Bastion bool `json:"bastion,omitempty"`

	// Timeout for connecting to the upstream. Default: 30s, like cloudflared.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	logger *zap.Logger
}

func (Access) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cf_access",
		New: func() caddy.Module { return new(Access) },
	}
}

func (h *Access) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	switch {
	case h.Bastion && h.Upstream != "":
		return fmt.Errorf("upstream and bastion are mutually exclusive")
	case !h.Bastion && h.Upstream == "":
		return fmt.Errorf("upstream is required unless bastion is set")
	case h.Upstream != "" && !strings.Contains(h.Upstream, "{"):
		if _, err := parseTCPAddr(h.Upstream); err != nil {
			return err
		}
	}
	if h.DialTimeout == 0 {
		h.DialTimeout = caddy.Duration(30 * time.Second)
	}
	return nil
}

func (h *Access) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if !isAccessClient(r) {
		return next.ServeHTTP(w, r)
	}

	var dest string
	var err error
	if h.Bastion {
		dest, err = carrier.ResolveBastionDest(r)
		if err != nil {
			return caddyhttp.Error(http.StatusBadRequest, err)
		}
	} else {
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		dest, err = parseTCPAddr(repl.ReplaceAll(h.Upstream, ""))
		if err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}
	}

	dialer := net.Dialer{Timeout: time.Duration(h.DialTimeout)}
	upstream, err := dialer.DialContext(r.Context(), "tcp", dest)
	if err != nil {
		return caddyhttp.Error(http.StatusBadGateway, err)
	}
	defer upstream.Close()

	// Status first, then hijack, like reverse_proxy: cloudflared's tunnel
	// transports require this order, and net/http flushes the status when
	// the connection is hijacked.
	for k, v := range websocket.NewResponseHeader(r) {
		w.Header()[k] = v
	}
	w.WriteHeader(http.StatusSwitchingProtocols)
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		h.logger.Error("hijack failed on protocol switch", zap.Error(err))
		return nil
	}
	defer conn.Close()
	if err := brw.Flush(); err != nil {
		return nil
	}

	logger := h.logger.With(zap.String("upstream", dest))
	logger.Debug("access stream started")
	start := time.Now()

	log := zerolog.New(newZapWriter(logger))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The reader may hold bytes the client sent right after the handshake.
	ws := websocket.NewConn(ctx, struct {
		io.Reader
		io.Writer
	}{brw.Reader, conn}, &log)
	defer ws.Close()
	stream.Pipe(ws, upstream, &log)

	logger.Debug("access stream closed", zap.Duration("duration", time.Since(start)))
	return nil
}

// isAccessClient tells `cloudflared access` WebSockets from the site's own:
// the client always sends User-Agent cloudflared/<version> ("DEV" for
// development builds).
func isAccessClient(r *http.Request) bool {
	if !websocket.IsWebSocketUpgrade(r) {
		return false
	}
	ua := r.Header.Get("User-Agent")
	return strings.HasPrefix(ua, "cloudflared/") || ua == "DEV"
}

// parseTCPAddr accepts "tcp://host:port" or "host:port".
func parseTCPAddr(s string) (string, error) {
	addr := s
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("invalid upstream %q: %w", s, err)
		}
		if u.Scheme != "tcp" || u.Path != "" || u.RawQuery != "" {
			return "", fmt.Errorf("invalid upstream %q: want tcp://host:port", s)
		}
		addr = u.Host
	}
	if _, port, err := net.SplitHostPort(addr); err != nil || port == "" {
		return "", fmt.Errorf("invalid upstream %q: want tcp://host:port", s)
	}
	return addr, nil
}

// parseAccessDirective sets up the handler from the Caddyfile:
//
//	cf_access <upstream>|bastion {
//		dial_timeout <duration>
//	}
func parseAccessDirective(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	a := new(Access)
	err := a.UnmarshalCaddyfile(h.Dispenser)
	return a, err
}

func (h *Access) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // directive name
	if !d.NextArg() {
		return d.ArgErr()
	}
	if d.Val() == "bastion" {
		h.Bastion = true
	} else {
		h.Upstream = d.Val()
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "dial_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid dial_timeout %q: %v", d.Val(), err)
			}
			h.DialTimeout = caddy.Duration(dur)
			if d.NextArg() {
				return d.ArgErr()
			}
		default:
			return d.Errf("unknown subdirective %q", d.Val())
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Access)(nil)
	_ caddyhttp.MiddlewareHandler = (*Access)(nil)
	_ caddyfile.Unmarshaler       = (*Access)(nil)
)
