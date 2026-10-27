package cftunnel

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/gobwas/ws/wsutil"
	gorilla "github.com/gorilla/websocket"
	"github.com/rs/zerolog"

	"github.com/cloudflare/cloudflared/carrier"
)

// echoServer accepts TCP connections and echoes what it reads.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// accessConfig serves ssh.example.com with cf_access to upstream and
// bastion.example.com in bastion mode, both on the listener and the tunnel.
// Every other request gets "site".
func accessConfig(token, upstream string) []byte {
	route := func(host string, access map[string]any) map[string]any {
		access["handler"] = "cf_access"
		return map[string]any{
			"match": []any{map[string]any{"host": []string{host}}},
			"handle": []any{access, map[string]any{
				"handler": "static_response",
				"body":    "site",
			}},
		}
	}
	cfg := map[string]any{
		"admin":   map[string]any{"disabled": true},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "ERROR"}}},
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					"web": map[string]any{
						"listen":          []string{"127.0.0.1:18081"},
						"automatic_https": map[string]any{"disable": true},
						"routes": []any{
							route("ssh.example.com", map[string]any{"upstream": "tcp://" + upstream}),
							route("bastion.example.com", map[string]any{"bastion": true}),
						},
					},
				},
			},
			"cloudflare_tunnel": map[string]any{"token": token},
		},
	}
	b, _ := json.Marshal(cfg)
	return b
}

// accessDial runs cloudflared's own access client (as `cloudflared access
// ssh` does) against the listener, and returns the local end of its stream.
func accessDial(t *testing.T, host string, headers http.Header) net.Conn {
	t.Helper()
	local, remote := net.Pipe()
	t.Cleanup(func() { local.Close() })
	if headers == nil {
		headers = http.Header{}
	}
	headers.Set("User-Agent", "cloudflared/test")
	log := zerolog.Nop()
	go func() {
		defer remote.Close()
		_ = carrier.StartClient(carrier.NewWSConnection(&log), remote, &carrier.StartOptions{
			OriginURL: "http://127.0.0.1:18081",
			Host:      host,
			Headers:   headers,
		})
	}()
	return local
}

func expectEcho(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	msg := []byte("SSH-2.0-test\r\n")
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo got %q, want %q", got, msg)
	}
}

func TestAccessListener(t *testing.T) {
	fakeTunnels(t)
	upstream := echoServer(t)
	if err := caddy.Load(accessConfig(fakeToken(t), upstream), true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })

	expectEcho(t, accessDial(t, "ssh.example.com", nil))

	h := http.Header{}
	carrier.SetBastionDest(h, upstream)
	expectEcho(t, accessDial(t, "bastion.example.com", h))

	// Bastion without --destination: rejected before the upgrade.
	resp := wsHandshake(t, "bastion.example.com", "cloudflared/test")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bastion without destination: HTTP %d, want 400", resp.StatusCode)
	}

	// The site's own WebSockets and plain requests go to the next handler.
	for _, ua := range []string{"Mozilla/5.0", ""} {
		resp := wsHandshake(t, "ssh.example.com", ua)
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || string(b) != "site" {
			t.Fatalf("WebSocket with User-Agent %q: HTTP %d %q, want the site", ua, resp.StatusCode, b)
		}
	}
	req, _ := http.NewRequest("GET", "http://127.0.0.1:18081/", nil)
	req.Host = "ssh.example.com"
	req.Header.Set("User-Agent", "cloudflared/test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "site" {
		t.Fatalf("plain request got %q, want the site", b)
	}
}

// wsHandshake attempts a WebSocket upgrade and returns the response.
func wsHandshake(t *testing.T, host, ua string) *http.Response {
	t.Helper()
	h := http.Header{"Host": {host}}
	if ua != "" {
		h.Set("User-Agent", ua)
	}
	c, resp, err := gorilla.DefaultDialer.Dial("ws://127.0.0.1:18081/", h)
	if err == nil {
		c.Close()
		t.Fatalf("%s: upgrade succeeded", host)
	}
	if !errors.Is(err, gorilla.ErrBadHandshake) {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// tunnelWriter behaves like cloudflared's tunnel response writers: Hijack
// fails until the status is written, and the hijacked connection carries
// the stream after the response headers.
type tunnelWriter struct {
	header http.Header
	status int
	conn   net.Conn
}

func (w *tunnelWriter) Header() http.Header         { return w.header }
func (w *tunnelWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *tunnelWriter) WriteHeader(status int)      { w.status = status }
func (w *tunnelWriter) Flush()                      {}

func (w *tunnelWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.status == 0 {
		return nil, nil, errors.New("status not yet written before attempting to hijack connection")
	}
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

func TestAccessTunnel(t *testing.T) {
	made := fakeTunnels(t)
	upstream := echoServer(t)
	if err := caddy.Load(accessConfig(fakeToken(t), upstream), true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })

	// Shaped like the request cloudflared hands its local service for a
	// WebSocket stream.
	req, _ := http.NewRequest("GET", "https://ssh.example.com/", nil)
	req.Header.Set("Cf-Connecting-IP", "203.0.113.7")
	req.Header.Set("User-Agent", "cloudflared/test")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-Websocket-Version", "13")
	req.Header.Set("Sec-Websocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	edge, local := net.Pipe()
	defer edge.Close()
	w := &tunnelWriter{header: http.Header{}, conn: local}
	done := make(chan struct{})
	go func() {
		defer close(done)
		(*made)[0].ServeHTTP(w, req)
	}()

	_ = edge.SetDeadline(time.Now().Add(5 * time.Second))
	msg := []byte("SSH-2.0-test\r\n")
	if err := wsutil.WriteClientBinary(edge, msg); err != nil {
		t.Fatal(err)
	}
	got, err := wsutil.ReadServerBinary(edge)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo got %q, want %q", got, msg)
	}
	if w.status != http.StatusSwitchingProtocols || w.header.Get("Sec-Websocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("response: %d %v", w.status, w.header)
	}

	edge.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return after the client closed")
	}
}

func TestAccessCaddyfile(t *testing.T) {
	src := `ssh.example.com {
	route {
		cf_access tcp://{env.SSH_HOST}:22 {
			dial_timeout 5s
		}
		respond "site"
	}
}

bastion.example.com {
	route {
		cf_access bastion
	}
}
`
	out, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(src), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`{"dial_timeout":5000000000,"handler":"cf_access","upstream":"tcp://{env.SSH_HOST}:22"}`,
		`{"bastion":true,"handler":"cf_access"}`,
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("adapted config has no %s:\n%s", want, out)
		}
	}
}

func TestAccessProvision(t *testing.T) {
	for _, tc := range []struct {
		h       Access
		wantErr string
	}{
		{Access{Upstream: "tcp://10.0.0.1:22"}, ""},
		{Access{Upstream: "10.0.0.1:22"}, ""},
		{Access{Upstream: "tcp://{env.HOST}"}, ""},
		{Access{Bastion: true}, ""},
		{Access{}, "upstream is required"},
		{Access{Upstream: "10.0.0.1:22", Bastion: true}, "mutually exclusive"},
		{Access{Upstream: "http://10.0.0.1:22"}, "want tcp://host:port"},
		{Access{Upstream: "tcp://10.0.0.1"}, "want tcp://host:port"},
	} {
		ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
		err := tc.h.Provision(ctx)
		cancel()
		if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%+v: got error %v, want %q", tc.h, err, tc.wantErr)
		}
	}
}
