package cftunnel

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/cloudflare/cloudflared/connection"
	"github.com/cloudflare/cloudflared/ingress"
)

func fakeToken(t *testing.T) string {
	t.Helper()
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	b, err := json.Marshal(connection.TunnelToken{
		AccountTag:   "0123456789abcdef0123456789abcdef",
		TunnelSecret: secret,
		TunnelID:     uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// fakeTunnels replaces the connector with one that never dials Cloudflare
// and records every tunnel created.
func fakeTunnels(t *testing.T) *[]*tunnel {
	var made []*tunnel
	orig := newTunnel
	newTunnel = func(opts tunnelOptions, logs *zapWriter) (*tunnel, error) {
		done := make(chan struct{})
		close(done)
		tun := &tunnel{logs: logs, cancel: func() {}, graceC: make(chan struct{}), done: done}
		made = append(made, tun)
		return tun, nil
	}
	t.Cleanup(func() { newTunnel = orig })
	return &made
}

func caddyConfig(token, body string, tunnelSettings map[string]any) []byte {
	site := func(listen string) map[string]any {
		return map[string]any{
			"listen":          []string{listen},
			"automatic_https": map[string]any{"disable": true},
			"routes": []any{map[string]any{
				"match": []any{map[string]any{"host": []string{"app.example.com"}}},
				"handle": []any{map[string]any{
					"handler": "static_response",
					"body":    body + " host={http.request.host} client={http.request.remote.host} scheme={http.request.scheme}",
				}},
			}},
		}
	}
	tun := map[string]any{"token": token}
	for k, v := range tunnelSettings {
		tun[k] = v
	}
	cfg := map[string]any{
		"admin":   map[string]any{"disabled": true},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "ERROR"}}},
		"apps": map[string]any{
			"http": map[string]any{
				"https_port": 18443,
				"servers": map[string]any{
					"web":    site("127.0.0.1:18080"),
					"secure": site("127.0.0.1:18443"),
				},
			},
			"cloudflare_tunnel": tun,
		},
	}
	b, _ := json.Marshal(cfg)
	return b
}

func tunnelGet(t *testing.T, tun *tunnel) string {
	t.Helper()
	// Shaped like cloudflared's requests (http.NewRequestWithContext): no TLS
	// state and no RemoteAddr. httptest.NewRequest would fake both.
	req, err := http.NewRequest("GET", "https://app.example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cf-Connecting-IP", "203.0.113.7")
	rec := httptest.NewRecorder()
	tun.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("tunnel request: HTTP %d %q", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func TestTunnelAndListenerServeSameSite(t *testing.T) {
	made := fakeTunnels(t)
	token := fakeToken(t)

	if err := caddy.Load(caddyConfig(token, "v1", nil), true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })
	if len(*made) != 1 {
		t.Fatalf("created %d tunnels, want 1", len(*made))
	}
	tun := (*made)[0]

	// Tunnel traffic goes to the server on the HTTPS port, with the visitor's
	// IP from Cf-Connecting-IP. Cloudflare terminated TLS, so the scheme is http.
	got := tunnelGet(t, tun)
	t.Logf("tunnel:   %s", got)
	if want := "v1 host=app.example.com client=203.0.113.7 scheme=http"; got != want {
		t.Fatalf("tunnel got %q, want %q", got, want)
	}

	// The same site still answers on the regular listener.
	req, _ := http.NewRequest("GET", "http://127.0.0.1:18443/", nil)
	req.Host = "app.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("listener: %s", b)
	if !strings.HasPrefix(string(b), "v1 host=app.example.com client=127.0.0.1") {
		t.Fatalf("listener got %q", b)
	}

	// A reload that leaves the tunnel settings alone keeps the same
	// connector and swaps in the new server.
	if err := caddy.Load(caddyConfig(token, "v2", nil), true); err != nil {
		t.Fatal(err)
	}
	if len(*made) != 1 {
		t.Fatalf("reload created a new tunnel (%d total)", len(*made))
	}
	if got := tunnelGet(t, tun); !strings.HasPrefix(got, "v2 ") {
		t.Fatalf("after reload, tunnel got %q, want v2", got)
	}
	select {
	case <-tun.graceC:
		t.Fatal("reload shut the tunnel down")
	default:
	}

	// Changing a tunnel setting starts a new connector, then stops the old one.
	if err := caddy.Load(caddyConfig(token, "v3", map[string]any{"ha_connections": 2}), true); err != nil {
		t.Fatal(err)
	}
	if len(*made) != 2 {
		t.Fatalf("settings change: %d tunnels created, want 2", len(*made))
	}
	if got := tunnelGet(t, (*made)[1]); !strings.HasPrefix(got, "v3 ") {
		t.Fatalf("new tunnel got %q, want v3", got)
	}
	select {
	case <-tun.graceC:
	default:
		t.Fatal("old tunnel was not shut down")
	}

	// Stopping Caddy shuts the remaining connector down.
	if err := caddy.Stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-(*made)[1].graceC:
	default:
		t.Fatal("tunnel still running after caddy.Stop")
	}
}

func TestExplicitServer(t *testing.T) {
	made := fakeTunnels(t)
	if err := caddy.Load(caddyConfig(fakeToken(t), "web", map[string]any{"server": "web"}), true); err != nil {
		t.Fatal(err)
	}
	defer caddy.Stop()
	if got := tunnelGet(t, (*made)[0]); !strings.HasPrefix(got, "web ") {
		t.Fatalf("got %q", got)
	}

	err := caddy.Load(caddyConfig(fakeToken(t), "x", map[string]any{"server": "nope"}), true)
	if err == nil || !strings.Contains(err.Error(), `http server "nope" not found (have: secure, web)`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCaddyfile(t *testing.T) {
	src := `{
	cloudflare_tunnel {env.TUNNEL_TOKEN} {
		server public
		service_name my-caddy
		protocol quic
		ha_connections 2
		grace_period 10s
		dns_resolver_addrs 1.1.1.1:53 [2606:4700:4700::1111]:53
		dns_resolver_addrs 8.8.8.8
	}
}

app.example.com {
	respond "hello"
}
`
	out, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(src), nil)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Apps map[string]json.RawMessage `json:"apps"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	got := string(cfg.Apps["cloudflare_tunnel"])
	want := `{"token":"{env.TUNNEL_TOKEN}","server":"public","service_name":"my-caddy","protocol":"quic","ha_connections":2,"grace_period":10000000000,"dns_resolver_addrs":["1.1.1.1:53","[2606:4700:4700::1111]:53","8.8.8.8"]}`
	if got != want {
		t.Fatalf("adapted to\n%s\nwant\n%s", got, want)
	}
}

// TestRealConnector builds the actual cloudflared connector with a made-up
// token. It dials Cloudflare's edge (registration is rejected), so it is
// skipped with -short.
func TestRealConnector(t *testing.T) {
	if testing.Short() {
		t.Skip("dials Cloudflare's edge")
	}
	creds, err := parseToken(fakeToken(t))
	if err != nil {
		t.Fatal(err)
	}
	opts := tunnelOptions{
		Credentials: creds, ServiceName: "caddy", Protocol: "auto",
		HAConnections: 1, GracePeriod: time.Second,
	}

	// Twice in one process: the second supervisor re-registers its metrics,
	// which panics without tolerantRegisterer. The second run uses static DNS
	// resolvers, which must skip the local resolver refresh loop.
	for i := range 2 {
		if i == 1 {
			opts.DNSResolverAddrs = []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53")}
		}
		core, logs := observer.New(zap.DebugLevel)
		begin := time.Now()
		tun, err := startTunnel(opts, newZapWriter(zap.New(core)))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("run %d: startTunnel returned after %s", i, time.Since(begin).Round(time.Millisecond))
		select {
		case <-tun.ready:
		case <-tun.done:
			t.Fatal("connector setup failed")
		}
		t.Logf("run %d: connector set up after %s", i, time.Since(begin).Round(time.Millisecond))
		tun.setTarget(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "from caddy")
		}))

		// The management rule wins over the catch-all for its hostname;
		// everything else reaches the target, named after service_name.
		ing := ingress.Ingress{InternalRules: tun.internalRules}
		for host, want := range map[string]string{"management.argotunnel.com": "management", "app.example.com": "caddy"} {
			rule, _ := ing.FindMatchingRule(host, "/host_details")
			if rule.Service.String() != want {
				t.Fatalf("%s matched %q, want %q", host, rule.Service.String(), want)
			}
		}
		rule, _ := ing.FindMatchingRule("app.example.com", "/")
		rec := httptest.NewRecorder()
		rule.Service.(ingress.HTTPLocalProxy).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		if rec.Body.String() != "from caddy" {
			t.Fatalf("catch-all served %q", rec.Body.String())
		}

		// Give it a moment to reach the edge, then check logs went through zap.
		// With static resolvers, wait for the supervisor (which resolves the
		// edge again first) to skip the refresh loop.
		time.Sleep(3 * time.Second)
		if i == 1 {
			deadline := time.Now().Add(30 * time.Second)
			for logs.FilterMessageSnippet("Canceled DNS local resolver refresh loop").Len() == 0 {
				if time.Now().After(deadline) {
					t.Fatal("static dns_resolver_addrs did not skip the refresh loop")
				}
				time.Sleep(100 * time.Millisecond)
			}
			if n := logs.FilterMessageSnippet("DNS local resolver").FilterLevelExact(zap.ErrorLevel).Len(); n != 0 {
				t.Fatalf("%d DNS local resolver errors with static resolvers", n)
			}
		}
		start := time.Now()
		if err := tun.Destruct(); err != nil {
			t.Fatal(err)
		}
		t.Logf("run %d: shutdown took %s", i, time.Since(start).Round(time.Millisecond))
		if logs.FilterMessageSnippet("Version 2026.10.0").Len() == 0 {
			t.Fatal("cloudflared logs did not reach zap")
		}
		for _, e := range logs.FilterMessageSnippet("Register tunnel error").All() {
			t.Logf("run %d: %s %v", i, e.Message, e.ContextMap())
			break
		}
	}
}

func TestVisitorScheme(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "xfp=%s xff=%s early=%q via=%s", r.Header.Get("X-Forwarded-Proto"),
			r.Header.Get("X-Forwarded-For"), r.Header.Get("Early-Data"), r.Header.Get("X-Caddy-Scheme"))
	}))
	defer backend.Close()

	made := fakeTunnels(t)
	cfg, _ := json.Marshal(map[string]any{
		"admin":   map[string]any{"disabled": true},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "ERROR"}}},
		"apps": map[string]any{
			"http": map[string]any{"servers": map[string]any{"s": map[string]any{
				"listen":          []string{"127.0.0.1:18082"},
				"automatic_https": map[string]any{"disable": true},
				// On by default with client auth: must accept the stand-in TLS state.
				"strict_sni_host": true,
				"routes": []any{
					map[string]any{
						"match":  []any{map[string]any{"protocol": "https"}},
						"handle": []any{map[string]any{"handler": "headers", "request": map[string]any{"set": map[string]any{"X-Caddy-Scheme": []string{"{http.request.scheme}"}}}}},
					},
					map[string]any{"handle": []any{map[string]any{
						"handler":   "reverse_proxy",
						"upstreams": []any{map[string]any{"dial": backend.Listener.Addr().String()}},
					}}},
				},
			}}},
			"cloudflare_tunnel": map[string]any{"token": fakeToken(t)},
		},
	})
	if err := caddy.Load(cfg, true); err != nil {
		t.Fatal(err)
	}
	defer caddy.Stop()

	for _, tc := range []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"https visitor", map[string]string{"Cf-Visitor": `{"scheme":"https"}`, "X-Forwarded-Proto": "https"},
			`xfp=https xff=203.0.113.7 early="" via=https`},
		{"http visitor", map[string]string{"Cf-Visitor": `{"scheme":"http"}`, "X-Forwarded-Proto": "http"},
			`xfp=http xff=203.0.113.7 early="" via=`},
		{"Cf-Visitor wins", map[string]string{"Cf-Visitor": `{"scheme":"http"}`, "X-Forwarded-Proto": "https"},
			`xfp=http xff=203.0.113.7 early="" via=`},
		{"X-Forwarded-Proto fallback", map[string]string{"X-Forwarded-Proto": "https"},
			`xfp=https xff=203.0.113.7 early="" via=https`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://App.Example.com:443/", nil)
			req.Host = "App.Example.com:443"
			req.Header.Set("Cf-Connecting-IP", "203.0.113.7")
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			(*made)[0].ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || rec.Body.String() != tc.want {
				t.Fatalf("HTTP %d %q, want %q", rec.Code, rec.Body.String(), tc.want)
			}
		})
	}
}

func TestParseResolverAddrs(t *testing.T) {
	got, err := parseResolverAddrs([]string{"1.1.1.1", "8.8.8.8:5353", "[2606:4700:4700::1111]:53", "2001:4860:4860::8888"})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.AddrPort{
		netip.MustParseAddrPort("1.1.1.1:53"),
		netip.MustParseAddrPort("8.8.8.8:5353"),
		netip.MustParseAddrPort("[2606:4700:4700::1111]:53"),
		netip.MustParseAddrPort("[2001:4860:4860::8888]:53"),
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, bad := range [][]string{{"dns.google:53"}, {"1.1.1.1:"}, {"1.1.1.1:99999"}, make([]string, 11)} {
		if _, err := parseResolverAddrs(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}
