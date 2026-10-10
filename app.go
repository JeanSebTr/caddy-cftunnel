// Package cftunnel is a Caddy app that runs a Cloudflare Tunnel connector
// in-process and serves its traffic with one of Caddy's HTTP servers, so the
// same sites answer on regular listeners (:80/:443) and on the tunnel.
package cftunnel

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/cloudflare/cloudflared/connection"
)

func init() {
	caddy.RegisterModule(App{})
}

// tunnels keeps connectors alive across config reloads: Caddy starts the new
// config before stopping the old one, so an unchanged tunnel is loaded twice,
// then released once, and never reconnects.
var tunnels = caddy.NewUsagePool()

// App runs a Cloudflare Tunnel connector and serves its traffic with a Caddy
// HTTP server. Requests to Cloudflare's management hostname are answered by
// cloudflared itself, as with the official binary.
type App struct {
	// Tunnel token, as printed by `cloudflared tunnel token <name>`.
	// Placeholders such as {env.TUNNEL_TOKEN} are supported.
	Token string `json:"token,omitempty"`

	// Name of the HTTP server (in apps.http.servers) that serves tunnel
	// traffic. Default: the server listening on the HTTPS port, or the only
	// server if there is just one.
	Server string `json:"server,omitempty"`

	// Name shown as "originService" in cloudflared's request logs.
	// Default: "caddy".
	ServiceName string `json:"service_name,omitempty"`

	// Transport to the edge: "auto" (default), "quic" or "http2".
	Protocol string `json:"protocol,omitempty"`

	// Number of connections to the edge. Default: 4, like cloudflared.
	HAConnections int `json:"ha_connections,omitempty"`

	// Time to let in-flight requests finish on shutdown. Default: 30s.
	GracePeriod caddy.Duration `json:"grace_period,omitempty"`

	// Connector label shown in the dashboard. Default: the system hostname.
	Label string `json:"label,omitempty"`

	// DNS resolvers ("ip:port", or "ip" for port 53, at most 10) for DNS
	// queries from private-network (WARP) clients, like cloudflared's
	// --dns-resolver-addrs. Default: the local resolver, detected every
	// 5 minutes from a lookup that uses the first nameserver in resolv.conf.
	DNSResolverAddrs []string `json:"dns_resolver_addrs,omitempty"`

	opts    tunnelOptions
	key     string
	httpApp *caddyhttp.App
	logger  *zap.Logger
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "cloudflare_tunnel",
		New: func() caddy.Module { return new(App) },
	}
}

func (a *App) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()

	token := caddy.NewReplacer().ReplaceAll(a.Token, "")
	if token == "" {
		return fmt.Errorf("token is required")
	}
	creds, err := parseToken(token)
	if err != nil {
		return err
	}

	a.opts = tunnelOptions{
		Credentials:   creds,
		ServiceName:   cmpOr(a.ServiceName, "caddy"),
		Protocol:      cmpOr(a.Protocol, connection.AutoSelectFlag),
		HAConnections: cmpOr(a.HAConnections, 4),
		GracePeriod:   cmpOr(time.Duration(a.GracePeriod), 30*time.Second),
		Label:         a.Label,
	}
	if a.opts.GracePeriod > connection.MaxGracePeriod {
		return fmt.Errorf("grace_period must be at most %s", connection.MaxGracePeriod)
	}
	if a.opts.DNSResolverAddrs, err = parseResolverAddrs(a.DNSResolverAddrs); err != nil {
		return err
	}
	a.key, err = poolKey(a.opts)
	if err != nil {
		return err
	}

	// Loading the http app here also guarantees it is provisioned first.
	httpApp, err := ctx.App("http")
	if err != nil {
		return fmt.Errorf("loading http app: %w", err)
	}
	a.httpApp = httpApp.(*caddyhttp.App)
	return nil
}

func (a *App) Start() error {
	name, srv, err := a.pickServer()
	if err != nil {
		return err
	}

	val, loaded, err := tunnels.LoadOrNew(a.key, func() (caddy.Destructor, error) {
		return newTunnel(a.opts, newZapWriter(a.logger))
	})
	if err != nil {
		return fmt.Errorf("starting tunnel: %w", err)
	}
	t := val.(*tunnel)
	t.logs.setLogger(a.logger)
	t.setTarget(fromTunnel(srv))

	a.logger.Info("serving tunnel traffic",
		zap.String("tunnel_id", a.opts.Credentials.TunnelID.String()),
		zap.String("server", name),
		zap.Bool("reused_connection", loaded))
	return nil
}

func (a *App) Stop() error {
	_, err := tunnels.Delete(a.key)
	return err
}

// poolKey identifies a running tunnel by its ID and every setting it was built
// with. A changed setting starts a new connector next to the old one (multiple
// replicas of a tunnel are allowed) before the old one shuts down gracefully.
func poolKey(opts tunnelOptions) (string, error) {
	b, err := json.Marshal(opts)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return opts.Credentials.TunnelID.String() + "/" + hex.EncodeToString(sum[:8]), nil
}

func (a *App) pickServer() (string, *caddyhttp.Server, error) {
	if a.Server != "" {
		srv, ok := a.httpApp.Servers[a.Server]
		if !ok {
			return "", nil, fmt.Errorf("http server %q not found (have: %s)", a.Server, serverNames(a.httpApp))
		}
		return a.Server, srv, nil
	}

	httpsPort := a.httpApp.HTTPSPort
	if httpsPort == 0 {
		httpsPort = caddyhttp.DefaultHTTPSPort
	}
	var matches []string
	for name, srv := range a.httpApp.Servers {
		for _, l := range srv.Listen {
			addr, err := caddy.ParseNetworkAddress(l)
			if err == nil && addr.StartPort <= uint(httpsPort) && uint(httpsPort) <= addr.EndPort {
				matches = append(matches, name)
				break
			}
		}
	}
	if len(matches) == 0 && len(a.httpApp.Servers) == 1 {
		for name := range a.httpApp.Servers {
			matches = append(matches, name)
		}
	}
	if len(matches) != 1 {
		return "", nil, fmt.Errorf("cannot choose an http server for tunnel traffic, set \"server\" (have: %s)", serverNames(a.httpApp))
	}
	return matches[0], a.httpApp.Servers[matches[0]], nil
}

// parseResolverAddrs parses dns_resolver_addrs with the same rules as
// cloudflared's --dns-resolver-addrs, also accepting a bare IP for port 53.
func parseResolverAddrs(input []string) ([]netip.AddrPort, error) {
	if len(input) > 10 {
		return nil, fmt.Errorf("dns_resolver_addrs: too many addresses provided, max: 10")
	}
	var addrs []netip.AddrPort
	for _, val := range input {
		if ip, err := netip.ParseAddr(val); err == nil {
			addrs = append(addrs, netip.AddrPortFrom(ip, 53))
			continue
		}
		addr, err := netip.ParseAddrPort(val)
		if err != nil {
			return nil, fmt.Errorf("dns_resolver_addrs: invalid address %q: want ip:port or ip", val)
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

func serverNames(app *caddyhttp.App) string {
	names := make([]string, 0, len(app.Servers))
	for name := range app.Servers {
		names = append(names, name)
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}

// fromTunnel adapts tunnel requests for a Caddy server. Every tunnel request
// comes from Cloudflare's edge, which sets these headers itself, so they are
// trusted:
//   - Cf-Connecting-IP becomes the remote address: Caddy's logs, matchers and
//     reverse_proxy see the visitor's IP.
//   - If the visitor used HTTPS, the request gets a TLS state, since Cloudflare
//     terminated TLS for us: {http.request.scheme} is https, the protocol
//     matcher works, and reverse_proxy sends X-Forwarded-Proto: https.
func fromTunnel(srv *caddyhttp.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ip, err := netip.ParseAddr(r.Header.Get("Cf-Connecting-IP")); err == nil {
			r.RemoteAddr = netip.AddrPortFrom(ip, 0).String()
		}
		if visitorUsedHTTPS(r) {
			r.TLS = edgeTLSState(r)
		}
		srv.ServeHTTP(w, r)
	})
}

// visitorUsedHTTPS reads the visitor's scheme from Cf-Visitor, which
// Cloudflare sets on every proxied request, falling back to X-Forwarded-Proto.
func visitorUsedHTTPS(r *http.Request) bool {
	if v := r.Header.Get("Cf-Visitor"); v != "" {
		var visitor struct {
			Scheme string `json:"scheme"`
		}
		if json.Unmarshal([]byte(v), &visitor) == nil && visitor.Scheme != "" {
			return strings.EqualFold(visitor.Scheme, "https")
		}
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// edgeTLSState stands in for the visitor's TLS connection, which ended at
// Cloudflare. HandshakeComplete must be true, or Caddy treats the request as
// 0-RTT early data. ServerName is the request host, so strict_sni_host (on by
// default with client auth) accepts it. Version, cipher suite and certificates
// are unknown and left empty.
func edgeTLSState(r *http.Request) *tls.ConnectionState {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return &tls.ConnectionState{
		HandshakeComplete: true,
		ServerName:        strings.ToLower(host),
	}
}

func cmpOr[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// Interface guards
var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
	_ caddy.Destructor  = (*tunnel)(nil)
)
