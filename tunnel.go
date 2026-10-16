package cftunnel

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"go.uber.org/zap"

	"github.com/cloudflare/cloudflared/client"
	"github.com/cloudflare/cloudflared/config"
	"github.com/cloudflare/cloudflared/connection"
	"github.com/cloudflare/cloudflared/credentials"
	"github.com/cloudflare/cloudflared/edgediscovery"
	"github.com/cloudflare/cloudflared/edgediscovery/allregions"
	"github.com/cloudflare/cloudflared/features"
	"github.com/cloudflare/cloudflared/ingress"
	"github.com/cloudflare/cloudflared/ingress/origins"
	"github.com/cloudflare/cloudflared/management"
	"github.com/cloudflare/cloudflared/orchestration"
	cfdsignal "github.com/cloudflare/cloudflared/signal"
	"github.com/cloudflare/cloudflared/supervisor"
	"github.com/cloudflare/cloudflared/tlsconfig"
	"github.com/cloudflare/cloudflared/tunnelrpc/pogs"
)

func init() {
	// supervisor.NewSupervisor registers its datagram metrics on the global
	// registry with MustRegister and no guard, so a second tunnel in the same
	// process (e.g. after a config change) would panic and take Caddy down.
	// Tolerate duplicate registrations instead; the first collectors stay
	// registered. Remove once cloudflared accepts a Registerer.
	prometheus.DefaultRegisterer = tolerantRegisterer{prometheus.DefaultRegisterer}
}

type tolerantRegisterer struct{ prometheus.Registerer }

func (r tolerantRegisterer) MustRegister(cs ...prometheus.Collector) {
	for _, c := range cs {
		if err := r.Register(c); err != nil {
			var already prometheus.AlreadyRegisteredError
			if !errors.As(err, &already) {
				panic(err)
			}
		}
	}
}

// tunnelOptions are the settings a running tunnel is built from. A change in
// any of them requires a new tunnel (see App.poolKey).
type tunnelOptions struct {
	Credentials   connection.Credentials `json:"credentials"`
	ServiceName   string                 `json:"service_name"`
	Protocol      string                 `json:"protocol"`
	HAConnections int                    `json:"ha_connections"`
	GracePeriod   time.Duration          `json:"grace_period"`
	Label         string                 `json:"label"`
	// DNSResolverAddrs, if set, are the resolvers for private-network DNS
	// (like --dns-resolver-addrs) instead of the auto-detected local one.
	DNSResolverAddrs []netip.AddrPort `json:"dns_resolver_addrs"`
}

func parseToken(s string) (connection.Credentials, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return connection.Credentials{}, fmt.Errorf("decoding tunnel token: %w", err)
	}
	var t connection.TunnelToken
	if err := json.Unmarshal(b, &t); err != nil {
		return connection.Credentials{}, fmt.Errorf("parsing tunnel token: %w", err)
	}
	return t.Credentials(), nil
}

// tunnel is a running cloudflared connector. It outlives Caddy config reloads
// (it is kept in a caddy.UsagePool) and forwards every non-management request
// to the current target handler, which each new config swaps in.
type tunnel struct {
	target atomic.Pointer[http.Handler]
	logs   *zapWriter

	// internalRules are the connector's ingress rules, kept for tests. They
	// are set before ready is closed.
	internalRules []ingress.Rule
	ready         chan struct{}

	cancel context.CancelFunc
	graceC chan struct{}
	done   chan struct{}
	grace  time.Duration
}

func (t *tunnel) setTarget(h http.Handler) { t.target.Store(&h) }

func (t *tunnel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// cloudflared calls this handler from its own stream goroutine, without
	// the recover net/http's server puts around handlers. Do the same here,
	// or any handler panic kills the process. reverse_proxy panics with
	// http.ErrAbortHandler on purpose when a streamed response breaks off
	// (a client closing an SSE stream, for one): net/http swallows that one
	// silently, and so do we.
	defer func() {
		if v := recover(); v != nil && v != http.ErrAbortHandler {
			buf := make([]byte, 64<<10)
			buf = buf[:runtime.Stack(buf, false)]
			t.logs.logger.Load().Error("panic serving tunnel request",
				zap.Any("panic", v), zap.String("host", r.Host),
				zap.String("uri", r.RequestURI), zap.ByteString("stack", buf))
		}
	}()
	h := t.target.Load()
	if h == nil {
		http.Error(w, "tunnel not ready", http.StatusServiceUnavailable)
		return
	}
	(*h).ServeHTTP(w, r)
}

// Destruct shuts the connector down the way the CLI does on SIGTERM: signal
// graceful shutdown, wait up to the grace period, then cancel.
func (t *tunnel) Destruct() error {
	close(t.graceC)
	if t.grace > 0 {
		select {
		case <-t.done:
		case <-time.After(t.grace):
		}
	}
	t.cancel()
	<-t.done
	return nil
}

// newTunnel is a variable so tests can replace it with a fake that does not
// dial Cloudflare.
var newTunnel = startTunnel

// startTunnel starts a connector in the background and returns at once:
// setup does DNS lookups (feature flags, edge discovery) that can take
// seconds, and must not hold up Caddy's startup or config reloads.
func startTunnel(opts tunnelOptions, logs *zapWriter) (*tunnel, error) {
	if err := checkPinnedVersion(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	t := &tunnel{
		logs:   logs,
		ready:  make(chan struct{}),
		cancel: cancel,
		graceC: make(chan struct{}),
		done:   make(chan struct{}),
		grace:  opts.GracePeriod,
	}
	go func() {
		defer close(t.done)
		if err := t.run(ctx, opts); err != nil && ctx.Err() == nil {
			logs.logger.Load().Error("tunnel stopped", zap.Error(err))
		}
	}()
	return t, nil
}

// run builds and runs the connector until shutdown, mirroring
// prepareTunnelConfig and runTunnel in cmd/cloudflared/tunnel with default
// flags.
func (t *tunnel) run(ctx context.Context, opts tunnelOptions) error {
	// Like the CLI, tee every log event to the management logger so the
	// dashboard's live log streaming (/logs) works. It filters per session.
	mgmtLogger := management.NewLogger()
	log := zerolog.New(zerolog.MultiLevelWriter(t.logs, mgmtLogger)).With().Timestamp().Logger()

	creds := opts.Credentials
	featureSelector, err := features.NewFeatureSelector(ctx, creds.AccountTag, nil, false, &log)
	if err != nil {
		return fmt.Errorf("creating feature selector: %w", err)
	}
	clientConfig, err := client.NewConfig(cloudflaredVersion, runtime.GOOS+"_"+runtime.GOARCH, featureSelector)
	if err != nil {
		return err
	}
	log.Info().Msgf("Version %s, connector ID %s", cloudflaredVersion, clientConfig.ConnectorID)
	// The CLI always appends this tag (see prepareTunnelConfig).
	tags := []pogs.Tag{{Name: "ID", Value: clientConfig.ConnectorID.String()}}

	protocolSelector, err := connection.NewProtocolSelector(opts.Protocol, &log)
	if err != nil {
		return err
	}
	edgeTLS := map[connection.Protocol]*tls.Config{}
	for _, p := range connection.ProtocolList {
		s := p.TLSSettings()
		c, err := tlsconfig.CreateTunnelConfig("", s.ServerName)
		if err != nil {
			return fmt.Errorf("creating edge TLS config: %w", err)
		}
		if len(s.NextProtos) > 0 {
			c.NextProtos = s.NextProtos
		}
		edgeTLS[p] = c
	}

	warp := ingress.NewWarpRoutingConfig(&config.WarpRoutingConfig{})
	dialer := ingress.NewOriginDialer(ingress.OriginConfig{
		DefaultDialer:   ingress.NewDialer(warp),
		TCPWriteTimeout: 0,
	}, &log)

	// Required: the supervisor dereferences it unconditionally. A private
	// registry avoids duplicate registration when a tunnel is recreated.
	// With static addresses the service skips its refresh loop, which looks
	// up the local resolver every 5 minutes and fails when the first
	// nameserver in /etc/resolv.conf does not answer.
	dnsMetrics := origins.NewMetrics(prometheus.NewRegistry())
	dnsService := origins.NewDNSResolverService(origins.NewDNSDialer(), &log, dnsMetrics)
	if len(opts.DNSResolverAddrs) > 0 {
		dnsService = origins.NewStaticDNSResolverService(opts.DNSResolverAddrs, origins.NewDNSDialer(), &log, dnsMetrics)
	}
	dialer.AddReservedService(dnsService, []netip.AddrPort{origins.VirtualDNSServiceAddr})

	tunnelConfig := &supervisor.TunnelConfig{
		ClientConfig:       clientConfig,
		GracePeriod:        opts.GracePeriod,
		Region:             creds.Endpoint,
		EdgeIPVersion:      allregions.Auto,
		HAConnections:      opts.HAConnections,
		Log:                &log,
		Observer:           connection.NewObserver(&log),
		ReportedVersion:    cloudflaredVersion,
		Tags:               tags,
		Retries:            5,
		MaxEdgeAddrRetries: 8,
		NamedTunnel:        &connection.TunnelProperties{Credentials: creds},
		ProtocolSelector:   protocolSelector,
		EdgeTLSConfigs:     edgeTLS,
		RPCTimeout:         5 * time.Second,
		// CLI defaults (--quic-connection-level-flow-control-limit, --quic-stream-level-flow-control-limit).
		QUICConnectionLevelFlowControlLimit: 30 * (1 << 20),
		QUICStreamLevelFlowControlLimit:     6 * (1 << 20),
		OriginDialerService:                 dialer,
		OriginDNSService:                    dnsService,
	}

	// Management service (/ping, /host_details, /logs, /metrics, pprof), wired
	// exactly as cmd/cloudflared/tunnel/cmd.go does with default flags.
	serviceIP := "198.41.200.113:80" // --service-op-ip default
	if edgeAddrs, err := edgediscovery.ResolveEdge(&log, tunnelConfig.Region, tunnelConfig.EdgeIPVersion); err == nil {
		if addr, err := edgeAddrs.GetAddrForRPC(); err == nil {
			serviceIP = addr.TCP.String()
		}
	}
	managementHostname := "management.argotunnel.com" // --management-hostname default
	if creds.Endpoint == credentials.FedEndpoint {
		managementHostname = credentials.FedRampHostname
	}
	mgmt := management.New(managementHostname, true /* --management-diagnostics */, serviceIP,
		clientConfig.ConnectorID, opts.Label, &log, mgmtLogger)

	// Order matters: the management rule must come before the catch-all,
	// which matches every hostname and hands the request to Caddy.
	t.internalRules = []ingress.Rule{
		ingress.NewManagementRule(mgmt),
		{Service: newLocalService(opts.ServiceName, t)},
	}
	close(t.ready)

	orch, err := orchestration.NewOrchestrator(ctx, &orchestration.Config{
		Ingress:             &ingress.Ingress{},
		WarpRouting:         warp,
		OriginDialerService: dialer,
	}, tags, t.internalRules, &log)
	if err != nil {
		return err
	}

	// Shut down during setup: don't connect at all.
	select {
	case <-t.graceC:
		return nil
	default:
	}
	return supervisor.StartTunnelDaemon(ctx, tunnelConfig, orch, cfdsignal.New(make(chan struct{})), t.graceC)
}

// localService serves requests in-process with an http.Handler under a custom
// name (shown as "originService" in request logs). ingress.OriginService is
// sealed by an unexported start() method; embedding *ingress.ManagementService
// promotes it, and String/MarshalJSON are overridden to rename it.
type localService struct {
	*ingress.ManagementService
	name string
}

func newLocalService(name string, h http.Handler) *localService {
	return &localService{ManagementService: &ingress.ManagementService{HTTPLocalProxy: h}, name: name}
}

func (s *localService) String() string { return s.name }

func (s *localService) MarshalJSON() ([]byte, error) { return json.Marshal(s.name) }
