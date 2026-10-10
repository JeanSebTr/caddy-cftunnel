# caddy-cftunnel (prototype)

A Caddy app that runs a Cloudflare Tunnel connector inside Caddy. Tunnel
traffic is served by one of Caddy's HTTP servers, so the same sites answer on
regular listeners (`:80`/`:443`) and through the tunnel.

```caddyfile
{
	cloudflare_tunnel {env.TUNNEL_TOKEN} {
		server         srv0      # default: the server on the HTTPS port, or the only one
		service_name   caddy     # "originService" in cloudflared request logs
		protocol       auto      # auto | quic | http2
		ha_connections 4
		grace_period   30s
		label          my-host   # connector name in the dashboard
		dns_resolver_addrs 1.1.1.1:53 8.8.8.8   # see below
	}
}

app.example.com {
	reverse_proxy localhost:8080
}
```

Point the hostnames at the tunnel in Cloudflare (a public hostname on the
tunnel, or a `CNAME` to `<tunnel-id>.cfargotunnel.com`, wildcards included).

`dns_resolver_addrs` (like cloudflared's `--dns-resolver-addrs`; `ip:port`,
or `ip` for port 53, at most 10) sets the resolvers used for DNS queries from
private-network (WARP) clients. Without it, cloudflared detects the local
resolver every 5 minutes with a lookup that only gets 5 seconds. If the first
nameserver in `/etc/resolv.conf` does not answer, that lookup always fails and
logs `Failed to refresh DNS local resolver ... i/o timeout`. On macOS, the
system resolver ignores `/etc/resolv.conf` but Go's resolver does not.

## Build

```sh
go build -o caddy ./cmd/caddy     # Go 1.26+
```

With xcaddy, repeat the `replace` directives from `go.mod`: dependents do
not inherit them.

```sh
xcaddy build \
  --with example.com/caddy-cftunnel=./ \
  --replace github.com/quic-go/quic-go=github.com/chungthuang/quic-go@v0.45.1-0.20260529212404-a9fddf436fc4 \
  --replace github.com/urfave/cli/v2=github.com/ipostelnik/cli/v2@v2.3.1-0.20210324024421-b6ea8234fe3d \
  --replace go.opentelemetry.io/contrib/propagators=./third_party/otel-propagators-empty
```

## How it works

- The connector is cloudflared's own code (`supervisor`, `orchestration`),
  pinned to release 2026.10.0 and reporting that version to the edge.
- Requests to `management.argotunnel.com` (dashboard host details, live logs)
  are answered by cloudflared. Everything else goes to
  `caddyhttp.Server.ServeHTTP`.
- The connector lives in a `caddy.UsagePool`, so config reloads keep it
  connected and only swap the target server. Changing a tunnel setting starts
  a new connector before the old one shuts down gracefully.
- `Cf-Connecting-IP` becomes the request's remote address: Caddy logs,
  matchers and `reverse_proxy` see the visitor's IP. No `trusted_proxies`
  configuration is needed.

## Caveats

- Not a supported cloudflared API: it relies on `ingress.ManagementService`
  to plug in a handler. Pin the commit; bump `cloudflaredVersion` with it.
- Caddy's HTTP/3 runs on cloudflared's quic-go fork (v0.59.1-based, Caddy
  expects v0.63.0). It builds; runtime behavior is untested. Use
  `servers { protocols h1 h2 }` to turn HTTP/3 off.
- Cloudflare terminates the visitor's TLS. When `Cf-Visitor` (or
  `X-Forwarded-Proto`) says the visitor used HTTPS, the request gets a
  stand-in TLS state: `{http.request.scheme}` is `https`, `protocol https`
  matches, `reverse_proxy` sends `X-Forwarded-Proto: https`. TLS version,
  cipher and client certificates are not known, so their placeholders are empty.
- Only HTTP and WebSocket traffic is served; WARP routing / raw TCP is not.
- Duplicate Prometheus registrations are ignored process-wide, because
  cloudflared's supervisor registers metrics unguarded on the global registry.
