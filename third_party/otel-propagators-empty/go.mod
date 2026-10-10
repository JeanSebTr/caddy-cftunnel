// Empty stand-in for the last monolithic propagators release (v0.22.0), which
// cloudflared requires. It bundles packages such as propagators/ot that Caddy
// gets from the newer split modules, making those imports ambiguous. With this
// replacement, cloudflared's propagators/jaeger import resolves to the split
// go.opentelemetry.io/contrib/propagators/jaeger module instead.
module go.opentelemetry.io/contrib/propagators

go 1.22
