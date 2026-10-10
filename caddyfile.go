package cftunnel

import (
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("cloudflare_tunnel", parseGlobalOption)
}

// parseGlobalOption sets up the app from the Caddyfile global options:
//
//	cloudflare_tunnel [<token>] {
//		token          <token>
//		server         <name>
//		service_name   <name>
//		protocol       auto|quic|http2
//		ha_connections <n>
//		grace_period   <duration>
//		label          <label>
//		dns_resolver_addrs <ip[:port]>...
//	}
func parseGlobalOption(d *caddyfile.Dispenser, _ any) (any, error) {
	app := new(App)
	if err := app.UnmarshalCaddyfile(d); err != nil {
		return nil, err
	}
	return httpcaddyfile.App{
		Name:  "cloudflare_tunnel",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}

func (a *App) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // option name
	if d.NextArg() {
		a.Token = d.Val()
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		key := d.Val()
		if key == "dns_resolver_addrs" {
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			a.DNSResolverAddrs = append(a.DNSResolverAddrs, args...)
			continue
		}
		if !d.NextArg() {
			return d.ArgErr()
		}
		val := d.Val()
		switch key {
		case "token":
			a.Token = val
		case "server":
			a.Server = val
		case "service_name":
			a.ServiceName = val
		case "protocol":
			a.Protocol = val
		case "label":
			a.Label = val
		case "ha_connections":
			n, err := strconv.Atoi(val)
			if err != nil || n < 1 {
				return d.Errf("invalid ha_connections %q", val)
			}
			a.HAConnections = n
		case "grace_period":
			dur, err := caddy.ParseDuration(val)
			if err != nil {
				return d.Errf("invalid grace_period %q: %v", val, err)
			}
			a.GracePeriod = caddy.Duration(dur)
		default:
			return d.Errf("unknown subdirective %q", key)
		}
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

var _ caddyfile.Unmarshaler = (*App)(nil)
