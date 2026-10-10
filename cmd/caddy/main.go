// Command caddy is Caddy with the cloudflare_tunnel app built in. It is the
// equivalent of `xcaddy build --with github.com/JeanSebTr/caddy-cftunnel=.`, kept here
// so the module builds and runs with plain `go build`.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"

	_ "github.com/JeanSebTr/caddy-cftunnel"
)

func main() {
	caddycmd.Main()
}
