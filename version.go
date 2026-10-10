package cftunnel

import (
	"fmt"
	"runtime/debug"
	"strings"
)

// cloudflaredVersion is reported to the edge exactly as the official binary
// reports it. It must be the release tag of the pinned cloudflared commit:
// the connector protocol code running here *is* that release.
const (
	cloudflaredVersion = "2026.10.0"
	cloudflaredCommit  = "18cdfe0a6fc7" // tag 2026.10.0
)

// checkPinnedVersion refuses to start if go.mod was bumped without updating
// cloudflaredVersion, so we never claim a version we are not running.
func checkPinnedVersion() error {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return fmt.Errorf("no build info")
	}
	for _, dep := range bi.Deps {
		if dep.Path == "github.com/cloudflare/cloudflared" {
			v := dep.Version
			if dep.Replace != nil {
				v = dep.Replace.Version
			}
			if !strings.HasSuffix(v, cloudflaredCommit) {
				return fmt.Errorf("cloudflared dependency is %s, but cloudflaredVersion is pinned to %s (%s)",
					v, cloudflaredVersion, cloudflaredCommit)
			}
			return nil
		}
	}
	return fmt.Errorf("cloudflared dependency not found in build info")
}
