// Command drillproof runs the read-only DrillProof recoverability audit.
//
// Open source, Apache-2.0: github.com/drillproof/audit
package main

import (
	"os"

	"github.com/drillproof/audit/cmd"
)

// Injected at build time by goreleaser via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.SetBuildInfo(version, commit, date)
	os.Exit(cmd.Execute())
}
