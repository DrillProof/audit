// Command drillproof runs the read-only DrillProof recoverability audit.
//
// Open source, Apache-2.0: github.com/drillproof/audit
//
// This lives in cmd/drillproof/ rather than at the module root for one reason:
// `go install` names the binary after the last element of the PACKAGE path. At
// the root that is the module name — `audit` — which would make every documented
// command read `audit audit scan`. Here it is `drillproof`, so a `go install`
// user gets exactly the same binary name as someone who installed from a
// release archive or Homebrew.
//
//	go install github.com/drillproof/audit/cmd/drillproof@latest
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
