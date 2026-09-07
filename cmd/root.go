// Package cmd wires the cobra command surface.
//
// # Why the tree looks like this
//
// The spec documents the UX as `drillproof audit <command>` (§3) but also as
// `docker run drillproof/audit scan` (§8) — two different shapes. Both are
// honoured: the binary is `drillproof` with an `audit` command group, and the
// container image sets its entrypoint to `["/drillproof", "audit"]`, so the
// documented docker invocation resolves to the same place.
package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/drillproof/audit/internal/checks"
)

// Build info, injected at link time by goreleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// SetBuildInfo lets main.go pass through ldflags values.
func SetBuildInfo(v, c, d string) {
	if v != "" {
		version = v
	}
	if c != "" {
		commit = c
	}
	if d != "" {
		date = d
	}
}

// globalFlags holds the flags shared by every subcommand.
type globalFlags struct {
	Profile     string
	Regions     []string
	Output      string
	Kubeconfig  string
	KubeContext string
	NoColor     bool
	Quiet       bool
	Verbose     bool
	Provider    string
	WarnAfter   time.Duration
	FailAfter   time.Duration
	Explain     bool
	// BucketAllowList narrows S3 discovery to named buckets, for customers
	// whose security team will not grant account-wide s3:ListAllMyBuckets.
	BucketAllowList []string
}

var flags globalFlags

const (
	outputTable = "table"
	outputJSON  = "json"
	outputSARIF = "sarif"
)

// Execute runs the CLI.
func Execute() int {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		// Cobra already printed usage errors; exit codes are set by the
		// subcommands via ExitCodeError.
		var ec *ExitCodeError
		if asExitCode(err, &ec) {
			return ec.Code
		}
		return 1
	}
	return 0
}

// ExitCodeError lets a subcommand choose the process exit code — needed by
// `score --fail-under` for CI gating.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string { return e.Err.Error() }
func (e *ExitCodeError) Unwrap() error { return e.Err }

func asExitCode(err error, target **ExitCodeError) bool {
	for err != nil {
		if ec, ok := err.(*ExitCodeError); ok {
			*target = ec
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "drillproof",
		Short:         "Prove your backups are actually recoverable",
		SilenceUsage:  true,
		SilenceErrors: false,
	}

	root.AddCommand(newAuditCmd())
	return root
}

// auditLong is shown by `drillproof audit --help`. The privacy promise is here
// deliberately: the spec requires it in --help, not only the README, because
// engineers will not run a tool that might exfiltrate their infra posture.
const auditLong = `Audit whether your AWS backups could actually be restored.

Inventories EBS volumes, RDS databases, and EKS cluster state across your
enabled regions, runs five checks against them, and prints a Recoverability
Score with the critical gaps.

The five checks:
  coverage         does a backup exist at all?
  freshness        how old is the most recent successful backup?
  immutability     is it on WORM storage, or can it be deleted?
  redundancy       is a copy isolated in another region?
  restore-testing  has a restore ever actually been performed?

PRIVACY
  Runs locally with your own credentials, and is strictly read-only — it calls
  only Describe/List/Get APIs and cannot create, modify, restore, or delete
  anything.

  No data leaves your machine. This tool does not phone home and does not
  upload findings anywhere. It reads configuration and metadata only, never the
  contents of your backups or databases.

  Run 'drillproof audit init' to see the exact least-privilege IAM policy it
  needs.`

func newAuditCmd() *cobra.Command {
	audit := &cobra.Command{
		Use:   "audit",
		Short: "Read-only recoverability audit of your AWS backups",
		Long:  auditLong,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return bindFlags(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Bare `drillproof audit` is most usefully a scan.
			return runScan(cmd)
		},
	}

	pf := audit.PersistentFlags()
	pf.StringVar(&flags.Profile, "profile", "", "AWS profile (default: standard AWS credential chain)")
	pf.StringSliceVar(&flags.Regions, "region", nil, "region(s) to scan (default: all enabled regions, auto-discovered)")
	pf.StringVarP(&flags.Output, "output", "o", outputTable, "output format: table | json | sarif")
	pf.StringVar(&flags.Kubeconfig, "kubeconfig", "", "path to kubeconfig for EKS/Velero checks (optional)")
	pf.StringVar(&flags.KubeContext, "context", "", "kube context to use (optional)")
	pf.BoolVar(&flags.NoColor, "no-color", false, "disable color (also respects NO_COLOR)")
	pf.BoolVarP(&flags.Quiet, "quiet", "q", false, "only print the score and failures")
	pf.BoolVarP(&flags.Verbose, "verbose", "v", false, "verbose logging to stderr")
	pf.BoolVar(&flags.Explain, "explain", false, "show how the score was calculated")
	pf.DurationVar(&flags.WarnAfter, "warn-after", 24*time.Hour, "flag backups older than this as a warning")
	pf.DurationVar(&flags.FailAfter, "fail-after", 7*24*time.Hour, "flag backups older than this as a failure")
	pf.StringSliceVar(&flags.BucketAllowList, "bucket", nil,
		"Limit S3 scanning to these buckets (repeatable). Use when your security team will not grant account-wide s3:ListAllMyBuckets.")

	// Reserved for future clouds; AWS is the only valid value in v1, and the
	// provider is auto-detected from the credential chain so nobody needs it.
	pf.StringVar(&flags.Provider, "provider", "aws", "cloud provider (v1: aws only)")
	_ = pf.MarkHidden("provider")

	audit.AddCommand(
		newScanCmd(),
		newScoreCmd(),
		newReportCmd(),
		newInitCmd(),
		newVerifyCmd(),
		newVersionCmd(),
	)
	return audit
}

// bindFlags wires viper so DRILLPROOF_* env vars work alongside flags.
func bindFlags(cmd *cobra.Command) error {
	v := viper.New()
	v.SetEnvPrefix("DRILLPROOF")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	if err := v.BindPFlags(cmd.Flags()); err != nil {
		return err
	}

	if flags.Provider != "" && strings.ToLower(flags.Provider) != "aws" {
		return fmt.Errorf("--provider %q is not supported in v1; only aws is available", flags.Provider)
	}

	switch flags.Output {
	case outputTable, outputJSON, outputSARIF:
	default:
		return fmt.Errorf("--output must be one of table, json, sarif (got %q)", flags.Output)
	}

	if flags.FailAfter <= flags.WarnAfter {
		return fmt.Errorf("--fail-after (%s) must be greater than --warn-after (%s)", flags.FailAfter, flags.WarnAfter)
	}

	return nil
}

// checksConfig builds the check thresholds from flags.
func checksConfig() checks.Config {
	return checks.Config{
		FreshWarnAfter: flags.WarnAfter,
		FreshFailAfter: flags.FailAfter,
		Now:            time.Now().UTC(),
	}
}

// cmdContext gives every command a cancellable context so Ctrl-C never leaves
// the tool hanging mid-scan.
func cmdContext() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}

func logf(format string, args ...any) {
	if flags.Verbose {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}
