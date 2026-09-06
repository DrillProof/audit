package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	awsx "github.com/drillproof/audit/internal/aws"
	"github.com/drillproof/audit/internal/k8s"
	"github.com/drillproof/audit/internal/model"
	"github.com/drillproof/audit/internal/report"
)

// lastResult caches the most recent scan so `report` can re-render it without
// hitting AWS again within the same process. Across processes, `report` re-scans
// — the alternative is writing scan output to disk, which for an infrastructure
// posture report is a privacy decision the user should make explicitly.
var lastResult *model.Result

func newScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Inventory backup coverage and configuration across AWS (read-only)",
		Long: `Inventory EBS volumes, RDS databases, and EKS cluster state across your
enabled regions, run the five recoverability checks, and print a table plus
your Recoverability Score.

Read-only: only Describe/List/Get APIs are called.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd)
		},
	}
}

// runScan is shared by `audit` and `audit scan`.
func runScan(cmd *cobra.Command) error {
	result, err := performScan(cmd)
	if err != nil {
		return err
	}
	return renderResult(cmd, result)
}

// performScan does the work and caches the result.
func performScan(cmd *cobra.Command) (*model.Result, error) {
	ctx, cancel := cmdContext()
	defer cancel()

	start := time.Now()
	logf("resolving credentials (profile=%q)", flags.Profile)

	region := ""
	if len(flags.Regions) == 1 {
		region = flags.Regions[0]
	}

	provider, err := awsx.LoadProvider(ctx, flags.Profile, region)
	if err != nil {
		return nil, fmt.Errorf("load AWS credentials: %w", err)
	}

	// Cluster state can only be assessed from inside the cluster, so this is
	// opt-in. Without it the cluster-state check reports "not assessed" rather
	// than guessing.
	var cluster *k8s.State
	if flags.Kubeconfig != "" || flags.KubeContext != "" {
		logf("inspecting cluster (kubeconfig=%q context=%q)", flags.Kubeconfig, flags.KubeContext)
		state := k8s.Inspect(ctx, flags.Kubeconfig, flags.KubeContext)
		cluster = &state
		logf("cluster: %s", state.Summary())
	}

	logf("scanning (regions=%v)", flags.Regions)
	result, err := awsx.Scan(ctx, provider, awsx.ScanOptions{
		Regions:         flags.Regions,
		Checks:          checksConfig(),
		Version:         version,
		Cluster:         cluster,
		BucketAllowList: flags.BucketAllowList,
	})
	if err != nil {
		return nil, err
	}

	logf("scan finished in %s", awsx.ScanDuration(start))
	lastResult = result
	return result, nil
}

// renderResult writes a result in whichever format was requested.
func renderResult(cmd *cobra.Command, result *model.Result) error {
	out := cmd.OutOrStdout()

	switch flags.Output {
	case outputJSON:
		return report.RenderJSON(out, result)
	case outputSARIF:
		return report.RenderSARIF(out, result)
	default:
		return report.RenderTable(out, result, report.Options{
			NoColor: flags.NoColor || !isTerminal(),
			Quiet:   flags.Quiet,
			Explain: flags.Explain,
			Checks:  checksConfig(),
		})
	}
}

// isTerminal reports whether stdout is a TTY, so piping the table into a file
// or another process does not embed ANSI escapes.
func isTerminal() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
