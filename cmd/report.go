package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/drillproof/audit/internal/report"
)

func newReportCmd() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Render the scan as html, json, or sarif",
		Long: `Render a scan in a machine-readable or shareable format.

  json   the full result, including the score breakdown
  sarif  SARIF 2.1.0, so findings surface in CI code-scanning UIs
  html   a single self-contained file you can send to someone

Note: findings are never written to disk unless you redirect the output, and
nothing is uploaded anywhere.

  drillproof audit report --format sarif > drillproof.sarif`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// --format is the documented flag for this command; fall back to
			// the global --output so both work.
			chosen := format
			if !cmd.Flags().Changed("format") {
				chosen = flags.Output
			}

			result := lastResult
			if result == nil {
				var err error
				result, err = performScan(cmd)
				if err != nil {
					return err
				}
			}

			out := cmd.OutOrStdout()
			switch chosen {
			case outputJSON:
				return report.RenderJSON(out, result)
			case outputSARIF:
				return report.RenderSARIF(out, result)
			case "html":
				return report.RenderHTML(out, result)
			case outputTable:
				return report.RenderTable(out, result, report.Options{
					NoColor: flags.NoColor || !isTerminal(),
					Quiet:   flags.Quiet,
					Explain: flags.Explain,
					Checks:  checksConfig(),
				})
			default:
				return fmt.Errorf("--format must be one of html, json, sarif, table (got %q)", chosen)
			}
		},
	}

	cmd.Flags().StringVar(&format, "format", "json", "output format: html | json | sarif | table")
	return cmd
}
