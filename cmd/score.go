package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/drillproof/audit/internal/report"
	"github.com/drillproof/audit/internal/score"
)

func newScoreCmd() *cobra.Command {
	var failUnder int

	cmd := &cobra.Command{
		Use:   "score",
		Short: "Print just the Recoverability Score (for CI gating)",
		Long: `Print the Recoverability Score on its own.

With --fail-under, exits non-zero when the score is below the threshold, so it
can gate a pipeline or drive a badge:

  drillproof audit score --fail-under 80

Exit codes:
  0  score meets the threshold (or no threshold was set)
  1  an error occurred
  2  score is below the threshold`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := performScan(cmd)
			if err != nil {
				return err
			}

			o := newOut(cmd.OutOrStdout())

			// JSON and SARIF stay machine-readable even for `score`.
			switch flags.Output {
			case outputJSON:
				if err := report.RenderJSON(cmd.OutOrStdout(), result); err != nil {
					return err
				}
			case outputSARIF:
				if err := report.RenderSARIF(cmd.OutOrStdout(), result); err != nil {
					return err
				}
			default:
				o.printf("Recoverability Score: %d/100  (%d critical gap%s)",
					result.Score.Value, result.Score.CriticalGaps,
					pluralSuffix(result.Score.CriticalGaps))

				if cmd.Flags().Changed("fail-under") && result.Score.Value < failUnder {
					o.printf("  (below threshold %d)", failUnder)
				}
				o.println()

				if result.Score.Blocked > 0 {
					o.printf(
						"%d check(s) blocked by missing permissions — run `drillproof audit init`.\n",
						result.Score.Blocked)
				}
				if result.Score.Moot > 0 {
					o.printf("%d check(s) not applicable.\n", result.Score.Moot)
				}

				if flags.Explain {
					o.println()
					for _, line := range score.Explain(result.Score) {
						o.println(line)
					}
				}
			}

			if err := o.Err(); err != nil {
				return err
			}

			// Gate last, so the score is always printed before we exit.
			if cmd.Flags().Changed("fail-under") && result.Score.Value < failUnder {
				return &ExitCodeError{
					Code: 2,
					Err: fmt.Errorf("recoverability score %d is below threshold %d",
						result.Score.Value, failUnder),
				}
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&failUnder, "fail-under", 0,
		"exit non-zero if the score is below this value (0-100)")
	return cmd
}

func pluralSuffix(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
