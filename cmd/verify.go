package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newVerifyCmd is a deliberate stub.
//
// verify will perform an actual isolated test-restore. That needs elevated
// permissions and real isolation guarantees, which makes it security-critical —
// so v1 ships it as an honest "not yet" rather than something half-safe. The
// command exists so the shape of the tool is clear, and it exits non-zero so no
// pipeline can mistake it for a passing check.
func newVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "(coming soon) Perform a safe, isolated test-restore",
		Long: `Coming soon — not available in this version.

'scan' can prove a backup has never been test-restored. It cannot prove a
restore would succeed; only performing the restore does that.

'verify' will do exactly that: recover a real restore point into an isolated,
throwaway environment in your account, assert that it works, tear the
environment down, and leave a dated evidence record.

It is not in v1 on purpose. A restore needs write permissions and genuine
isolation guarantees, and shipping that carelessly is how an audit tool becomes
an incident. It is being built with that as the first requirement rather than
the last.

In the meantime:
  drillproof audit scan     find which restore points have never been tested
  https://drillproof.com/audit   have a real test-restore run with you, free`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o := newOut(cmd.OutOrStdout())
			o.println(cmd.Long)
			if err := o.Err(); err != nil {
				return err
			}
			// Exit 3 (distinct from an error or a score gate) so a pipeline that
			// wires this up early gets an unambiguous "not implemented".
			return &ExitCodeError{
				Code: 3,
				Err:  fmt.Errorf("verify is not available in v1"),
			}
		},
	}
}
