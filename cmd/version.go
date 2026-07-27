package cmd

import (
	"encoding/json"
	"runtime"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build info",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o := newOut(cmd.OutOrStdout())

			info := map[string]string{
				"version":   version,
				"commit":    commit,
				"built":     date,
				"goVersion": runtime.Version(),
				"platform":  runtime.GOOS + "/" + runtime.GOARCH,
			}

			if flags.Output == outputJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}

			o.printf("drillproof-audit %s\n", version)
			o.printf("  commit:   %s\n", commit)
			o.printf("  built:    %s\n", date)
			o.printf("  go:       %s\n", runtime.Version())
			o.printf("  platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
			return o.Err()
		},
	}
}
