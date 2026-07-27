package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/drillproof/audit/internal/iam"
)

func newInitCmd() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Emit the exact least-privilege IAM policy and Terraform needed",
		Long: `Print exactly the permissions this tool needs — nothing more.

Every action is a Describe, List, or Get. There are no wildcards: the policy is
generated from the same call list the scanner actually uses, and a test in this
repo fails the build if the two ever drift apart.

Formats:
  policy      IAM policy JSON (default)
  terraform   role + policy + trust relationship with an external ID
  cloudformation  the same, as a CFN template
  rbac        read-only Kubernetes ClusterRole for the optional EKS/Velero checks
  all         everything above

  drillproof audit init --format terraform > drillproof-audit.tf`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o := newOut(cmd.OutOrStdout())

			emitPolicy := func() error {
				policy, err := iam.PolicyJSON()
				if err != nil {
					return err
				}
				o.println(policy)
				return o.Err()
			}

			switch format {
			case "policy", "json":
				return emitPolicy()

			case "terraform", "tf":
				tf, err := iam.Terraform()
				if err != nil {
					return err
				}
				o.print(tf)
				return o.Err()

			case "cloudformation", "cfn":
				cf, err := iam.CloudFormation()
				if err != nil {
					return err
				}
				o.print(cf)
				return o.Err()

			case "rbac", "k8s":
				o.print(iam.KubernetesRBAC())
				return o.Err()

			case "all":
				o.println("# ── What each permission is for ──")
				for _, line := range iam.Explanation() {
					o.println("# " + line)
				}
				o.println()

				o.println("# ── IAM policy ──")
				if err := emitPolicy(); err != nil {
					return err
				}

				o.println("\n# ── Terraform ──")
				tf, err := iam.Terraform()
				if err != nil {
					return err
				}
				o.print(tf)

				o.println("\n# ── Kubernetes RBAC (only needed with --kubeconfig) ──")
				o.print(iam.KubernetesRBAC())
				return nil

			default:
				return fmt.Errorf(
					"--format must be one of policy, terraform, cloudformation, rbac, all (got %q)", format)
			}
		},
	}

	cmd.Flags().StringVar(&format, "format", "policy",
		"what to emit: policy | terraform | cloudformation | rbac | all")
	return cmd
}
