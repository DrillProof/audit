// Package iam emits the exact least-privilege permissions the audit needs.
//
// The policy here is the single source of truth: it is generated from the same
// action list the scanner actually calls, so `init` cannot drift into promising
// less (or demanding more) than the tool uses.
package iam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// PolicyName is the conventional name used in the emitted snippets.
const PolicyName = "DrillProofAuditReadOnly"

// Statement is one IAM policy statement.
type Statement struct {
	SID      string   `json:"Sid"`
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource string   `json:"Resource"`
}

// Policy is an IAM policy document.
type Policy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// actionGroups maps each statement to the actions the scanner calls, with a
// note on which check needs them. Keep this in step with internal/aws — the
// test in this package asserts the two agree.
var actionGroups = []struct {
	sid     string
	purpose string
	actions []string
}{
	{
		sid:     "Identity",
		purpose: "resolve the account being audited",
		actions: []string{"sts:GetCallerIdentity"},
	},
	{
		sid:     "RegionAndVolumeInventory",
		purpose: "discover enabled regions, EBS volumes and their snapshots",
		actions: []string{
			"ec2:DescribeRegions",
			"ec2:DescribeVolumes",
			"ec2:DescribeSnapshots",
		},
	},
	{
		sid:     "DatabaseInventory",
		purpose: "inventory RDS instances, clusters and their snapshots",
		actions: []string{
			"rds:DescribeDBInstances",
			"rds:DescribeDBClusters",
			"rds:DescribeDBSnapshots",
			"rds:DescribeDBClusterSnapshots",
		},
	},
	{
		sid:     "BackupPosture",
		purpose: "read recovery points, vault lock state and restore history",
		actions: []string{
			"backup:ListBackupVaults",
			"backup:DescribeBackupVault",
			"backup:ListRecoveryPointsByBackupVault",
			"backup:ListRecoveryPointsByResource",
			"backup:ListRestoreTestingPlans",
		},
	},
	{
		sid:     "ClusterInventory",
		purpose: "inventory EKS clusters for cluster-state coverage",
		actions: []string{
			"eks:ListClusters",
			"eks:DescribeCluster",
		},
	},
	{
		sid:     "BucketPosture",
		purpose: "inventory S3 buckets and read versioning, Object Lock and replication",
		actions: []string{
			"s3:ListAllMyBuckets",
			"s3:GetBucketLocation",
			"s3:GetBucketVersioning",
			"s3:GetBucketObjectLockConfiguration",
			"s3:GetBucketReplication",
			"s3:GetBucketTagging",
		},
	},
	{
		sid:     "TableInventory",
		purpose: "inventory DynamoDB tables and read Point-in-Time Recovery status",
		actions: []string{
			"dynamodb:ListTables",
			"dynamodb:DescribeTable",
			"dynamodb:DescribeContinuousBackups",
			"dynamodb:ListTagsOfResource",
		},
	},
	{
		sid:     "FileSystemPosture",
		purpose: "inventory EFS filesystems and read automatic backups and replication",
		actions: []string{
			"elasticfilesystem:DescribeFileSystems",
			"elasticfilesystem:DescribeBackupPolicy",
			"elasticfilesystem:DescribeReplicationConfigurations",
			"elasticfilesystem:ListTagsForResource",
		},
	},
	{
		sid:     "KeyState",
		purpose: "read whether the KMS keys protecting recovery points are still enabled",
		actions: []string{"kms:DescribeKey"},
	},
}

// BuildPolicy returns the least-privilege policy document.
//
// Resource is "*" throughout because every action is a read-only Describe/List
// whose scope is the account itself; narrowing to specific ARNs would break
// discovery, which by definition does not yet know the ARNs.
func BuildPolicy() Policy {
	p := Policy{Version: "2012-10-17"}
	for _, g := range actionGroups {
		actions := append([]string(nil), g.actions...)
		sort.Strings(actions)
		p.Statement = append(p.Statement, Statement{
			SID:      g.sid,
			Effect:   "Allow",
			Action:   actions,
			Resource: "*",
		})
	}
	return p
}

// AllActions is the flat, sorted list of every action the tool may call.
func AllActions() []string {
	var all []string
	for _, g := range actionGroups {
		all = append(all, g.actions...)
	}
	sort.Strings(all)
	return all
}

// PolicyJSON renders the policy document as indented JSON.
func PolicyJSON() (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(BuildPolicy()); err != nil {
		return "", err
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

// Explanation lists what each statement is for, so a reviewer can see why every
// permission is present rather than taking the policy on trust.
func Explanation() []string {
	var lines []string
	for _, g := range actionGroups {
		lines = append(lines, fmt.Sprintf("%-28s %s", g.sid, g.purpose))
	}
	return lines
}

// Terraform emits a ready-to-apply role for a user to run the audit locally, or
// grant to CI.
func Terraform() (string, error) {
	policy, err := PolicyJSON()
	if err != nil {
		return "", err
	}
	indented := indent(policy, "  ")

	return fmt.Sprintf(`# DrillProof audit — least-privilege, read-only.
#
# Every action below is a Describe/List/Get. This role cannot create, modify,
# restore, or delete anything.
#
#   terraform apply
#   AWS_PROFILE=... drillproof audit scan

variable "trusted_principal" {
  description = "ARN allowed to assume the audit role (your IAM user, SSO role, or CI role)."
  type        = string
}

variable "external_id" {
  description = "Shared secret required on AssumeRole. Mitigates the confused-deputy problem."
  type        = string
  sensitive   = true
}

resource "aws_iam_policy" "%[2]s" {
  name        = "%[2]s"
  description = "Read-only permissions for the DrillProof recoverability audit"
  policy      = <<-POLICY
%[1]s
  POLICY
}

resource "aws_iam_role" "%[2]s" {
  name = "%[2]s"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = var.trusted_principal
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = var.external_id
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "%[2]s" {
  role       = aws_iam_role.%[2]s.name
  policy_arn = aws_iam_policy.%[2]s.arn
}

output "audit_role_arn" {
  value       = aws_iam_role.%[2]s.arn
  description = "Pass to the auditor, or assume locally before running the scan."
}
`, indented, PolicyName), nil
}

// CloudFormation emits the same role for teams not using Terraform.
func CloudFormation() (string, error) {
	policy := BuildPolicy()
	statements, err := json.MarshalIndent(policy.Statement, "          ", "  ")
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(`# DrillProof audit — least-privilege, read-only.
AWSTemplateFormatVersion: "2010-09-09"
Description: Read-only role for the DrillProof recoverability audit

Parameters:
  TrustedPrincipal:
    Type: String
    Description: ARN allowed to assume the audit role
  ExternalId:
    Type: String
    NoEcho: true
    Description: Shared secret required on AssumeRole

Resources:
  DrillProofAuditRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: %[2]s
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Ref TrustedPrincipal
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                sts:ExternalId: !Ref ExternalId
      Policies:
        - PolicyName: %[2]s
          PolicyDocument:
            Version: "2012-10-17"
            Statement: %[1]s

Outputs:
  AuditRoleArn:
    Value: !GetAtt DrillProofAuditRole.Arn
`, string(statements), PolicyName), nil
}

// KubernetesRBAC emits the read-only ClusterRole for the optional EKS/Velero
// checks. Separate from IAM because cluster access is a separate grant.
func KubernetesRBAC() string {
	return `# DrillProof audit — read-only cluster access for the EKS/Velero checks.
#
# Only needed if you pass --kubeconfig. get/list/watch only; nothing here can
# modify the cluster.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: drillproof-audit-readonly
rules:
  # Detect whether Velero is installed and what it is backing up.
  - apiGroups: ["velero.io"]
    resources: ["backups", "schedules", "backupstoragelocations", "restores"]
    verbs: ["get", "list"]
  # Discovery: is there anything in the cluster worth backing up?
  - apiGroups: [""]
    resources: ["namespaces", "persistentvolumes", "persistentvolumeclaims"]
    verbs: ["get", "list"]
  - apiGroups: ["apiextensions.k8s.io"]
    resources: ["customresourcedefinitions"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: drillproof-audit-readonly
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: drillproof-audit-readonly
subjects:
  - kind: User
    name: CHANGE_ME  # the identity that will run the audit
    apiGroup: rbac.authorization.k8s.io
`
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "\n")
}
