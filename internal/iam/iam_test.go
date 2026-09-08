package iam

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awsx "github.com/drillproof/audit/internal/aws"
)

// servicePrefix maps each AWS interface to its IAM service prefix.
var servicePrefix = map[string]string{
	"STSAPI":      "sts",
	"EC2API":      "ec2",
	"RDSAPI":      "rds",
	"BackupAPI":   "backup",
	"EKSAPI":      "eks",
	"S3API":       "s3",
	"DynamoDBAPI": "dynamodb",
	"EFSAPI":      "elasticfilesystem",
	"KMSAPI":      "kms",
}

// iamActionExceptions covers the places where the IAM action name differs from
// the API operation name. S3 is the notorious one: the API call is
// GetObjectLockConfiguration but the IAM action is
// GetBucketObjectLockConfiguration. Getting this wrong means handing users a
// policy that does not actually authorise the tool.
var iamActionExceptions = map[string]string{
	"s3:GetObjectLockConfiguration": "s3:GetBucketObjectLockConfiguration",
	"s3:ListBuckets":                "s3:ListAllMyBuckets",
}

func interfaceTypes() map[string]reflect.Type {
	return map[string]reflect.Type{
		"STSAPI":      reflect.TypeOf((*awsx.STSAPI)(nil)).Elem(),
		"EC2API":      reflect.TypeOf((*awsx.EC2API)(nil)).Elem(),
		"RDSAPI":      reflect.TypeOf((*awsx.RDSAPI)(nil)).Elem(),
		"BackupAPI":   reflect.TypeOf((*awsx.BackupAPI)(nil)).Elem(),
		"EKSAPI":      reflect.TypeOf((*awsx.EKSAPI)(nil)).Elem(),
		"S3API":       reflect.TypeOf((*awsx.S3API)(nil)).Elem(),
		"DynamoDBAPI": reflect.TypeOf((*awsx.DynamoDBAPI)(nil)).Elem(),
		"EFSAPI":      reflect.TypeOf((*awsx.EFSAPI)(nil)).Elem(),
		"KMSAPI":      reflect.TypeOf((*awsx.KMSAPI)(nil)).Elem(),
	}
}

// requiredActions derives the IAM actions implied by the AWS interfaces.
func requiredActions(t *testing.T) map[string]bool {
	t.Helper()
	actions := map[string]bool{}
	for name, typ := range interfaceTypes() {
		prefix, ok := servicePrefix[name]
		require.True(t, ok, "no IAM service prefix registered for %s", name)
		for i := 0; i < typ.NumMethod(); i++ {
			action := prefix + ":" + typ.Method(i).Name
			if mapped, ok := iamActionExceptions[action]; ok {
				action = mapped
			}
			actions[action] = true
		}
	}
	return actions
}

// TestPolicyCoversEverySDKCall is the drift guard. If someone adds an AWS call
// to the scanner without adding the permission here, `init` would hand users a
// policy that silently fails at scan time. This fails instead.
func TestPolicyCoversEverySDKCall(t *testing.T) {
	granted := map[string]bool{}
	for _, a := range AllActions() {
		granted[a] = true
	}

	for action := range requiredActions(t) {
		assert.True(t, granted[action],
			"the scanner calls %s but the emitted IAM policy does not grant it — add it to actionGroups", action)
	}
}

// TestPolicyGrantsNothingUnused is the other half: an over-broad policy is a
// smaller failure than a broken one, but still a failure. Users read this
// policy and reasonably expect it to be minimal.
func TestPolicyGrantsNothingUnused(t *testing.T) {
	required := requiredActions(t)
	for _, action := range AllActions() {
		assert.True(t, required[action],
			"the policy grants %s but no interface method needs it — remove it or wire up the call", action)
	}
}

func TestPolicyCoversTheNewResourceTypes(t *testing.T) {
	actions := map[string]bool{}
	for _, a := range AllActions() {
		actions[a] = true
	}
	for _, want := range []string{
		"s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketVersioning",
		"s3:GetBucketObjectLockConfiguration", "s3:GetBucketReplication", "s3:GetBucketTagging",
		"dynamodb:ListTables", "dynamodb:DescribeTable",
		"dynamodb:DescribeContinuousBackups", "dynamodb:ListTagsOfResource",
	} {
		assert.True(t, actions[want], "policy is missing %s", want)
	}
}

func TestPolicyGrantsNothingTheScannerDoesNotCall(t *testing.T) {
	// The other half of the contract. A policy that over-grants is a policy a
	// security reviewer is right to reject, and it undermines the least-
	// privilege claim the product makes.
	required := requiredActions(t)
	for _, granted := range AllActions() {
		assert.True(t, required[granted],
			"policy grants %s but no interface method calls it", granted)
	}
}

func TestPolicyIsReadOnly(t *testing.T) {
	for _, action := range AllActions() {
		parts := strings.SplitN(action, ":", 2)
		require.Len(t, parts, 2, "malformed action %q", action)
		verb := parts[1]

		isRead := strings.HasPrefix(verb, "Describe") ||
			strings.HasPrefix(verb, "List") ||
			strings.HasPrefix(verb, "Get")
		assert.True(t, isRead, "%s is not a read-only action — v1 must never mutate", action)
	}
}

func TestPolicyJSONIsValidAndComplete(t *testing.T) {
	out, err := PolicyJSON()
	require.NoError(t, err)

	var parsed Policy
	require.NoError(t, json.Unmarshal([]byte(out), &parsed), "emitted policy must be valid JSON")

	assert.Equal(t, "2012-10-17", parsed.Version)
	require.NotEmpty(t, parsed.Statement)

	for _, s := range parsed.Statement {
		assert.Equal(t, "Allow", s.Effect)
		assert.NotEmpty(t, s.SID)
		assert.NotEmpty(t, s.Action)
		assert.Equal(t, "*", s.Resource)
	}
}

func TestNoWildcardActions(t *testing.T) {
	// The spec asks for the *exact* least-privilege policy. "ec2:Describe*"
	// would be easier and is what most vendors ship; it also grants reads we
	// never make.
	for _, action := range AllActions() {
		assert.NotContains(t, action, "*",
			"%s is a wildcard — the spec requires exact actions", action)
	}
}

func TestTerraformEmbedsThePolicyAndRequiresExternalID(t *testing.T) {
	tf, err := Terraform()
	require.NoError(t, err)

	assert.Contains(t, tf, "aws_iam_role")
	assert.Contains(t, tf, "sts:ExternalId", "external ID is the confused-deputy mitigation and must be present")
	assert.Contains(t, tf, "sts:AssumeRole")
	assert.Contains(t, tf, "output \"audit_role_arn\"")

	// The real actions must appear, not a placeholder.
	for _, action := range AllActions() {
		assert.Contains(t, tf, action, "Terraform output is missing action %s", action)
	}
}

func TestCloudFormationIsEmitted(t *testing.T) {
	cf, err := CloudFormation()
	require.NoError(t, err)
	assert.Contains(t, cf, "AWSTemplateFormatVersion")
	assert.Contains(t, cf, "AWS::IAM::Role")
	assert.Contains(t, cf, "sts:ExternalId")
}

func TestKubernetesRBACIsReadOnly(t *testing.T) {
	rbac := KubernetesRBAC()
	assert.Contains(t, rbac, "velero.io", "Velero detection needs its CRDs")
	assert.Contains(t, rbac, "ClusterRole")

	// No mutating verb may appear anywhere in the manifest.
	for _, verb := range []string{"create", "update", "patch", "delete", "deletecollection"} {
		assert.NotContains(t, rbac, `"`+verb+`"`,
			"RBAC must not grant %q", verb)
	}
}

func TestExplanationCoversEveryStatement(t *testing.T) {
	lines := Explanation()
	assert.Len(t, lines, len(BuildPolicy().Statement),
		"every statement needs a stated purpose so reviewers can see why it is there")
}

func TestPolicyCoversEFS(t *testing.T) {
	actions := map[string]bool{}
	for _, a := range AllActions() {
		actions[a] = true
	}
	for _, want := range []string{
		"elasticfilesystem:DescribeFileSystems",
		"elasticfilesystem:DescribeBackupPolicy",
		"elasticfilesystem:DescribeReplicationConfigurations",
		"elasticfilesystem:ListTagsForResource",
	} {
		assert.True(t, actions[want], "policy is missing %s", want)
	}
}

func TestEFSNeedsNoNewBackupActions(t *testing.T) {
	// EFS recovery points are read through the AWS Backup permissions the
	// policy already grants (spec §3). A new backup:* action here would mean
	// asking every existing customer for more than EFS actually needs.
	backupActions := 0
	for _, a := range AllActions() {
		if strings.HasPrefix(a, "backup:") {
			backupActions++
		}
	}
	assert.Equal(t, 5, backupActions, "the backup:* set must not grow for EFS")
}

func TestPolicyGrantsKeyStateOnly(t *testing.T) {
	doc := BuildPolicy()
	var all []string
	for _, st := range doc.Statement {
		all = append(all, st.Action...)
	}
	joined := strings.Join(all, " ")

	if !strings.Contains(joined, "kms:DescribeKey") {
		t.Fatal("kms:DescribeKey missing — KEY_AVAILABILITY cannot run")
	}
	// The trust claim in the docs is "state only, never material, never
	// decryption". This is the test that makes that claim true.
	for _, forbidden := range []string{
		"kms:Decrypt", "kms:GenerateDataKey", "kms:ReEncrypt",
		"kms:GetKeyPolicy", "kms:ListAliases", "kms:ScheduleKeyDeletion",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("policy requests %s — it must not", forbidden)
		}
	}
}
