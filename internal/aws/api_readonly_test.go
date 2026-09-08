package aws

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readVerbs are the only operation prefixes v1 is permitted to call.
var readVerbs = []string{"Describe", "List", "Get"}

// mutatingVerbs are spelled out so a failure message is unambiguous about why.
var mutatingVerbs = []string{
	"Create", "Delete", "Update", "Modify", "Put", "Start", "Stop",
	"Restore", "Copy", "Cancel", "Tag", "Untag", "Disassociate",
	"Associate", "Attach", "Detach", "Enable", "Disable", "Reset",
	"Register", "Deregister", "Revoke", "Terminate", "Run", "Import",
	"Export", "Set", "Add", "Remove",
}

// TestInterfacesAreReadOnly is the enforcement mechanism for the spec's
// "never call any mutating API in v1" rule. It reflects over every AWS
// interface in this package: if anyone adds a mutating operation, this fails
// rather than waiting for a reviewer to notice.
func TestInterfacesAreReadOnly(t *testing.T) {
	interfaces := map[string]reflect.Type{
		"STSAPI":      reflect.TypeOf((*STSAPI)(nil)).Elem(),
		"EC2API":      reflect.TypeOf((*EC2API)(nil)).Elem(),
		"RDSAPI":      reflect.TypeOf((*RDSAPI)(nil)).Elem(),
		"BackupAPI":   reflect.TypeOf((*BackupAPI)(nil)).Elem(),
		"EKSAPI":      reflect.TypeOf((*EKSAPI)(nil)).Elem(),
		"S3API":       reflect.TypeOf((*S3API)(nil)).Elem(),
		"DynamoDBAPI": reflect.TypeOf((*DynamoDBAPI)(nil)).Elem(),
		"EFSAPI":      reflect.TypeOf((*EFSAPI)(nil)).Elem(),
		"KMSAPI":      reflect.TypeOf((*KMSAPI)(nil)).Elem(),
	}

	for name, typ := range interfaces {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, reflect.Interface, typ.Kind())
			require.Greater(t, typ.NumMethod(), 0, "%s exposes no operations", name)

			for i := 0; i < typ.NumMethod(); i++ {
				method := typ.Method(i).Name

				hasReadVerb := false
				for _, v := range readVerbs {
					if strings.HasPrefix(method, v) {
						hasReadVerb = true
						break
					}
				}
				assert.True(t, hasReadVerb,
					"%s.%s does not start with a read verb (%s) — v1 is read-only",
					name, method, strings.Join(readVerbs, "/"))

				for _, v := range mutatingVerbs {
					assert.False(t, strings.HasPrefix(method, v),
						"%s.%s starts with mutating verb %q — v1 must never mutate",
						name, method, v)
				}
			}
		})
	}
}

func TestNewInterfacesAreReadOnly(t *testing.T) {
	// The guard that makes "we cannot mutate anything" a compile-time fact
	// rather than a review promise. A mutating method added to either
	// interface fails here before it can reach a customer account.
	for name, typ := range map[string]reflect.Type{
		"S3API":       reflect.TypeOf((*S3API)(nil)).Elem(),
		"DynamoDBAPI": reflect.TypeOf((*DynamoDBAPI)(nil)).Elem(),
	} {
		for i := 0; i < typ.NumMethod(); i++ {
			method := typ.Method(i).Name
			isRead := strings.HasPrefix(method, "Describe") ||
				strings.HasPrefix(method, "List") ||
				strings.HasPrefix(method, "Get")
			assert.True(t, isRead, "%s.%s is not a read verb", name, method)
		}
	}
}

func TestEFSAPICoversTheCallsTheScannerNeeds(t *testing.T) {
	typ := reflect.TypeOf((*EFSAPI)(nil)).Elem()
	for _, want := range []string{
		"DescribeFileSystems", "DescribeBackupPolicy", "DescribeReplicationConfigurations", "ListTagsForResource",
	} {
		_, ok := typ.MethodByName(want)
		assert.True(t, ok, "EFSAPI is missing %s", want)
	}
}

func TestDynamoDBAPICoversTheCallsTheScannerNeeds(t *testing.T) {
	typ := reflect.TypeOf((*DynamoDBAPI)(nil)).Elem()
	for _, want := range []string{
		"ListTables", "DescribeTable", "DescribeContinuousBackups", "ListTagsOfResource",
	} {
		_, ok := typ.MethodByName(want)
		assert.True(t, ok, "DynamoDBAPI is missing %s", want)
	}
}

func TestKMSAPICoversTheCallsTheScannerNeeds(t *testing.T) {
	typ := reflect.TypeOf((*KMSAPI)(nil)).Elem()
	for _, want := range []string{
		"DescribeKey",
	} {
		_, ok := typ.MethodByName(want)
		assert.True(t, ok, "KMSAPI is missing %s", want)
	}
}

func TestS3APICoversTheBucketPostureCalls(t *testing.T) {
	typ := reflect.TypeOf((*S3API)(nil)).Elem()
	for _, want := range []string{
		"ListBuckets", "GetBucketLocation", "GetBucketVersioning",
		"GetBucketReplication", "GetObjectLockConfiguration", "GetBucketTagging",
	} {
		_, ok := typ.MethodByName(want)
		assert.True(t, ok, "S3API is missing %s", want)
	}
}

func TestIsAccessDenied(t *testing.T) {
	assert.False(t, IsAccessDenied(nil))
	assert.True(t, IsAccessDenied(&stubAPIErr{code: "AccessDeniedException"}))
	assert.True(t, IsAccessDenied(&stubAPIErr{code: "UnauthorizedOperation"}))
	assert.True(t, IsAccessDenied(&stubAPIErr{code: "Weird", msg: "User is not authorized to perform ec2:DescribeVolumes"}))
	assert.False(t, IsAccessDenied(&stubAPIErr{code: "Throttling", msg: "Rate exceeded"}))
}

func TestIsNotFound(t *testing.T) {
	assert.False(t, IsNotFound(nil))
	assert.True(t, IsNotFound(&stubAPIErr{code: "ObjectLockConfigurationNotFoundError"}))
	assert.False(t, IsNotFound(&stubAPIErr{code: "AccessDenied"}))
}

func TestErrorCode(t *testing.T) {
	assert.Equal(t, "Throttling", ErrorCode(&stubAPIErr{code: "Throttling"}))
	assert.Equal(t, "", ErrorCode(assert.AnError))
}
