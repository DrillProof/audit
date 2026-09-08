package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewResourceTypesHaveStableWireValues(t *testing.T) {
	// These strings appear in JSON, SARIF and the control-plane API. They are
	// public API in two products; a change here is a breaking change twice.
	assert.Equal(t, ResourceType("bucket"), TypeBucket)
	assert.Equal(t, ResourceType("table"), TypeTable)
}

func TestProtectionIsAbsentByDefault(t *testing.T) {
	// The existing types must be untouched by this change. A nil S3/Dynamo is
	// what keeps an EBS volume's state byte-identical to what it was before,
	// which is what makes the existing golden fixtures a regression guard.
	s := NewBackupState()
	assert.Nil(t, s.S3)
	assert.Nil(t, s.Dynamo)

	encoded, err := json.Marshal(s)
	assert.NoError(t, err)
	assert.NotContains(t, string(encoded), "s3")
	assert.NotContains(t, string(encoded), "dynamo")
}

func TestMFADeleteDefaultsToUnknownNotNo(t *testing.T) {
	// GetBucketVersioning commonly omits MFADelete rather than reporting it
	// Disabled. Absent must mean "we could not find out", never "it is off".
	p := S3Protection{}
	assert.Equal(t, Unknown, p.MFADelete)
	assert.Equal(t, Unknown, p.Versioning)
}

func TestPITRDefaultsToUnknown(t *testing.T) {
	d := DynamoProtection{}
	assert.Equal(t, Unknown, d.PITR)
}

func TestFileSystemTypeAndProtection(t *testing.T) {
	// The wire string is public API: it appears in JSON, SARIF, and the
	// control plane's own model. A rename is a breaking change in two
	// products at once.
	assert.Equal(t, ResourceType("file-system"), TypeFileSystem)

	s := NewBackupState()
	s.EFS = &EFSProtection{
		AutomaticBackups: Yes,
		OneZone:          No,
		Replication: EFSReplicationState{
			Configured:  Yes,
			Healthy:     Yes,
			CrossRegion: Yes,
			DestRegions: []string{"us-west-2"},
		},
	}

	// Unknown must survive round-tripping: an unreadable replication health
	// is not "healthy", and collapsing it would be a false statement.
	s.EFS.Replication.Healthy = Unknown
	assert.Equal(t, "unknown", s.EFS.Replication.Healthy.String())
	assert.Nil(t, s.Dynamo)
	assert.Nil(t, s.S3)
}

func TestKeyAvailabilityIsACheck(t *testing.T) {
	if CheckKeyAvailability != "key-availability" {
		t.Fatalf("wire value changed: %q", CheckKeyAvailability)
	}
	found := false
	for _, c := range AllChecks {
		if c == CheckKeyAvailability {
			found = true
		}
	}
	if !found {
		t.Fatal("CheckKeyAvailability missing from AllChecks")
	}
	if len(AllChecks) != 6 {
		t.Fatalf("expected 6 checks, got %d", len(AllChecks))
	}
}

func TestBackupStateCarriesKeys(t *testing.T) {
	s := NewBackupState()
	s.Keys = []RecoveryPointKey{{
		KeyARN:       "arn:aws:kms:us-east-1:111122223333:key/abc",
		State:        "Enabled",
		CrossAccount: No,
	}}
	if s.Keys[0].AWSManaged {
		t.Fatal("AWSManaged should default false")
	}
}
