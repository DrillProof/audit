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
