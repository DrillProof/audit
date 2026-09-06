package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/drillproof/audit/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormaliseBucketRegion(t *testing.T) {
	// GetBucketLocation returns an empty LocationConstraint for us-east-1 and
	// the legacy "EU" for eu-west-1. Both are easy to get wrong and both would
	// silently misfile a bucket into the wrong region, which then reads as a
	// same-region replication failure.
	assert.Equal(t, "us-east-1", normaliseBucketRegion(""))
	assert.Equal(t, "eu-west-1", normaliseBucketRegion("EU"))
	assert.Equal(t, "ap-southeast-1", normaliseBucketRegion("ap-southeast-1"))
}

func s3Provider(f *fakeS3) *fakeProvider {
	return &fakeProvider{
		base: "us-east-1",
		sts:  &fakeSTS{account: "123456789012"},
		perRegion: map[string]Clients{
			"us-east-1": {Region: "us-east-1", S3: f, EC2: &fakeEC2{}, RDS: &fakeRDS{}, Backup: &fakeBackup{}, EKS: &fakeEKS{}, DynamoDB: &fakeDynamoDB{}},
			"eu-west-1": {Region: "eu-west-1", S3: f, EC2: &fakeEC2{}, RDS: &fakeRDS{}, Backup: &fakeBackup{}, EKS: &fakeEKS{}, DynamoDB: &fakeDynamoDB{}},
		},
	}
}

func TestBucketsAreEnumeratedOncePerAccount(t *testing.T) {
	// ListBuckets is account-global. Calling it inside the region fan-out
	// would return every bucket once per region and multiply the estate.
	f := &fakeS3{
		buckets:   []string{"uploads"},
		locations: map[string]string{"uploads": ""},
	}
	resources, states, _ := Buckets(context.Background(), s3Provider(f), []string{"us-east-1", "eu-west-1"}, nil)

	require.Len(t, resources, 1)
	assert.Equal(t, "us-east-1", resources[0].Region)
	assert.Equal(t, model.TypeBucket, resources[0].Type)
	assert.Contains(t, resources[0].Display, "(S3)")
	assert.NotNil(t, states["uploads"])
}

func TestBucketsOutsideScannedRegionsAreDroppedWithAWarning(t *testing.T) {
	f := &fakeS3{
		buckets:   []string{"far-away"},
		locations: map[string]string{"far-away": "sa-east-1"},
	}
	resources, _, warnings := Buckets(context.Background(), s3Provider(f), []string{"us-east-1"}, nil)

	assert.Empty(t, resources)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "far-away")
	assert.Contains(t, warnings[0], "sa-east-1")
}

func TestBucketTierIsReadFromVersioningAndObjectLock(t *testing.T) {
	f := &fakeS3{
		buckets:   []string{"locked", "versioned", "bare"},
		locations: map[string]string{"locked": "", "versioned": "", "bare": ""},
		versioning: map[string]s3.GetBucketVersioningOutput{
			"versioned": {Status: s3types.BucketVersioningStatusEnabled, MFADelete: s3types.MFADeleteStatusEnabled},
		},
		objectLock: map[string]s3.GetObjectLockConfigurationOutput{
			"locked": {ObjectLockConfiguration: &s3types.ObjectLockConfiguration{
				ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
				Rule: &s3types.ObjectLockRule{DefaultRetention: &s3types.DefaultRetention{
					Mode: s3types.ObjectLockRetentionModeCompliance,
				}},
			}},
		},
	}
	_, states, _ := Buckets(context.Background(), s3Provider(f), []string{"us-east-1"}, nil)

	assert.Equal(t, "COMPLIANCE", states["locked"].S3.ObjectLockMode)
	assert.Equal(t, model.Yes, states["versioned"].S3.Versioning)
	assert.Equal(t, model.Yes, states["versioned"].S3.MFADelete)
	assert.Equal(t, "", states["bare"].S3.ObjectLockMode)
	assert.Equal(t, model.No, states["bare"].S3.Versioning)
}

func TestAbsentMFADeleteIsUnknownNotNo(t *testing.T) {
	// GetBucketVersioning commonly omits MFADelete entirely. The SDK gives us
	// an empty string, which must not be read as "Disabled".
	f := &fakeS3{
		buckets:   []string{"versioned"},
		locations: map[string]string{"versioned": ""},
		versioning: map[string]s3.GetBucketVersioningOutput{
			"versioned": {Status: s3types.BucketVersioningStatusEnabled},
		},
	}
	_, states, _ := Buckets(context.Background(), s3Provider(f), []string{"us-east-1"}, nil)
	assert.Equal(t, model.Unknown, states["versioned"].S3.MFADelete)
}

func TestDisabledReplicationRuleIsRecorded(t *testing.T) {
	f := &fakeS3{
		buckets:   []string{"uploads"},
		locations: map[string]string{"uploads": ""},
		replication: map[string]s3.GetBucketReplicationOutput{
			"uploads": {ReplicationConfiguration: &s3types.ReplicationConfiguration{
				Rules: []s3types.ReplicationRule{{
					Status:      s3types.ReplicationRuleStatusDisabled,
					Destination: &s3types.Destination{Bucket: awssdk.String("arn:aws:s3:::dr-copy")},
				}},
			}},
		},
	}
	_, states, _ := Buckets(context.Background(), s3Provider(f), []string{"us-east-1"}, nil)

	rep := states["uploads"].S3.Replication
	assert.Equal(t, model.Yes, rep.Configured)
	assert.Equal(t, model.No, rep.EnabledRule)
}

func TestDeniedVersioningMarksCoverageUnassessedNamingTheAction(t *testing.T) {
	// The honesty contract doing real work: a customer whose role predates
	// S3 support must see "not assessed (s3:GetBucketVersioning denied)",
	// never a FAIL that tells them their bucket is unprotected.
	f := &fakeS3{
		buckets:       []string{"uploads"},
		locations:     map[string]string{"uploads": ""},
		versioningErr: denied(),
	}
	_, states, _ := Buckets(context.Background(), s3Provider(f), []string{"us-east-1"}, nil)

	reason, ok := states["uploads"].Unassessed[model.CheckCoverage]
	require.True(t, ok, "denied versioning must mark coverage unassessed")
	assert.Contains(t, reason, "s3:GetBucketVersioning")
}

func TestAllowListSkipsListBuckets(t *testing.T) {
	// A security team can grant s3:GetBucket* on named ARNs and withhold
	// s3:ListAllMyBuckets. That must still produce real findings.
	f := &fakeS3{
		listErr:   denied(),
		locations: map[string]string{"named": ""},
	}
	resources, states, warnings := Buckets(context.Background(), s3Provider(f), []string{"us-east-1"}, []string{"named"})

	require.Len(t, resources, 1)
	assert.Equal(t, "named", resources[0].Name)
	assert.NotNil(t, states["named"])
	assert.Empty(t, warnings)
}
