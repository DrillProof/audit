package checks

import (
	"testing"

	"github.com/drillproof/audit/internal/model"
	"github.com/stretchr/testify/assert"
)

func bucket() model.Resource {
	return model.Resource{
		Display: "customer-uploads (S3)",
		Name:    "customer-uploads",
		Type:    model.TypeBucket,
		Region:  "us-east-1",
	}
}

func bucketState(p model.S3Protection) *model.BackupState {
	s := model.NewBackupState()
	s.S3 = &p
	return s
}

func TestBucketCoverageTiers(t *testing.T) {
	cases := []struct {
		name     string
		p        model.S3Protection
		wantTier model.ProtectionTier
		want     model.Status
	}{
		{
			name:     "object lock compliance is strongest",
			p:        model.S3Protection{ObjectLockMode: "COMPLIANCE", Versioning: model.Yes, MFADelete: model.No},
			wantTier: model.TierStrongest,
			want:     model.StatusOK,
		},
		{
			name:     "versioning with mfa delete is strong",
			p:        model.S3Protection{Versioning: model.Yes, MFADelete: model.Yes},
			wantTier: model.TierStrong,
			want:     model.StatusOK,
		},
		{
			name:     "versioning without mfa delete is partial",
			p:        model.S3Protection{Versioning: model.Yes, MFADelete: model.No},
			wantTier: model.TierPartial,
			want:     model.StatusWarn,
		},
		{
			name:     "versioning with unknown mfa delete is partial",
			p:        model.S3Protection{Versioning: model.Yes, MFADelete: model.Unknown},
			wantTier: model.TierPartial,
			want:     model.StatusWarn,
		},
		{
			name:     "governance only is weak",
			p:        model.S3Protection{ObjectLockMode: "GOVERNANCE", Versioning: model.No},
			wantTier: model.TierWeak,
			want:     model.StatusWarn,
		},
		{
			name:     "nothing is unprotected",
			p:        model.S3Protection{Versioning: model.No, MFADelete: model.No},
			wantTier: model.TierUnprotected,
			want:     model.StatusFail,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := Coverage(bucket(), bucketState(tc.p), testConfig())
			assert.Equal(t, tc.want, f.Status)
			assert.Contains(t, f.Summary, string(tc.wantTier),
				"the tier name must appear in the finding so the customer sees why")
		})
	}
}

func TestBucketComplianceLockPassesWithMFADeleteOff(t *testing.T) {
	// The false-positive guard. Object Lock in compliance mode is strictly
	// stronger than MFA Delete; failing a compliance-locked bucket because MFA
	// Delete is off would erode exactly the trust the product sells.
	f := Coverage(bucket(), bucketState(model.S3Protection{
		ObjectLockMode: "COMPLIANCE",
		Versioning:     model.Unknown,
		MFADelete:      model.No,
	}), testConfig())
	assert.Equal(t, model.StatusOK, f.Status)
}

func TestBucketGovernanceSaysOverridable(t *testing.T) {
	f := Immutability(bucket(), bucketState(model.S3Protection{
		ObjectLockMode: "GOVERNANCE",
	}), testConfig())
	assert.Equal(t, model.StatusWarn, f.Status)
	assert.Contains(t, f.Summary, "overridable")
}

func TestBucketMFADeleteRemediationNamesRootUserConstraint(t *testing.T) {
	f := Coverage(bucket(), bucketState(model.S3Protection{
		Versioning: model.Yes,
		MFADelete:  model.No,
	}), testConfig())
	assert.Contains(t, f.Remediation, "root user")
	assert.Contains(t, f.Remediation, "Object Lock")
}

func TestBucketCoverageBlockedNamesTheAction(t *testing.T) {
	s := bucketState(model.S3Protection{})
	s.MarkUnassessed(model.CheckCoverage, "s3:GetBucketVersioning denied")
	f := Coverage(bucket(), s, testConfig())
	assert.Equal(t, model.StatusSkipped, f.Status)
	assert.True(t, f.SkipIsAccessGap)
	assert.Contains(t, f.SkipReason, "s3:GetBucketVersioning")
}

func TestBucketImmutability(t *testing.T) {
	t.Run("compliance is ok", func(t *testing.T) {
		f := Immutability(bucket(), bucketState(model.S3Protection{ObjectLockMode: "COMPLIANCE"}), testConfig())
		assert.Equal(t, model.StatusOK, f.Status)
	})

	t.Run("no object lock fails", func(t *testing.T) {
		f := Immutability(bucket(), bucketState(model.S3Protection{}), testConfig())
		assert.Equal(t, model.StatusFail, f.Status)
		assert.NotEmpty(t, f.Remediation)
	})

	t.Run("does not go moot on zero recovery points", func(t *testing.T) {
		// The regression this test exists for: the shared path short-circuits
		// to moot when RecoveryPoints == 0, which is true of every bucket. If
		// S3 ever rides that path, every bucket silently reports "not
		// applicable" and the check stops doing any work at all.
		s := bucketState(model.S3Protection{ObjectLockMode: "COMPLIANCE"})
		s.RecoveryPoints = 0
		f := Immutability(bucket(), s, testConfig())
		assert.Equal(t, model.StatusOK, f.Status)
	})
}

func TestBucketRedundancy(t *testing.T) {
	t.Run("enabled cross-region rule is ok", func(t *testing.T) {
		f := Redundancy(bucket(), bucketState(model.S3Protection{
			Replication: model.ReplicationState{
				Configured: model.Yes, EnabledRule: model.Yes, CrossRegion: model.Yes,
				DestRegions: []string{"eu-west-1"},
			},
		}), testConfig())
		assert.Equal(t, model.StatusOK, f.Status)
		assert.Contains(t, f.Summary, "eu-west-1")
	})

	t.Run("rule present but disabled fails explicitly", func(t *testing.T) {
		f := Redundancy(bucket(), bucketState(model.S3Protection{
			Replication: model.ReplicationState{Configured: model.Yes, EnabledRule: model.No},
		}), testConfig())
		assert.Equal(t, model.StatusFail, f.Status)
		assert.Contains(t, f.Summary, "configured but disabled")
	})

	t.Run("same-region destination fails", func(t *testing.T) {
		f := Redundancy(bucket(), bucketState(model.S3Protection{
			Replication: model.ReplicationState{
				Configured: model.Yes, EnabledRule: model.Yes, CrossRegion: model.No,
				DestRegions: []string{"us-east-1"},
			},
		}), testConfig())
		assert.Equal(t, model.StatusFail, f.Status)
		assert.Contains(t, f.Summary, "same region")
	})

	t.Run("no replication config fails", func(t *testing.T) {
		f := Redundancy(bucket(), bucketState(model.S3Protection{
			Replication: model.ReplicationState{Configured: model.No},
		}), testConfig())
		assert.Equal(t, model.StatusFail, f.Status)
	})

	t.Run("unresolvable destination region is blocked, not failed", func(t *testing.T) {
		f := Redundancy(bucket(), bucketState(model.S3Protection{
			Replication: model.ReplicationState{
				Configured: model.Yes, EnabledRule: model.Yes, CrossRegion: model.Unknown,
			},
		}), testConfig())
		assert.Equal(t, model.StatusSkipped, f.Status)
		assert.True(t, f.SkipIsAccessGap)
	})
}

func TestBucketFreshnessAndRestoreTestingAreNotApplicable(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  model.Finding
	}{
		{"freshness", Freshness(bucket(), bucketState(model.S3Protection{}), testConfig())},
		{"restore-testing", RestoreTested(bucket(), bucketState(model.S3Protection{}), testConfig())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, model.StatusSkipped, tc.got.Status)
			assert.False(t, tc.got.SkipIsAccessGap,
				"not applicable must not be reported as an access gap")
			assert.Contains(t, tc.got.Summary, "not applicable")
		})
	}
}
