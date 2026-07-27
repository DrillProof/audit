package checks

import (
	"testing"
	"time"

	"github.com/drillproof/audit/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var fixedNow = time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

func testConfig() Config {
	c := DefaultConfig()
	c.Now = fixedNow
	return c
}

func ago(d time.Duration) *time.Time {
	t := fixedNow.Add(-d)
	return &t
}

func volume() model.Resource {
	return model.Resource{Display: "orders-pv (EKS/EBS)", Type: model.TypeVolume, Region: "ap-southeast-1"}
}

func etcd() model.Resource {
	return model.Resource{Display: "etcd (prod-cluster)", Type: model.TypeK8sState, Region: "ap-southeast-1"}
}

func TestCoverage(t *testing.T) {
	t.Run("with recovery points is ok", func(t *testing.T) {
		s := model.NewBackupState()
		s.RecoveryPoints = 3
		f := Coverage(volume(), s, testConfig())
		assert.Equal(t, model.StatusOK, f.Status)
		assert.Contains(t, f.Summary, "3 recovery point")
	})

	t.Run("without any backup fails", func(t *testing.T) {
		f := Coverage(volume(), model.NewBackupState(), testConfig())
		assert.Equal(t, model.StatusFail, f.Status)
		assert.NotEmpty(t, f.Remediation)
	})

	t.Run("cluster state gets its own wording", func(t *testing.T) {
		f := Coverage(etcd(), model.NewBackupState(), testConfig())
		assert.Equal(t, model.StatusFail, f.Status)
		assert.Contains(t, f.Summary, "unrecoverable")
	})

	t.Run("missing permission is skipped, not passed", func(t *testing.T) {
		s := model.NewBackupState()
		s.MarkUnassessed(model.CheckCoverage, "backup:ListRecoveryPointsByResource denied")
		f := Coverage(volume(), s, testConfig())
		assert.Equal(t, model.StatusSkipped, f.Status)
		assert.Contains(t, f.SkipReason, "denied")
	})
}

func TestFreshness(t *testing.T) {
	cases := []struct {
		name string
		age  time.Duration
		want model.Status
	}{
		{"three hours is ok", 3 * time.Hour, model.StatusOK},
		{"exactly 24h is still ok", 24 * time.Hour, model.StatusOK},
		{"just over 24h warns", 25 * time.Hour, model.StatusWarn},
		{"six days warns", 6 * 24 * time.Hour, model.StatusWarn},
		{"just over 7d fails", 7*24*time.Hour + time.Minute, model.StatusFail},
		{"thirty days fails", 30 * 24 * time.Hour, model.StatusFail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := model.NewBackupState()
			s.RecoveryPoints = 1
			s.LatestBackupAt = ago(tc.age)
			assert.Equal(t, tc.want, Freshness(volume(), s, testConfig()).Status)
		})
	}

	t.Run("no backup defers to coverage rather than double-penalising", func(t *testing.T) {
		f := Freshness(volume(), model.NewBackupState(), testConfig())
		assert.Equal(t, model.StatusSkipped, f.Status)
	})
}

func TestImmutability(t *testing.T) {
	t.Run("locked is ok", func(t *testing.T) {
		s := model.NewBackupState()
		s.Immutable = model.Yes
		assert.Equal(t, model.StatusOK, Immutability(volume(), s, testConfig()).Status)
	})

	t.Run("known-deletable fails", func(t *testing.T) {
		s := model.NewBackupState()
		s.Immutable = model.No
		f := Immutability(volume(), s, testConfig())
		assert.Equal(t, model.StatusFail, f.Status)
		assert.Contains(t, f.Remediation, "Vault Lock")
	})

	t.Run("unknown is skipped, never assumed safe", func(t *testing.T) {
		s := model.NewBackupState()
		s.Immutable = model.Unknown
		assert.Equal(t, model.StatusSkipped, Immutability(volume(), s, testConfig()).Status)
	})
}

func TestRedundancy(t *testing.T) {
	base := func(cr model.Tristate) *model.BackupState {
		s := model.NewBackupState()
		s.RecoveryPoints = 2
		s.CrossRegion = cr
		return s
	}

	assert.Equal(t, model.StatusOK, Redundancy(volume(), base(model.Yes), testConfig()).Status)
	assert.Equal(t, model.StatusFail, Redundancy(volume(), base(model.No), testConfig()).Status)
	assert.Equal(t, model.StatusSkipped, Redundancy(volume(), base(model.Unknown), testConfig()).Status)

	t.Run("nothing to replicate is skipped", func(t *testing.T) {
		assert.Equal(t, model.StatusSkipped, Redundancy(volume(), model.NewBackupState(), testConfig()).Status)
	})
}

func TestRestoreTested(t *testing.T) {
	t.Run("an actual restore is ok", func(t *testing.T) {
		s := model.NewBackupState()
		s.RecoveryPoints = 1
		s.LastRestoreAt = ago(48 * time.Hour)
		f := RestoreTested(volume(), s, testConfig())
		assert.Equal(t, model.StatusOK, f.Status)
		assert.Contains(t, f.Summary, "2026-07-24")
	})

	t.Run("never tested fails with the wedge wording", func(t *testing.T) {
		s := model.NewBackupState()
		s.RecoveryPoints = 1
		f := RestoreTested(volume(), s, testConfig())
		assert.Equal(t, model.StatusFail, f.Status)
		assert.Contains(t, f.Summary, `"backed up" is not "recoverable"`)
	})

	t.Run("a plan configured but not yet run only warns", func(t *testing.T) {
		s := model.NewBackupState()
		s.RecoveryPoints = 1
		s.RestoreTestingConfigured = true
		f := RestoreTested(volume(), s, testConfig())
		assert.Equal(t, model.StatusWarn, f.Status)
	})
}

func TestRunProducesOneFindingPerCheck(t *testing.T) {
	s := model.NewBackupState()
	s.RecoveryPoints = 1
	s.LatestBackupAt = ago(2 * time.Hour)
	s.Immutable = model.Yes
	s.CrossRegion = model.Yes

	findings := Run(volume(), s, testConfig())
	require.Len(t, findings, len(model.AllChecks))

	seen := map[model.CheckID]bool{}
	for _, f := range findings {
		seen[f.Check] = true
	}
	for _, c := range model.AllChecks {
		assert.True(t, seen[c], "missing finding for check %s", c)
	}
}

func TestAge(t *testing.T) {
	s := model.NewBackupState()
	assert.Equal(t, "-", Age(s, testConfig()))
	s.LatestBackupAt = ago(6 * time.Hour)
	assert.Equal(t, "6h", Age(s, testConfig()))
	s.LatestBackupAt = ago(72 * time.Hour)
	assert.Equal(t, "3d", Age(s, testConfig()))
}
