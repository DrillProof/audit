package checks

import (
	"testing"
	"time"

	"github.com/drillproof/audit/internal/model"
	"github.com/stretchr/testify/assert"
)

func table() model.Resource {
	return model.Resource{
		Display: "sessions (DynamoDB)",
		Name:    "sessions",
		Type:    model.TypeTable,
		Region:  "us-east-1",
	}
}

func tableState(pitr model.Tristate, recoveryPoints int) *model.BackupState {
	s := model.NewBackupState()
	s.Dynamo = &model.DynamoProtection{PITR: pitr}
	s.RecoveryPoints = recoveryPoints
	return s
}

func TestTableCoverage(t *testing.T) {
	t.Run("PITR alone is protected", func(t *testing.T) {
		// The false-positive guard. Most teams protect DynamoDB with PITR, not
		// AWS Backup; failing a PITR-enabled table would be wrong and would be
		// the first thing a design partner noticed.
		f := Coverage(table(), tableState(model.Yes, 0), testConfig())
		assert.Equal(t, model.StatusOK, f.Status)
		assert.Contains(t, f.Summary, "Point-in-Time Recovery")
	})

	t.Run("backup plan alone is protected", func(t *testing.T) {
		f := Coverage(table(), tableState(model.No, 4), testConfig())
		assert.Equal(t, model.StatusOK, f.Status)
		assert.Contains(t, f.Summary, "4 recovery point")
	})

	t.Run("both are noted", func(t *testing.T) {
		f := Coverage(table(), tableState(model.Yes, 4), testConfig())
		assert.Equal(t, model.StatusOK, f.Status)
		assert.Contains(t, f.Summary, "Point-in-Time Recovery")
		assert.Contains(t, f.Summary, "recovery point")
	})

	t.Run("neither fails", func(t *testing.T) {
		f := Coverage(table(), tableState(model.No, 0), testConfig())
		assert.Equal(t, model.StatusFail, f.Status)
		assert.NotEmpty(t, f.Remediation)
	})

	t.Run("unreadable PITR is blocked and names the action", func(t *testing.T) {
		s := tableState(model.Unknown, 0)
		s.MarkUnassessed(model.CheckCoverage, "dynamodb:DescribeContinuousBackups denied")
		f := Coverage(table(), s, testConfig())
		assert.Equal(t, model.StatusSkipped, f.Status)
		assert.True(t, f.SkipIsAccessGap)
		assert.Contains(t, f.SkipReason, "dynamodb:DescribeContinuousBackups")
	})
}

func TestTablePITROnlyChecks(t *testing.T) {
	s := tableState(model.Yes, 0)

	t.Run("freshness is not applicable", func(t *testing.T) {
		f := Freshness(table(), s, testConfig())
		assert.Equal(t, model.StatusSkipped, f.Status)
		assert.False(t, f.SkipIsAccessGap)
		assert.Contains(t, f.Summary, "continuous")
	})

	t.Run("immutability is not applicable", func(t *testing.T) {
		f := Immutability(table(), s, testConfig())
		assert.Equal(t, model.StatusSkipped, f.Status)
		assert.False(t, f.SkipIsAccessGap)
	})

	t.Run("redundancy fails and explains the single-region limit", func(t *testing.T) {
		// The one deliberate exception to "no recovery points means moot".
		// PITR is genuinely single-region, so this is a real gap, not an
		// absent one — reporting it as N/A would hide the finding.
		f := Redundancy(table(), s, testConfig())
		assert.Equal(t, model.StatusFail, f.Status)
		assert.Contains(t, f.Summary, "single region")
		assert.NotEmpty(t, f.Remediation)
	})
}

func TestTableGlobalReplicaDoesNotSatisfyRedundancy(t *testing.T) {
	// A replica is not a backup: a delete propagates to it. Counting it would
	// be the exact false confidence this product exists to challenge.
	s := tableState(model.Yes, 0)
	s.Dynamo.GlobalTableReplicas = []string{"eu-west-1"}

	f := Redundancy(table(), s, testConfig())
	assert.Equal(t, model.StatusFail, f.Status)
	assert.Contains(t, f.Summary, "replica")
	assert.Contains(t, f.Remediation, "cross-region backup copy")
}

func TestTableWithBackupPlanUsesExistingLogic(t *testing.T) {
	s := tableState(model.No, 2)
	latest := fixedNow.Add(-3 * time.Hour)
	s.LatestBackupAt = &latest
	s.Immutable = model.Yes
	s.CrossRegion = model.Yes

	assert.Equal(t, model.StatusOK, Freshness(table(), s, testConfig()).Status)
	assert.Equal(t, model.StatusOK, Immutability(table(), s, testConfig()).Status)
	assert.Equal(t, model.StatusOK, Redundancy(table(), s, testConfig()).Status)
}

func TestTableRestoreTestingIsUnchanged(t *testing.T) {
	s := tableState(model.No, 2)
	f := RestoreTested(table(), s, testConfig())
	assert.Equal(t, model.StatusFail, f.Status)
	assert.Contains(t, f.Summary, "never test-restored")
}
