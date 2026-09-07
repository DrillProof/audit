package checks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drillproof/audit/internal/model"
)

func efsResource(oneZone bool) model.Resource {
	attrs := map[string]string{"file_system": "fs-1", "storage_class": "regional"}
	if oneZone {
		attrs["storage_class"] = "one-zone"
		attrs["availability_zone"] = "us-east-1a"
	}
	return model.Resource{
		Display: "shared-data (EFS)", Name: "shared-data",
		ARN:    "arn:aws:elasticfilesystem:us-east-1:111122223333:file-system/fs-1",
		Type:   model.TypeFileSystem,
		Region: "us-east-1",
		Attrs:  attrs,
	}
}

func efsState(automatic model.Tristate, recoveryPoints int, oneZone bool) *model.BackupState {
	s := model.NewBackupState()
	s.EFS = &model.EFSProtection{AutomaticBackups: automatic}
	if oneZone {
		s.EFS.OneZone = model.Yes
		s.EFS.AvailabilityZone = "us-east-1a"
	} else {
		s.EFS.OneZone = model.No
	}
	s.RecoveryPoints = recoveryPoints
	return s
}

func efsConfig() Config {
	return Config{
		FreshWarnAfter: 24 * time.Hour,
		FreshFailAfter: 7 * 24 * time.Hour,
		Now:            time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC),
	}
}

// The false-positive guard: automatic backups alone protect a filesystem.
func TestCoverageAcceptsAutomaticBackupsAlone(t *testing.T) {
	f := Coverage(efsResource(false), efsState(model.Yes, 0, false), efsConfig())
	assert.Equal(t, model.StatusOK, f.Status)
	assert.Contains(t, f.Summary, "automatic backups")
}

func TestCoverageAcceptsBackupPlanAlone(t *testing.T) {
	f := Coverage(efsResource(false), efsState(model.No, 3, false), efsConfig())
	assert.Equal(t, model.StatusOK, f.Status)
	assert.Contains(t, f.Summary, "3 recovery point(s)")
}

func TestCoverageNotesBothPaths(t *testing.T) {
	f := Coverage(efsResource(false), efsState(model.Yes, 2, false), efsConfig())
	assert.Equal(t, model.StatusOK, f.Status)
	assert.Contains(t, f.Summary, "automatic backups")
	assert.Contains(t, f.Summary, "2 recovery point(s)")
}

func TestCoverageFailsWithNeither(t *testing.T) {
	f := Coverage(efsResource(false), efsState(model.No, 0, false), efsConfig())
	assert.Equal(t, model.StatusFail, f.Status)
	assert.NotEmpty(t, f.Remediation)
}

func TestCoverageOneZoneWithNoBackupSaysSoPlainly(t *testing.T) {
	r := efsResource(true)
	s := efsState(model.No, 0, true)
	f := Coverage(r, s, efsConfig())
	assert.Equal(t, model.StatusFail, f.Status)
	assert.Contains(t, f.Summary, "One Zone")
	assert.True(t, OneZoneNoBackup(r, s), "this is the compounding-risk case the score weights extra")
}

func TestCoverageOneZoneWithBackupsPassesWithContextOnly(t *testing.T) {
	r := efsResource(true)
	s := efsState(model.Yes, 0, true)
	f := Coverage(r, s, efsConfig())
	assert.Equal(t, model.StatusOK, f.Status)
	// Storage class is context, never a failure on its own: a One Zone
	// filesystem that is properly backed up is a legitimate cost choice.
	assert.Contains(t, f.Summary, "One Zone")
	assert.False(t, OneZoneNoBackup(r, s))
}

func TestCoverageDeniedPolicyIsNotAssessed(t *testing.T) {
	s := efsState(model.Unknown, 0, false)
	s.MarkUnassessed(model.CheckCoverage, "elasticfilesystem:DescribeBackupPolicy denied")
	f := Coverage(efsResource(false), s, efsConfig())
	assert.Equal(t, model.StatusSkipped, f.Status)
	assert.True(t, f.SkipIsAccessGap)
	assert.Contains(t, f.SkipReason, "elasticfilesystem:DescribeBackupPolicy")
}

func TestRedundancyAcceptsCrossRegionReplication(t *testing.T) {
	s := efsState(model.Yes, 0, false)
	s.EFS.Replication = model.EFSReplicationState{
		Configured: model.Yes, Healthy: model.Yes, CrossRegion: model.Yes,
		DestRegions: []string{"us-west-2"},
	}
	f := Redundancy(efsResource(false), s, efsConfig())
	assert.Equal(t, model.StatusOK, f.Status)
	assert.Contains(t, f.Summary, "us-west-2")
}

func TestRedundancyFailsSameRegionReplication(t *testing.T) {
	s := efsState(model.Yes, 0, false)
	s.EFS.Replication = model.EFSReplicationState{
		Configured: model.Yes, Healthy: model.Yes, CrossRegion: model.No,
		DestRegions: []string{"us-east-1"},
	}
	f := Redundancy(efsResource(false), s, efsConfig())
	assert.Equal(t, model.StatusFail, f.Status)
	assert.Contains(t, f.Summary, "does not survive the loss of")
}

func TestRedundancyFailsUnhealthyReplication(t *testing.T) {
	s := efsState(model.Yes, 0, false)
	s.EFS.Replication = model.EFSReplicationState{
		Configured: model.Yes, Healthy: model.No, CrossRegion: model.Yes,
		DestRegions: []string{"us-west-2"},
	}
	f := Redundancy(efsResource(false), s, efsConfig())
	assert.Equal(t, model.StatusFail, f.Status)
	assert.Contains(t, f.Summary, "not healthy")
}

func TestRedundancyUnknownReplicationHealthIsNotAPass(t *testing.T) {
	s := efsState(model.Yes, 0, false)
	s.EFS.Replication = model.EFSReplicationState{
		Configured: model.Yes, Healthy: model.Unknown, CrossRegion: model.Yes,
	}
	f := Redundancy(efsResource(false), s, efsConfig())
	assert.Equal(t, model.StatusSkipped, f.Status)
	assert.True(t, f.SkipIsAccessGap)
}

func TestRedundancyAcceptsBackupCopyWithoutReplication(t *testing.T) {
	s := efsState(model.No, 2, false)
	s.CrossRegion = model.Yes
	s.EFS.Replication = model.EFSReplicationState{Configured: model.No}
	f := Redundancy(efsResource(false), s, efsConfig())
	assert.Equal(t, model.StatusOK, f.Status)
}

func TestRedundancyFailsWithNeitherPath(t *testing.T) {
	s := efsState(model.No, 2, false)
	s.CrossRegion = model.No
	s.EFS.Replication = model.EFSReplicationState{Configured: model.No}
	f := Redundancy(efsResource(false), s, efsConfig())
	assert.Equal(t, model.StatusFail, f.Status)
}

func TestFreshnessAndImmutabilityReuseTheSharedLogic(t *testing.T) {
	s := efsState(model.Yes, 1, false)
	backedUp := efsConfig().Now.Add(-2 * time.Hour)
	s.LatestBackupAt = &backedUp
	s.Immutable = model.Yes

	fresh := Freshness(efsResource(false), s, efsConfig())
	require.Equal(t, model.StatusOK, fresh.Status)
	assert.Contains(t, fresh.Summary, "2h old")

	immutable := Immutability(efsResource(false), s, efsConfig())
	assert.Equal(t, model.StatusOK, immutable.Status)
}
