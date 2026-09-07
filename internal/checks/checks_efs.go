package checks

import (
	"fmt"
	"strings"

	"github.com/drillproof/audit/internal/model"
)

// OneZoneNoBackup reports the compounding-risk case: a single-AZ filesystem
// with no recovery path at all.
//
// Exported so the one definition is testable on its own and can be reused by
// anything that needs to name this case. The scorer cannot call it — it sees
// findings, not states — which is exactly why the storage class also rides on
// Resource.Attrs; oneZoneFileSystem() in internal/score is the findings-side
// half of the same rule, and the two must stay in step.
func OneZoneNoBackup(r model.Resource, s *model.BackupState) bool {
	if r.Type != model.TypeFileSystem || s.EFS == nil {
		return false
	}
	return s.EFS.OneZone == model.Yes && !efsProtected(s)
}

// efsProtected is the coverage predicate: automatic backups OR a plan.
func efsProtected(s *model.BackupState) bool {
	return (s.EFS != nil && s.EFS.AutomaticBackups == model.Yes) || s.RecoveryPoints > 0
}

// coverageFileSystem accepts EFS automatic backups *or* a user-defined AWS
// Backup plan.
//
// The automatic-backup feature is a separate AWS Backup default plan, enabled
// at filesystem creation and invisible to a plan-only check. A filesystem with
// it on is protected; reporting it as unprotected is the same class of false
// positive as failing a PITR-only DynamoDB table, and false positives are how
// an audit tool loses the room.
func coverageFileSystem(r model.Resource, s *model.BackupState) model.Finding {
	if s.EFS == nil {
		return blocked(r, model.CheckCoverage, "elasticfilesystem:DescribeBackupPolicy not read")
	}

	f := model.Finding{Resource: r, Check: model.CheckCoverage}
	automatic := s.EFS.AutomaticBackups == model.Yes
	plan := s.RecoveryPoints > 0
	zone := oneZoneSuffix(s)

	switch {
	case automatic && plan:
		f.Status = model.StatusOK
		f.Summary = fmt.Sprintf(
			"automatic backups are enabled, and %d recovery point(s) exist from an AWS Backup plan%s",
			s.RecoveryPoints, zone)
	case automatic:
		f.Status = model.StatusOK
		f.Summary = "automatic backups are enabled" + zone
	case plan:
		f.Status = model.StatusOK
		f.Summary = fmt.Sprintf("%d recovery point(s) found%s", s.RecoveryPoints, zone)
	default:
		f.Status = model.StatusFail
		f.Summary = "no backup exists — automatic backups are off and no backup plan covers this filesystem"
		f.Remediation = "Enable automatic backups on the filesystem, or add it to an AWS Backup plan."
		if s.EFS.OneZone == model.Yes {
			f.Summary = fmt.Sprintf(
				"no backup exists, and this is a One Zone filesystem in %s — losing that availability zone loses the data outright",
				s.EFS.AvailabilityZone)
			f.Remediation = "Enable automatic backups or add the filesystem to an AWS Backup plan. A One Zone filesystem has no second copy of its own."
		}
	}
	return f
}

// oneZoneSuffix reports the storage class as context on a passing finding.
// Never a failure on its own: One Zone with backups is a deliberate cost
// choice, and penalising it would be penalising the architecture, not the
// recoverability.
func oneZoneSuffix(s *model.BackupState) string {
	if s.EFS == nil || s.EFS.OneZone != model.Yes {
		return ""
	}
	if s.EFS.AvailabilityZone != "" {
		return fmt.Sprintf(" (One Zone storage class, %s)", s.EFS.AvailabilityZone)
	}
	return " (One Zone storage class)"
}

// redundancyFileSystem accepts an AWS Backup cross-region copy *or* EFS
// Replication. Either genuinely survives the loss of the source region; only
// accepting the first would fail estates that are correctly protected.
func redundancyFileSystem(r model.Resource, s *model.BackupState) model.Finding {
	if s.EFS == nil {
		return blocked(r, model.CheckRedundancy, "elasticfilesystem:DescribeReplicationConfigurations not read")
	}

	repl := s.EFS.Replication
	f := model.Finding{Resource: r, Check: model.CheckRedundancy}

	// An AWS Backup cross-region copy answers the question on its own.
	if s.CrossRegion == model.Yes {
		f.Status = model.StatusOK
		f.Summary = "at least one backup copy exists outside the filesystem's region"
		return f
	}

	if repl.Configured == model.Yes {
		switch {
		case repl.Healthy == model.No:
			f.Status = model.StatusFail
			f.Summary = "replication is configured but not healthy — it is not currently protecting this filesystem"
			f.Remediation = "Investigate the replication configuration's status in the EFS console; a failed replication is not a copy."
			return f
		case repl.Healthy == model.Unknown:
			return blocked(r, model.CheckRedundancy, "could not determine EFS replication health")
		case repl.CrossRegion == model.Yes:
			f.Status = model.StatusOK
			f.Summary = fmt.Sprintf("EFS Replication is healthy and targets %s",
				strings.Join(repl.DestRegions, ", "))
			return f
		case repl.CrossRegion == model.No:
			f.Status = model.StatusFail
			f.Summary = fmt.Sprintf(
				"EFS Replication targets %s, the same region as the filesystem — it does not survive the loss of that region",
				strings.Join(repl.DestRegions, ", "))
			f.Remediation = "Point replication at another region, or add a cross-region copy action to an AWS Backup plan."
			return f
		default:
			return blocked(r, model.CheckRedundancy, "could not resolve the EFS replication destination region")
		}
	}

	if repl.Configured == model.Unknown {
		return blocked(r, model.CheckRedundancy, "could not determine whether EFS replication is configured")
	}

	// Neither path. Fall through to the shared vault logic so a filesystem
	// with no backup at all is reported as moot ("no backup to replicate")
	// rather than as a redundancy failure on top of its coverage failure.
	return redundancyFromVaults(r, s)
}
