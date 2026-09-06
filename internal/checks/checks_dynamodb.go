package checks

import (
	"fmt"
	"strings"

	"github.com/drillproof/audit/internal/model"
)

// pitrOnly reports a table protected by Point-in-Time Recovery and nothing
// else. PITR is continuous and single-region, which changes what three of the
// five checks can honestly say.
func pitrOnly(s *model.BackupState) bool {
	return s.Dynamo != nil && s.Dynamo.PITR == model.Yes && s.RecoveryPoints == 0
}

// coverageTable accepts PITR *or* an AWS Backup plan.
//
// Most teams protect DynamoDB with PITR rather than AWS Backup. A table with
// PITR on and no backup plan is protected; flagging it is a false positive, and
// false positives are how an audit tool loses the room.
func coverageTable(r model.Resource, s *model.BackupState) model.Finding {
	if s.Dynamo == nil {
		return blocked(r, model.CheckCoverage, "dynamodb:DescribeContinuousBackups not read")
	}

	f := model.Finding{Resource: r, Check: model.CheckCoverage}
	pitr := s.Dynamo.PITR == model.Yes
	plan := s.RecoveryPoints > 0

	switch {
	case pitr && plan:
		f.Status = model.StatusOK
		f.Summary = fmt.Sprintf("Point-in-Time Recovery is enabled, and %d recovery point(s) exist from an AWS Backup plan", s.RecoveryPoints)
	case pitr:
		f.Status = model.StatusOK
		f.Summary = "Point-in-Time Recovery is enabled"
	case plan:
		f.Status = model.StatusOK
		f.Summary = fmt.Sprintf("%d recovery point(s) found", s.RecoveryPoints)
	default:
		f.Status = model.StatusFail
		f.Summary = "no backup exists — Point-in-Time Recovery is off and no backup plan covers this table"
		f.Remediation = "Enable Point-in-Time Recovery on the table, or add it to an AWS Backup plan. PITR is a single API call and covers the previous 35 days."
	}
	return f
}

// freshnessTable falls back to the shared age logic when a backup plan exists.
// PITR is continuous, so "age of last backup" is meaningless for a PITR-only
// table — substituting one would answer a different question.
func freshnessTable(r model.Resource, s *model.BackupState, cfg Config) model.Finding {
	if pitrOnly(s) {
		return moot(r, model.CheckFreshness, "Point-in-Time Recovery is continuous — there is no last-backup age")
	}
	return freshnessFromRecoveryPoints(r, s, cfg)
}

// immutabilityTable uses Vault Lock on the destination vault, exactly as
// EBS/RDS do. PITR has no vault, so there is nothing whose lock state could
// matter.
func immutabilityTable(r model.Resource, s *model.BackupState) model.Finding {
	if pitrOnly(s) {
		return moot(r, model.CheckImmutability, "Point-in-Time Recovery has no vault to lock")
	}
	return immutabilityFromVaults(r, s)
}

// redundancyTable is the one place a table with no recovery points still gets a
// verdict rather than an N/A.
//
// PITR is single-region by construction. That is a real gap in a real estate,
// not an absent one, so reporting it as "not applicable" would hide the finding
// rather than state a limit honestly.
func redundancyTable(r model.Resource, s *model.BackupState) model.Finding {
	if !pitrOnly(s) {
		return redundancyFromVaults(r, s)
	}

	f := model.Finding{
		Resource: r,
		Check:    model.CheckRedundancy,
		Status:   model.StatusFail,
		Summary: fmt.Sprintf(
			"Point-in-Time Recovery is single region — everything recoverable for this table lives in %s",
			r.Region),
		Remediation: "Add this table to an AWS Backup plan with a cross-region backup copy action. PITR does not survive the loss of its region.",
	}

	if len(s.Dynamo.GlobalTableReplicas) > 0 {
		// Naming the replica matters: the customer almost certainly believes it
		// is their redundancy, and it is not.
		f.Summary = fmt.Sprintf(
			"Point-in-Time Recovery is single region; the global-table replica in %s is not a backup — a delete propagates to it",
			strings.Join(s.Dynamo.GlobalTableReplicas, ", "))
	}
	return f
}
