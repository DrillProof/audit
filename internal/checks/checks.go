// Package checks holds the five recoverability checks.
//
// Every check is a pure function of (resource, observed backup state, config).
// No I/O, no clock reads except the one passed in — which is what makes them
// testable and what makes the score reproducible.
package checks

import (
	"fmt"
	"time"

	"github.com/drillproof/audit/internal/model"
)

// Config carries the tunable thresholds.
type Config struct {
	// FreshWarnAfter flags a backup as warn once it is older than this.
	FreshWarnAfter time.Duration
	// FreshFailAfter flags a backup as fail once it is older than this.
	FreshFailAfter time.Duration
	// Now is injected so checks are deterministic under test.
	Now time.Time
}

// DefaultConfig matches the spec: warn > 24h, fail > 7d.
func DefaultConfig() Config {
	return Config{
		FreshWarnAfter: 24 * time.Hour,
		FreshFailAfter: 7 * 24 * time.Hour,
		Now:            time.Now().UTC(),
	}
}

// Run evaluates all five checks for one resource, in canonical order.
func Run(r model.Resource, s *model.BackupState, cfg Config) []model.Finding {
	return []model.Finding{
		Coverage(r, s, cfg),
		Freshness(r, s, cfg),
		Immutability(r, s, cfg),
		Redundancy(r, s, cfg),
		RestoreTested(r, s, cfg),
	}
}

// blocked builds a finding for a check we were not permitted to evaluate.
// These are actionable: granting the permission makes the check run.
func blocked(r model.Resource, c model.CheckID, reason string) model.Finding {
	return model.Finding{
		Resource:        r,
		Check:           c,
		Status:          model.StatusSkipped,
		Summary:         fmt.Sprintf("not assessed (%s)", reason),
		SkipReason:      reason,
		SkipIsAccessGap: true,
	}
}

// moot builds a finding for a check with nothing to evaluate — a resource with
// no backup has no backup age, no cross-region copy, and no restore history.
// Reporting these as blocked would misattribute them to permissions.
func moot(r model.Resource, c model.CheckID, reason string) model.Finding {
	return model.Finding{
		Resource:   r,
		Check:      c,
		Status:     model.StatusSkipped,
		Summary:    fmt.Sprintf("not applicable (%s)", reason),
		SkipReason: reason,
	}
}

// Coverage — does this resource have a backup at all?
func Coverage(r model.Resource, s *model.BackupState, _ Config) model.Finding {
	if reason, ok := s.Unassessed[model.CheckCoverage]; ok {
		return blocked(r, model.CheckCoverage, reason)
	}
	if r.Type == model.TypeBucket {
		return coverageBucket(r, s)
	}
	if r.Type == model.TypeTable {
		return coverageTable(r, s)
	}

	f := model.Finding{Resource: r, Check: model.CheckCoverage}
	if s.RecoveryPoints > 0 {
		f.Status = model.StatusOK
		f.Summary = fmt.Sprintf("%d recovery point(s) found", s.RecoveryPoints)
		return f
	}

	f.Status = model.StatusFail
	switch r.Type {
	case model.TypeK8sState:
		f.Summary = "no backup of cluster state — the cluster is unrecoverable"
		f.Remediation = "Install Velero and schedule a backup that includes cluster resources, or enable an EKS control-plane backup path."
	case model.TypeDatabase, model.TypeDBCluster:
		f.Summary = "no backup exists — automated backups appear disabled"
		f.Remediation = "Set a non-zero backup retention period, or protect the resource with an AWS Backup plan."
	default:
		f.Summary = "no backup exists"
		f.Remediation = "Add this resource to an AWS Backup plan, or schedule snapshots."
	}
	return f
}

// Freshness — how old is the most recent successful backup?
func Freshness(r model.Resource, s *model.BackupState, cfg Config) model.Finding {
	if r.Type == model.TypeBucket {
		return moot(r, model.CheckFreshness, "live bucket — no backup age to measure")
	}
	if reason, ok := s.Unassessed[model.CheckFreshness]; ok {
		return blocked(r, model.CheckFreshness, reason)
	}
	if r.Type == model.TypeTable {
		return freshnessTable(r, s, cfg)
	}
	return freshnessFromRecoveryPoints(r, s, cfg)
}

// freshnessFromRecoveryPoints is the shared age check driven by AWS Backup
// recovery points. Both the default Freshness path and the DynamoDB
// backup-plan path call it, so there is one implementation to keep correct.
func freshnessFromRecoveryPoints(r model.Resource, s *model.BackupState, cfg Config) model.Finding {
	f := model.Finding{Resource: r, Check: model.CheckFreshness}

	// No backup at all is Coverage's finding to report, not Freshness's.
	// Double-penalising the same root cause would distort the score.
	if s.LatestBackupAt == nil {
		return moot(r, model.CheckFreshness, "no backup to age")
	}

	age := cfg.Now.Sub(*s.LatestBackupAt)
	switch {
	case age > cfg.FreshFailAfter:
		f.Status = model.StatusFail
		f.Summary = fmt.Sprintf("most recent backup is %s old (threshold %s)", humanAge(age), humanAge(cfg.FreshFailAfter))
		f.Remediation = "Check for a silently failing backup schedule; a job that stopped succeeding usually still reports as configured."
	case age > cfg.FreshWarnAfter:
		f.Status = model.StatusWarn
		f.Summary = fmt.Sprintf("most recent backup is %s old (warn after %s)", humanAge(age), humanAge(cfg.FreshWarnAfter))
		f.Remediation = "Increase backup frequency, or confirm this cadence is intentional for this resource."
	default:
		f.Status = model.StatusOK
		f.Summary = fmt.Sprintf("most recent backup is %s old", humanAge(age))
	}
	return f
}

// Immutability — are backups on WORM storage?
func Immutability(r model.Resource, s *model.BackupState, _ Config) model.Finding {
	if reason, ok := s.Unassessed[model.CheckImmutability]; ok {
		return blocked(r, model.CheckImmutability, reason)
	}
	if r.Type == model.TypeBucket {
		return immutabilityBucket(r, s)
	}
	if r.Type == model.TypeTable {
		return immutabilityTable(r, s)
	}
	return immutabilityFromVaults(r, s)
}

// immutabilityFromVaults is the shared Vault Lock check. Both the default
// Immutability path and the DynamoDB backup-plan path call it.
func immutabilityFromVaults(r model.Resource, s *model.BackupState) model.Finding {
	f := model.Finding{Resource: r, Check: model.CheckImmutability}
	switch s.Immutable {
	case model.Yes:
		f.Status = model.StatusOK
		f.Summary = "backups are on locked (WORM) storage"
	case model.No:
		f.Status = model.StatusFail
		f.Summary = "backups can be deleted — no Vault Lock or Object Lock"
		f.Remediation = "Enable AWS Backup Vault Lock (compliance mode) on the destination vault, or Object Lock on the backup bucket."
	default:
		// With no recovery points there is nothing whose lock state could
		// matter; that is moot, not a gap in our access.
		if s.RecoveryPoints == 0 {
			return moot(r, model.CheckImmutability, "no backup to protect")
		}
		return blocked(r, model.CheckImmutability, "could not determine lock configuration")
	}
	return f
}

// Redundancy — is a copy isolated from the resource's own region?
func Redundancy(r model.Resource, s *model.BackupState, _ Config) model.Finding {
	if reason, ok := s.Unassessed[model.CheckRedundancy]; ok {
		return blocked(r, model.CheckRedundancy, reason)
	}
	if r.Type == model.TypeBucket {
		return redundancyBucket(r, s)
	}
	if r.Type == model.TypeTable {
		return redundancyTable(r, s)
	}
	return redundancyFromVaults(r, s)
}

// redundancyFromVaults is the shared cross-region check driven by AWS Backup
// recovery points. Both the default Redundancy path and the DynamoDB
// backup-plan path call it.
func redundancyFromVaults(r model.Resource, s *model.BackupState) model.Finding {
	f := model.Finding{Resource: r, Check: model.CheckRedundancy}
	if s.RecoveryPoints == 0 {
		return moot(r, model.CheckRedundancy, "no backup to replicate")
	}

	switch s.CrossRegion {
	case model.Yes:
		f.Status = model.StatusOK
		f.Summary = "at least one copy exists outside the resource's region"
	case model.No:
		f.Status = model.StatusFail
		f.Summary = fmt.Sprintf("all backups are in %s, the same region as the resource", r.Region)
		f.Remediation = "Add a cross-region copy action to the backup plan so a region-level event does not take the backups with it."
	default:
		return blocked(r, model.CheckRedundancy, "could not enumerate vaults in other regions")
	}
	return f
}

// RestoreTested — has a restore ever actually been performed?
//
// This is the check the product is built around, so it is careful to
// distinguish three things: a real restore happened, a restore-testing plan
// exists but has not run yet, and nothing has ever been tried.
func RestoreTested(r model.Resource, s *model.BackupState, _ Config) model.Finding {
	if r.Type == model.TypeBucket {
		return moot(r, model.CheckRestoreTested, "restore verification for buckets is not implemented in this release")
	}
	if reason, ok := s.Unassessed[model.CheckRestoreTested]; ok {
		return blocked(r, model.CheckRestoreTested, reason)
	}

	f := model.Finding{Resource: r, Check: model.CheckRestoreTested}
	if s.RecoveryPoints == 0 {
		return moot(r, model.CheckRestoreTested, "no backup to restore")
	}

	if s.LastRestoreAt != nil {
		f.Status = model.StatusOK
		f.Summary = fmt.Sprintf("a restore was performed on %s", s.LastRestoreAt.UTC().Format("2006-01-02"))
		return f
	}

	f.Status = model.StatusFail
	if s.RestoreTestingConfigured {
		f.Status = model.StatusWarn
		f.Summary = "a restore-testing plan covers this type, but no restore has completed yet"
		f.Remediation = "Confirm the restore-testing plan is selecting this resource and that its runs are succeeding."
		return f
	}
	f.Summary = `never test-restored — "backed up" is not "recoverable"`
	f.Remediation = "Run a real restore into an isolated environment, or schedule one: https://drillproof.com/audit"
	return f
}

// humanAge formats a duration the way an engineer scanning a table wants it.
func humanAge(d time.Duration) string {
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 48*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// Age renders a state's backup age for the table, or "-" when there is none.
func Age(s *model.BackupState, cfg Config) string {
	if s.LatestBackupAt == nil {
		return "-"
	}
	return humanAge(cfg.Now.Sub(*s.LatestBackupAt))
}
