// Package model holds the vocabulary shared by every layer of the audit: what
// a protected resource is, what we managed to learn about its backups, and what
// a single check concluded.
//
// Deliberately dependency-free. The AWS and Kubernetes layers translate their
// SDK types into these; the checks, scorer, and renderers only ever see these.
// That is what keeps the checks pure and testable with fakes.
package model

import "time"

// ResourceType is the kind of thing being protected. The strings are stable —
// they appear in JSON and SARIF output, so treat them as API.
type ResourceType string

const (
	TypeVolume     ResourceType = "volume"      // EBS
	TypeDatabase   ResourceType = "database"    // RDS instance
	TypeDBCluster  ResourceType = "db-cluster"  // RDS/Aurora cluster
	TypeK8sState   ResourceType = "k8s-state"   // EKS cluster state / etcd
	TypeBucket     ResourceType = "bucket"      // S3 bucket
	TypeTable      ResourceType = "table"       // DynamoDB table
	TypeFileSystem ResourceType = "file-system" // EFS
)

// CheckID identifies one of the six checks. Stable API.
type CheckID string

const (
	CheckCoverage      CheckID = "coverage"
	CheckFreshness     CheckID = "freshness"
	CheckImmutability  CheckID = "immutability"
	CheckRedundancy    CheckID = "redundancy"
	CheckRestoreTested CheckID = "restore-testing"
	// CheckKeyAvailability asks whether the KMS keys protecting this
	// resource's recovery points are still present and enabled. A backup
	// encrypted with a deleted key cannot be restored, and every other check
	// passes it — which is why this is a check and not a note.
	CheckKeyAvailability CheckID = "key-availability"
)

// AllChecks is the canonical order checks run and render in.
var AllChecks = []CheckID{
	CheckCoverage,
	CheckFreshness,
	CheckImmutability,
	CheckRedundancy,
	CheckRestoreTested,
	CheckKeyAvailability,
}

// Status is a check outcome.
type Status string

const (
	StatusOK   Status = "ok"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
	// StatusSkipped means the check did not produce a verdict, either because
	// we were not permitted to look or because there was nothing to look at.
	// See Finding.SkipIsAccessGap for which. Never treated as a pass.
	StatusSkipped Status = "skipped"
)

// Tristate distinguishes "we know it is false" from "we could not find out".
// Collapsing those two is how audit tools end up lying, so the distinction is
// carried all the way to the output.
type Tristate int

const (
	Unknown Tristate = iota
	Yes
	No
)

func (t Tristate) String() string {
	switch t {
	case Yes:
		return "yes"
	case No:
		return "no"
	default:
		return "unknown"
	}
}

// Resource is one protected thing, normalised across services.
type Resource struct {
	// Display is the human label used in the table, e.g. "payments-db (RDS)".
	Display string       `json:"display"`
	Name    string       `json:"name"`
	ARN     string       `json:"arn,omitempty"`
	Type    ResourceType `json:"type"`
	Region  string       `json:"region"`
	// Production is a best-effort heuristic (name/tags). It only ever
	// increases scrutiny, never decreases it.
	Production bool `json:"production"`
	// Attrs carries service-specific detail for the report, e.g. engine, size.
	Attrs map[string]string `json:"attrs,omitempty"`
}

// ProtectionTier names how strongly a bucket is protected against deletion.
//
// S3 is not a volume — it *is* the storage — so "does a backup exist" is the
// wrong question and the answer is graded rather than binary. The tier is
// surfaced in the finding text so a customer can see why they passed or failed
// rather than being handed a verdict.
type ProtectionTier string

const (
	// TierStrongest is Object Lock in COMPLIANCE mode: undeletable before
	// retention expires, even by root.
	TierStrongest ProtectionTier = "strongest"
	// TierStrong is versioning plus MFA Delete.
	TierStrong ProtectionTier = "strong"
	// TierPartial is versioning with MFA Delete off or unreadable.
	TierPartial ProtectionTier = "partial"
	// TierWeak is Object Lock in GOVERNANCE mode only — overridable by anyone
	// holding s3:BypassGovernanceRetention.
	TierWeak ProtectionTier = "weak"
	// TierUnprotected is neither versioning nor Object Lock.
	TierUnprotected ProtectionTier = "unprotected"
)

// ReplicationState is what GetBucketReplication told us.
//
// The three fields are deliberately separate rather than one boolean: a rule
// that exists but is Disabled is the S3 analogue of a silently failing backup
// schedule, and reporting it as "no replication" would lose the finding most
// worth having.
type ReplicationState struct {
	// Configured is whether any replication configuration exists at all.
	Configured Tristate `json:"configured"`
	// EnabledRule is whether at least one rule has Status == Enabled.
	EnabledRule Tristate `json:"enabled_rule"`
	// CrossRegion is whether an enabled rule targets another region. Unknown
	// when the destination bucket's region could not be resolved.
	CrossRegion Tristate `json:"cross_region"`
	// DestRegions are the resolved destination regions, for the finding text.
	DestRegions []string `json:"dest_regions,omitempty"`
}

// S3Protection is a bucket's deletion-protection posture. Non-nil only when
// Resource.Type is TypeBucket.
type S3Protection struct {
	Tier ProtectionTier `json:"tier"`
	// ObjectLockMode is "COMPLIANCE", "GOVERNANCE", or "" when Object Lock is
	// off or no default retention rule is configured.
	ObjectLockMode string           `json:"object_lock_mode,omitempty"`
	Versioning     Tristate         `json:"versioning"`
	MFADelete      Tristate         `json:"mfa_delete"`
	Replication    ReplicationState `json:"replication"`
}

// DynamoProtection is a table's continuous-backup posture. Non-nil only when
// Resource.Type is TypeTable.
type DynamoProtection struct {
	// PITR is Point-in-Time Recovery. Most teams protect DynamoDB with this
	// rather than AWS Backup, so a table with PITR on and no backup plan is
	// protected — flagging it otherwise is a false positive.
	PITR Tristate `json:"pitr"`
	// GlobalTableReplicas are regions holding a global-table replica. A
	// replica is NOT a backup: a delete propagates to it. Recorded for the
	// finding text, never to satisfy redundancy.
	GlobalTableReplicas []string `json:"global_table_replicas,omitempty"`
}

// EFSReplicationState is what DescribeReplicationConfigurations told us.
//
// Health is carried separately from existence for the same reason S3 splits
// Configured from EnabledRule: a replication that exists but sits in ERROR is
// the EFS analogue of a silently failing backup schedule, and reporting it as
// "replicated" would lose the finding most worth having.
type EFSReplicationState struct {
	// Configured is whether any replication configuration exists at all.
	Configured Tristate `json:"configured"`
	// Healthy is whether at least one destination is in a good state.
	// Unknown when the status could not be read — never assumed healthy.
	Healthy Tristate `json:"healthy"`
	// CrossRegion is whether a destination is in another region.
	CrossRegion Tristate `json:"cross_region"`
	// DestRegions are the destination regions, for the finding text.
	DestRegions []string `json:"dest_regions,omitempty"`
}

// EFSProtection is a filesystem's backup posture. Non-nil only when
// Resource.Type is TypeFileSystem.
type EFSProtection struct {
	// AutomaticBackups is EFS's built-in backup policy — an AWS Backup
	// default plan, separate from any user-defined plan. A filesystem with
	// this on IS protected; flagging it would be the same class of false
	// positive as failing a PITR-only DynamoDB table.
	AutomaticBackups Tristate `json:"automatic_backups"`
	// OneZone is whether the filesystem is single-AZ. A One Zone filesystem
	// does not survive the loss of its availability zone.
	OneZone Tristate `json:"one_zone"`
	// AvailabilityZone is the AZ name for a One Zone filesystem, empty for a
	// Regional one. Reported as context, not as a failure.
	AvailabilityZone string `json:"availability_zone,omitempty"`
	// Replication is EFS's own cross-region replication, distinct from an AWS
	// Backup copy job.
	Replication EFSReplicationState `json:"replication"`
}

// RecoveryPointKey is one KMS key protecting a resource's recovery points.
//
// Deliberately the *backup's* key, not the live resource's: restoring a
// snapshot needs the key the snapshot was written with, and the two diverge
// whenever a resource is re-encrypted after a backup was taken.
type RecoveryPointKey struct {
	// KeyARN is the key as the recovery point reported it.
	KeyARN string `json:"key_arn"`
	// State is KeyMetadata.KeyState verbatim ("Enabled", "Disabled",
	// "PendingDeletion", "PendingImport", "Unavailable"). Empty when the key
	// could not be described — see CrossAccount and the Unassessed reason.
	State string `json:"state,omitempty"`
	// AWSManaged is KeyMetadata.KeyManager == "AWS". An AWS-managed key
	// cannot be disabled or deleted by the customer, so it never fails.
	AWSManaged bool `json:"aws_managed,omitempty"`
	// CrossAccount is whether the key lives in another account. Unknown when
	// the scanned account's own id could not be resolved — in that case the
	// check must skip rather than assume same-account.
	CrossAccount Tristate `json:"cross_account"`
	// DeletionDate is set only for State == "PendingDeletion". The countdown
	// is the whole value of that finding.
	DeletionDate *time.Time `json:"deletion_date,omitempty"`
}

// BackupState is everything the discovery layer learned about one resource's
// backups. The checks read this and nothing else.
type BackupState struct {
	// RecoveryPoints is how many usable restore points were found.
	RecoveryPoints int
	// LatestBackupAt is the completion time of the most recent *successful*
	// backup. Nil means none was found.
	LatestBackupAt *time.Time
	// Immutable is whether backups sit on WORM storage (AWS Backup Vault Lock
	// or S3 Object Lock).
	Immutable Tristate
	// CrossRegion is whether at least one copy lives in another region.
	CrossRegion Tristate
	// LastRestoreAt is when a restore was last performed from any of this
	// resource's recovery points. This is the "verified recoverable" signal.
	LastRestoreAt *time.Time
	// RestoreTestingConfigured reports an AWS Backup restore-testing plan
	// covering this resource type.
	RestoreTestingConfigured bool
	// S3 is the bucket deletion-protection posture. Nil for every other type.
	S3 *S3Protection `json:"s3,omitempty"`
	// Dynamo is the table continuous-backup posture. Nil for every other type.
	Dynamo *DynamoProtection `json:"dynamo,omitempty"`
	// EFS is the filesystem backup posture. Nil for every other type.
	EFS *EFSProtection `json:"efs,omitempty"`
	// Keys are the KMS keys protecting this resource's recovery points. Empty
	// means the backups are unencrypted, which is not a finding — it is
	// nothing to assess.
	Keys []RecoveryPointKey `json:"keys,omitempty"`
	// Unassessed records why a given check could not run — keyed by check.
	Unassessed map[CheckID]string
	// Notes are extra facts worth surfacing in the report.
	Notes []string
}

// NewBackupState returns a state with maps initialised.
func NewBackupState() *BackupState {
	return &BackupState{Unassessed: map[CheckID]string{}}
}

// MarkUnassessed records that a check cannot be evaluated, with the reason.
func (s *BackupState) MarkUnassessed(c CheckID, reason string) {
	if s.Unassessed == nil {
		s.Unassessed = map[CheckID]string{}
	}
	s.Unassessed[c] = reason
}

// Finding is one check's conclusion about one resource.
type Finding struct {
	Resource    Resource `json:"resource"`
	Check       CheckID  `json:"check"`
	Status      Status   `json:"status"`
	Summary     string   `json:"summary"`
	Remediation string   `json:"remediation,omitempty"`
	// SkipReason is set when Status is StatusSkipped.
	SkipReason string `json:"skip_reason,omitempty"`
	// SkipIsAccessGap separates "we were not allowed to look" from "there was
	// nothing here to look at".
	//
	// These must never be conflated. Telling someone their checks were blocked
	// by permissions when in truth the resource simply has no backup is a false
	// statement about their estate, and the score's credibility is the whole
	// product. Only an access gap is actionable by granting permissions.
	SkipIsAccessGap bool `json:"skip_is_access_gap,omitempty"`
}

// AccessGaps counts skipped checks that a permission grant would fix.
func AccessGaps(findings []Finding) int {
	n := 0
	for _, f := range findings {
		if f.Status == StatusSkipped && f.SkipIsAccessGap {
			n++
		}
	}
	return n
}

// NotApplicable counts skipped checks that were simply moot — most often a
// resource with no backup, where freshness and redundancy have nothing to say.
func NotApplicable(findings []Finding) int {
	n := 0
	for _, f := range findings {
		if f.Status == StatusSkipped && !f.SkipIsAccessGap {
			n++
		}
	}
	return n
}

// AccessGapReasons returns the distinct access-gap reasons, so the report can
// tell the user exactly which permission to grant rather than just a count.
func AccessGapReasons(findings []Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		if f.Status == StatusSkipped && f.SkipIsAccessGap && !seen[f.SkipReason] {
			seen[f.SkipReason] = true
			out = append(out, f.SkipReason)
		}
	}
	return out
}

// Row is the per-resource view the table renders: the five check outcomes
// collapsed into one line.
type Row struct {
	Resource Resource           `json:"resource"`
	State    *BackupState       `json:"state"`
	Statuses map[CheckID]Status `json:"statuses"`
}

// Result is a complete scan.
type Result struct {
	AccountID   string    `json:"account_id"`
	AccountArn  string    `json:"account_arn,omitempty"`
	Regions     []string  `json:"regions"`
	GeneratedAt time.Time `json:"generated_at"`
	Rows        []Row     `json:"rows"`
	Findings    []Finding `json:"findings"`
	Score       Score     `json:"score"`
	// Warnings are scan-level problems: a region that errored, a missing
	// permission that affected everything, kubeconfig that would not load.
	Warnings []string `json:"warnings,omitempty"`
	Version  string   `json:"version"`
}

// Penalty is one deduction from the perfect score, with its reason. Exposing
// these is what makes the score explainable rather than a magic number.
type Penalty struct {
	Check    CheckID `json:"check"`
	Resource string  `json:"resource"`
	Points   int     `json:"points"`
	Reason   string  `json:"reason"`
}

// ResourceScore is one resource's own recoverability, 0-100, plus how heavily
// it counts toward the estate score.
//
// The estate score is a weighted mean of these, so without them the headline
// number is unexplainable — `--explain` could print deductions but not the
// arithmetic that produced the value.
type ResourceScore struct {
	// Resource is the display label, matching Penalty.Resource.
	Resource string `json:"resource"`
	// Score is 0-100 for this resource alone. A resource with no backup is 0:
	// it is unrecoverable, and its other checks are moot.
	Score int `json:"score"`
	// Weight is 2 for critical resources (cluster state, production
	// databases), 1 otherwise.
	Weight int `json:"weight"`
}

// Score is the Recoverability Score and the arithmetic behind it.
type Score struct {
	Value        int       `json:"value"`         // 0-100
	CriticalGaps int       `json:"critical_gaps"` // count of failing checks
	Penalties    []Penalty `json:"penalties"`
	// ResourceScores is the per-resource arithmetic behind Value, sorted
	// worst-first then by resource.
	ResourceScores []ResourceScore `json:"resource_scores"`
	// RawDeduction is the absolute sum of every deduction, with no zeroing and
	// no floor, so a catastrophic estate can be distinguished from a merely
	// bad one in the report even though Value itself no longer can (Value is
	// a weighted mean of per-resource scores, each floored at 0).
	RawDeduction int `json:"raw_deduction"`
	// Assessed is how many checks actually ran (skipped ones excluded).
	Assessed int `json:"assessed"`
	Skipped  int `json:"skipped"`
	// Blocked and Moot split Skipped by cause. Only Blocked is fixable by
	// granting a permission; conflating them misdirects the reader.
	Blocked int `json:"blocked"`
	Moot    int `json:"moot"`
}
