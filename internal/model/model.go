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
	TypeVolume    ResourceType = "volume"     // EBS
	TypeDatabase  ResourceType = "database"   // RDS instance
	TypeDBCluster ResourceType = "db-cluster" // RDS/Aurora cluster
	TypeK8sState  ResourceType = "k8s-state"  // EKS cluster state / etcd
)

// CheckID identifies one of the five checks. Stable API.
type CheckID string

const (
	CheckCoverage      CheckID = "coverage"
	CheckFreshness     CheckID = "freshness"
	CheckImmutability  CheckID = "immutability"
	CheckRedundancy    CheckID = "redundancy"
	CheckRestoreTested CheckID = "restore-testing"
)

// AllChecks is the canonical order checks run and render in.
var AllChecks = []CheckID{
	CheckCoverage,
	CheckFreshness,
	CheckImmutability,
	CheckRedundancy,
	CheckRestoreTested,
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

// Score is the Recoverability Score and the arithmetic behind it.
type Score struct {
	Value        int       `json:"value"`         // 0-100
	CriticalGaps int       `json:"critical_gaps"` // count of failing checks
	Penalties    []Penalty `json:"penalties"`
	// MaxPenalty is the total deduction before clamping, so a catastrophic
	// estate can be distinguished from a merely bad one in the report.
	RawDeduction int `json:"raw_deduction"`
	// Assessed is how many checks actually ran (skipped ones excluded).
	Assessed int `json:"assessed"`
	Skipped  int `json:"skipped"`
	// Blocked and Moot split Skipped by cause. Only Blocked is fixable by
	// granting a permission; conflating them misdirects the reader.
	Blocked int `json:"blocked"`
	Moot    int `json:"moot"`
}
