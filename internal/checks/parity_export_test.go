package checks

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/drillproof/audit/internal/model"
)

// TestEmitCheckFixtures writes findings-level golden fixtures so the
// TypeScript port in the control plane can be proven identical to this one.
//
// `score/golden_test.go` proves the two implementations agree on a *score*.
// This proves the stronger claim: they agree on every individual *finding*
// that score is computed from. If the two ever disagreed about a customer's
// findings, both products would stop being believable — so parity here is
// enforced by replaying this fixture in TypeScript, not hoped for.
//
// The output shape is deliberately the TypeScript wire format (camelCase,
// `externalId` rather than `arn`, Tristate as its string form) rather than
// this package's own Go structs, so the replay test can pass a case straight
// into `runChecks` with no translation layer to keep in sync on its own.
//
// Regenerate after any change to a check's branches:
//
//	EMIT_GOLDEN=1 GOLDEN_OUT=../../../app/packages/shared/src/__fixtures__/checks-golden.json \
//	  go test -run TestEmitCheckFixtures ./internal/checks/
//
// Skipped by default so it never runs in normal CI.
func TestEmitCheckFixtures(t *testing.T) {
	if os.Getenv("EMIT_GOLDEN") == "" {
		t.Skip("set EMIT_GOLDEN=1")
	}

	// Fixed clock. Every freshness verdict is computed relative to it, so the
	// TypeScript replay must reuse this exact instant rather than time.Now().
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	cfg := Config{FreshWarnAfter: 24 * time.Hour, FreshFailAfter: 7 * 24 * time.Hour, Now: now}

	bucketRes := model.Resource{Display: "customer-uploads (S3)", Name: "customer-uploads", Type: model.TypeBucket, Region: "us-east-1"}
	tableRes := model.Resource{Display: "sessions (DynamoDB)", Name: "sessions", Type: model.TypeTable, Region: "us-east-1"}
	fsRes := model.Resource{
		Display: "shared-data (EFS)", Name: "shared-data",
		Type: model.TypeFileSystem, Region: "us-east-1",
		Attrs: map[string]string{"storage_class": "regional"},
	}
	oneZoneRes := model.Resource{
		Display: "cheap-data (EFS)", Name: "cheap-data",
		Type: model.TypeFileSystem, Region: "us-east-1",
		Attrs: map[string]string{"storage_class": "one-zone", "availability_zone": "us-east-1a"},
	}
	efsState := func(automatic model.Tristate, recoveryPoints int, repl model.EFSReplicationState) *model.BackupState {
		s := model.NewBackupState()
		s.EFS = &model.EFSProtection{AutomaticBackups: automatic, OneZone: model.No, Replication: repl}
		s.RecoveryPoints = recoveryPoints
		return s
	}
	noRepl := model.EFSReplicationState{Configured: model.No}
	healthyRepl := model.EFSReplicationState{
		Configured: model.Yes, Healthy: model.Yes, CrossRegion: model.Yes,
		DestRegions: []string{"us-west-2"},
	}

	// healthyReplication is the baseline used by the coverage-tier cases,
	// which are about the tier alone — replication branches get their own
	// dedicated cases below so the two aren't entangled.
	healthyReplication := model.ReplicationState{
		Configured:  model.Yes,
		EnabledRule: model.Yes,
		CrossRegion: model.Yes,
		DestRegions: []string{"us-west-2"},
	}

	bucketState := func(p model.S3Protection) *model.BackupState {
		s := model.NewBackupState()
		s.S3 = &p
		return s
	}
	tableState := func(pitr model.Tristate, recoveryPoints int) *model.BackupState {
		s := model.NewBackupState()
		s.Dynamo = &model.DynamoProtection{PITR: pitr}
		s.RecoveryPoints = recoveryPoints
		return s
	}

	type fixtureCase struct {
		name     string
		resource model.Resource
		state    *model.BackupState
	}

	cases := []fixtureCase{
		// The six coverage tiers. "Strongest with MFA Delete off" is the
		// false-positive guard: compliance-mode Object Lock is strictly
		// stronger than MFA Delete, so it must win regardless of MFA Delete's
		// state. "Partial, MFA Delete unknown" pins that an unreadable MFA
		// Delete state is reported as unknown, never coerced to "no".
		{"s3-tier-strongest-compliance-mfa-off", bucketRes, bucketState(model.S3Protection{
			ObjectLockMode: "COMPLIANCE", Versioning: model.No, MFADelete: model.No, Replication: healthyReplication,
		})},
		{"s3-tier-strong", bucketRes, bucketState(model.S3Protection{
			Versioning: model.Yes, MFADelete: model.Yes, Replication: healthyReplication,
		})},
		{"s3-tier-partial-mfa-off", bucketRes, bucketState(model.S3Protection{
			Versioning: model.Yes, MFADelete: model.No, Replication: healthyReplication,
		})},
		{"s3-tier-partial-mfa-delete-absent", bucketRes, bucketState(model.S3Protection{
			Versioning: model.Yes, MFADelete: model.Unknown, Replication: healthyReplication,
		})},
		{"s3-tier-weak-governance-only", bucketRes, bucketState(model.S3Protection{
			ObjectLockMode: "GOVERNANCE", Versioning: model.No, MFADelete: model.Unknown, Replication: healthyReplication,
		})},
		{"s3-tier-unprotected", bucketRes, bucketState(model.S3Protection{
			Versioning: model.No, MFADelete: model.Unknown, Replication: healthyReplication,
		})},

		// Replication branches, isolated from the tier by holding it at
		// "strong" throughout.
		{"s3-replication-not-configured", bucketRes, bucketState(model.S3Protection{
			Versioning: model.Yes, MFADelete: model.Yes,
			Replication: model.ReplicationState{Configured: model.No},
		})},
		{"s3-replication-configured-but-disabled", bucketRes, bucketState(model.S3Protection{
			Versioning: model.Yes, MFADelete: model.Yes,
			Replication: model.ReplicationState{Configured: model.Yes, EnabledRule: model.No},
		})},
		{"s3-replication-same-region", bucketRes, bucketState(model.S3Protection{
			Versioning: model.Yes, MFADelete: model.Yes,
			Replication: model.ReplicationState{Configured: model.Yes, EnabledRule: model.Yes, CrossRegion: model.No, DestRegions: []string{"us-east-1"}},
		})},
		{"s3-replication-unresolvable-destination", bucketRes, bucketState(model.S3Protection{
			Versioning: model.Yes, MFADelete: model.Yes,
			Replication: model.ReplicationState{Configured: model.Yes, EnabledRule: model.Yes, CrossRegion: model.Unknown},
		})},

		// Every new S3 permission denied is skipped with the IAM action
		// named, never reported as a fail. Coverage/immutability/redundancy
		// all check Unassessed before dispatching to the bucket-specific
		// logic, so one state exercises all three.
		{"s3-permission-denied", bucketRes, func() *model.BackupState {
			s := bucketState(model.S3Protection{Versioning: model.Yes, MFADelete: model.Yes, Replication: healthyReplication})
			s.MarkUnassessed(model.CheckCoverage, "s3:GetBucketVersioning denied")
			s.MarkUnassessed(model.CheckImmutability, "s3:GetBucketObjectLockConfiguration denied")
			s.MarkUnassessed(model.CheckRedundancy, "s3:GetBucketReplication denied")
			return s
		}()},

		// DynamoDB: PITR-only, backup-plan-only, both, neither.
		{"dynamo-pitr-only", tableRes, tableState(model.Yes, 0)},
		{"dynamo-backup-plan-only", tableRes, func() *model.BackupState {
			s := tableState(model.No, 3)
			backedUp := now.Add(-2 * time.Hour)
			s.LatestBackupAt = &backedUp
			s.Immutable = model.Yes
			s.CrossRegion = model.Yes
			return s
		}()},
		{"dynamo-both-pitr-and-plan", tableRes, func() *model.BackupState {
			s := tableState(model.Yes, 2)
			backedUp := now.Add(-2 * time.Hour)
			s.LatestBackupAt = &backedUp
			s.Immutable = model.Yes
			s.CrossRegion = model.Yes
			return s
		}()},
		{"dynamo-neither", tableRes, tableState(model.No, 0)},

		// PITR is single-region by construction, so a PITR-only table still
		// fails redundancy rather than reporting "not applicable" — that
		// would hide a real gap. The global-table-replica wording variant
		// matters because a customer would otherwise assume the replica is
		// their redundancy, and a delete propagates to it.
		{"dynamo-pitr-only-redundancy-fail", tableRes, tableState(model.Yes, 0)},
		{"dynamo-pitr-only-redundancy-fail-global-table-replica", tableRes, func() *model.BackupState {
			s := tableState(model.Yes, 0)
			s.Dynamo.GlobalTableReplicas = []string{"eu-west-1"}
			return s
		}()},

		// The new DynamoDB permission denied is skipped with the IAM action
		// named, never a fail.
		{"dynamo-permission-denied", tableRes, func() *model.BackupState {
			s := tableState(model.Unknown, 0)
			s.MarkUnassessed(model.CheckCoverage, "dynamodb:DescribeContinuousBackups denied")
			return s
		}()},

		// Coverage accepts automatic backups OR a plan. The automatic-only
		// case is the false-positive guard.
		{"efs-automatic-backups-only", fsRes, efsState(model.Yes, 0, noRepl)},
		{"efs-backup-plan-only", fsRes, func() *model.BackupState {
			s := efsState(model.No, 3, noRepl)
			backedUp := now.Add(-2 * time.Hour)
			s.LatestBackupAt = &backedUp
			s.Immutable = model.Yes
			s.CrossRegion = model.Yes
			return s
		}()},
		{"efs-both-automatic-and-plan", fsRes, func() *model.BackupState {
			s := efsState(model.Yes, 2, noRepl)
			backedUp := now.Add(-30 * time.Hour)
			s.LatestBackupAt = &backedUp
			s.Immutable = model.No
			s.CrossRegion = model.No
			return s
		}()},
		{"efs-neither", fsRes, efsState(model.No, 0, noRepl)},

		// Redundancy: replication is the second valid path, and its
		// unhealthy/same-region/unreadable branches must all be distinct.
		{"efs-replication-cross-region-healthy", fsRes, efsState(model.Yes, 0, healthyRepl)},
		{"efs-replication-same-region", fsRes, efsState(model.Yes, 0, model.EFSReplicationState{
			Configured: model.Yes, Healthy: model.Yes, CrossRegion: model.No,
			DestRegions: []string{"us-east-1"},
		})},
		{"efs-replication-unhealthy", fsRes, efsState(model.Yes, 0, model.EFSReplicationState{
			Configured: model.Yes, Healthy: model.No, CrossRegion: model.Yes,
			DestRegions: []string{"us-west-2"},
		})},
		{"efs-replication-health-unreadable", fsRes, efsState(model.Yes, 0, model.EFSReplicationState{
			Configured: model.Yes, Healthy: model.Unknown, CrossRegion: model.Yes,
		})},

		// One Zone: context when backed up, stated plainly when not.
		{"efs-one-zone-with-backups", oneZoneRes, func() *model.BackupState {
			s := efsState(model.Yes, 0, healthyRepl)
			s.EFS.OneZone = model.Yes
			s.EFS.AvailabilityZone = "us-east-1a"
			return s
		}()},
		{"efs-one-zone-no-backup", oneZoneRes, func() *model.BackupState {
			s := efsState(model.No, 0, noRepl)
			s.EFS.OneZone = model.Yes
			s.EFS.AvailabilityZone = "us-east-1a"
			return s
		}()},

		// Each new permission denied is skipped with the action named.
		{"efs-permission-denied", fsRes, func() *model.BackupState {
			s := efsState(model.Unknown, 0, model.EFSReplicationState{Configured: model.Unknown, Healthy: model.Unknown, CrossRegion: model.Unknown})
			s.MarkUnassessed(model.CheckCoverage, "elasticfilesystem:DescribeBackupPolicy denied")
			s.MarkUnassessed(model.CheckRedundancy, "elasticfilesystem:DescribeReplicationConfigurations denied")
			return s
		}()},
	}

	type outCase struct {
		Name     string        `json:"name"`
		Resource wireResource  `json:"resource"`
		State    wireState     `json:"state"`
		Findings []wireFinding `json:"findings"`
	}

	out := make([]outCase, 0, len(cases))
	for _, c := range cases {
		findings := Run(c.resource, c.state, cfg)
		wireFindings := make([]wireFinding, len(findings))
		for i, f := range findings {
			wireFindings[i] = toWireFinding(f)
		}
		out = append(out, outCase{
			Name:     c.name,
			Resource: toWireResource(c.resource),
			State:    toWireState(c.state),
			Findings: wireFindings,
		})
	}

	fixture := struct {
		Now   string    `json:"now"`
		Cases []outCase `json:"cases"`
	}{
		Now:   now.Format(time.RFC3339),
		Cases: out,
	}

	b, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("GOLDEN_OUT"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d cases", len(out))
}

// The wire* types below mirror packages/shared/src/model.ts field-for-field.
// model.Resource/Finding/BackupState use different JSON tags (or none at all)
// because they serve the CLI's own JSON/SARIF output, which is a separate
// contract from the TypeScript port's wire shape — so the fixture is built
// through an explicit translation rather than by tagging production structs
// for two audiences at once.

type wireResource struct {
	Display    string             `json:"display"`
	Name       string             `json:"name"`
	ExternalID string             `json:"externalId,omitempty"`
	Type       model.ResourceType `json:"type"`
	Region     string             `json:"region"`
	Production bool               `json:"production"`
	Attrs      map[string]string  `json:"attrs,omitempty"`
}

type wireReplication struct {
	Configured  string   `json:"configured"`
	EnabledRule string   `json:"enabledRule"`
	CrossRegion string   `json:"crossRegion"`
	DestRegions []string `json:"destRegions,omitempty"`
}

type wireS3 struct {
	Tier           model.ProtectionTier `json:"tier"`
	ObjectLockMode string               `json:"objectLockMode"`
	Versioning     string               `json:"versioning"`
	MFADelete      string               `json:"mfaDelete"`
	Replication    wireReplication      `json:"replication"`
}

type wireDynamo struct {
	PITR                string   `json:"pitr"`
	GlobalTableReplicas []string `json:"globalTableReplicas,omitempty"`
}

type wireEFSReplication struct {
	Configured  string   `json:"configured"`
	Healthy     string   `json:"healthy"`
	CrossRegion string   `json:"crossRegion"`
	DestRegions []string `json:"destRegions,omitempty"`
}

type wireEFS struct {
	AutomaticBackups string             `json:"automaticBackups"`
	OneZone          string             `json:"oneZone"`
	AvailabilityZone string             `json:"availabilityZone,omitempty"`
	Replication      wireEFSReplication `json:"replication"`
}

type wireState struct {
	RecoveryPoints           int               `json:"recoveryPoints"`
	LatestBackupAt           *string           `json:"latestBackupAt,omitempty"`
	Immutable                string            `json:"immutable"`
	CrossRegion              string            `json:"crossRegion"`
	LastRestoreAt            *string           `json:"lastRestoreAt,omitempty"`
	RestoreTestingConfigured bool              `json:"restoreTestingConfigured"`
	Unassessed               map[string]string `json:"unassessed,omitempty"`
	Notes                    []string          `json:"notes,omitempty"`
	S3                       *wireS3           `json:"s3,omitempty"`
	Dynamo                   *wireDynamo       `json:"dynamo,omitempty"`
	EFS                      *wireEFS          `json:"efs,omitempty"`
}

type wireFinding struct {
	Resource    wireResource  `json:"resource"`
	Check       model.CheckID `json:"check"`
	Status      model.Status  `json:"status"`
	Summary     string        `json:"summary"`
	Remediation string        `json:"remediation,omitempty"`
	SkipReason  string        `json:"skipReason,omitempty"`
	// A pointer, and omitted for a non-skipped finding: the TypeScript port
	// only ever sets this field from blocked()/moot() (true or false), and
	// every other builder leaves the key off the object entirely — which a
	// plain bool with omitempty cannot represent, since it can't distinguish
	// "moot() wrote false" from "never set". A strict deep-equal fails on
	// either mismatch.
	SkipIsAccessGap *bool `json:"skipIsAccessGap,omitempty"`
}

func toWireResource(r model.Resource) wireResource {
	return wireResource{
		Display:    r.Display,
		Name:       r.Name,
		ExternalID: r.ARN,
		Type:       r.Type,
		Region:     r.Region,
		Production: r.Production,
		Attrs:      r.Attrs,
	}
}

func toWireFinding(f model.Finding) wireFinding {
	wf := wireFinding{
		Resource:    toWireResource(f.Resource),
		Check:       f.Check,
		Status:      f.Status,
		Summary:     f.Summary,
		Remediation: f.Remediation,
		SkipReason:  f.SkipReason,
	}
	if f.Status == model.StatusSkipped {
		gap := f.SkipIsAccessGap
		wf.SkipIsAccessGap = &gap
	}
	return wf
}

func rfc3339(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format(time.RFC3339)
	return &s
}

func toWireState(s *model.BackupState) wireState {
	ws := wireState{
		RecoveryPoints:           s.RecoveryPoints,
		LatestBackupAt:           rfc3339(s.LatestBackupAt),
		Immutable:                s.Immutable.String(),
		CrossRegion:              s.CrossRegion.String(),
		LastRestoreAt:            rfc3339(s.LastRestoreAt),
		RestoreTestingConfigured: s.RestoreTestingConfigured,
		Unassessed:               map[string]string{},
		Notes:                    s.Notes,
	}
	for k, v := range s.Unassessed {
		ws.Unassessed[string(k)] = v
	}
	if len(ws.Unassessed) == 0 {
		ws.Unassessed = nil
	}
	if s.S3 != nil {
		ws.S3 = &wireS3{
			Tier:           s.S3.Tier,
			ObjectLockMode: s.S3.ObjectLockMode,
			Versioning:     s.S3.Versioning.String(),
			MFADelete:      s.S3.MFADelete.String(),
			Replication: wireReplication{
				Configured:  s.S3.Replication.Configured.String(),
				EnabledRule: s.S3.Replication.EnabledRule.String(),
				CrossRegion: s.S3.Replication.CrossRegion.String(),
				DestRegions: s.S3.Replication.DestRegions,
			},
		}
	}
	if s.Dynamo != nil {
		ws.Dynamo = &wireDynamo{
			PITR:                s.Dynamo.PITR.String(),
			GlobalTableReplicas: s.Dynamo.GlobalTableReplicas,
		}
	}
	if s.EFS != nil {
		ws.EFS = &wireEFS{
			AutomaticBackups: s.EFS.AutomaticBackups.String(),
			OneZone:          s.EFS.OneZone.String(),
			AvailabilityZone: s.EFS.AvailabilityZone,
			Replication: wireEFSReplication{
				Configured:  s.EFS.Replication.Configured.String(),
				Healthy:     s.EFS.Replication.Healthy.String(),
				CrossRegion: s.EFS.Replication.CrossRegion.String(),
				DestRegions: s.EFS.Replication.DestRegions,
			},
		}
	}
	return ws
}
