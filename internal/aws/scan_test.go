package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drillproof/audit/internal/checks"
	"github.com/drillproof/audit/internal/k8s"
	"github.com/drillproof/audit/internal/model"
)

var now = time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

func scanOpts() ScanOptions {
	cfg := checks.DefaultConfig()
	cfg.Now = now
	return ScanOptions{Checks: cfg, Version: "test", Concurrency: 2}
}

// estate builds a two-region account resembling the spec's sample output:
// a volume with a locked cross-region backup, an unbacked production database,
// and an EKS cluster with no cluster-state backup at all.
func estate() *fakeProvider {
	volumeARN := "arn:aws:ec2:ap-southeast-1:123456789012:volume/vol-orders"

	primary := Clients{
		Region: "ap-southeast-1",
		EC2: &fakeEC2{
			regions: []string{"ap-southeast-1", "us-east-1"},
			volumes: []ec2types.Volume{{
				VolumeId: awssdk.String("vol-orders"),
				Size:     awssdk.Int32(120),
				State:    ec2types.VolumeStateInUse,
				Tags: []ec2types.Tag{
					{Key: awssdk.String("Name"), Value: awssdk.String("orders-pv")},
				},
			}},
		},
		RDS: &fakeRDS{
			instances: []rdstypes.DBInstance{{
				DBInstanceIdentifier:  awssdk.String("payments-db"),
				DBInstanceArn:         awssdk.String("arn:aws:rds:ap-southeast-1:123456789012:db:payments-db"),
				Engine:                awssdk.String("postgres"),
				BackupRetentionPeriod: awssdk.Int32(0), // automated backups off
			}},
		},
		Backup: &fakeBackup{
			vaults: []backuptypes.BackupVaultListMember{{
				BackupVaultName: awssdk.String("primary-vault"),
				Locked:          awssdk.Bool(true),
			}},
			locked: map[string]bool{"primary-vault": true},
			pointsByVault: map[string][]backuptypes.RecoveryPointByBackupVault{
				"primary-vault": {
					completedPoint(volumeARN, now.Add(-3*time.Hour), nil),
				},
			},
		},
		EKS:      &fakeEKS{clusters: []string{"prod-cluster"}},
		S3:       &fakeS3{},
		DynamoDB: &fakeDynamoDB{},
	}

	// The DR region holds a copy of the volume's recovery point, which is what
	// makes the redundancy check answer "yes".
	secondary := Clients{
		Region: "us-east-1",
		EC2:    &fakeEC2{},
		RDS:    &fakeRDS{},
		Backup: &fakeBackup{
			vaults: []backuptypes.BackupVaultListMember{{
				BackupVaultName: awssdk.String("dr-vault"),
				Locked:          awssdk.Bool(true),
			}},
			locked: map[string]bool{"dr-vault": true},
			pointsByVault: map[string][]backuptypes.RecoveryPointByBackupVault{
				"dr-vault": {
					completedPoint(volumeARN, now.Add(-4*time.Hour), nil),
				},
			},
		},
		EKS:      &fakeEKS{},
		S3:       &fakeS3{},
		DynamoDB: &fakeDynamoDB{},
	}

	return &fakeProvider{
		base: "ap-southeast-1",
		sts:  &fakeSTS{account: "123456789012"},
		perRegion: map[string]Clients{
			"ap-southeast-1": primary,
			"us-east-1":      secondary,
		},
	}
}

func rowFor(t *testing.T, result *model.Result, display string) model.Row {
	t.Helper()
	for _, r := range result.Rows {
		if r.Resource.Display == display {
			return r
		}
	}
	t.Fatalf("no row for %q; rows present: %v", display, displays(result))
	return model.Row{}
}

func displays(result *model.Result) []string {
	var out []string
	for _, r := range result.Rows {
		out = append(out, r.Resource.Display)
	}
	return out
}

func TestScanInventoriesAllThreeResourceTypes(t *testing.T) {
	result, err := Scan(context.Background(), estate(), scanOpts())
	require.NoError(t, err)

	assert.Equal(t, "123456789012", result.AccountID)
	assert.Len(t, result.Rows, 3)

	types := map[model.ResourceType]bool{}
	for _, r := range result.Rows {
		types[r.Resource.Type] = true
	}
	assert.True(t, types[model.TypeVolume], "EBS volume missing")
	assert.True(t, types[model.TypeDatabase], "RDS instance missing")
	assert.True(t, types[model.TypeK8sState], "EKS cluster state missing")
}

func TestBackedUpVolumePassesCoverageFreshnessImmutabilityRedundancy(t *testing.T) {
	result, err := Scan(context.Background(), estate(), scanOpts())
	require.NoError(t, err)

	row := rowFor(t, result, "orders-pv (EBS)")
	assert.Equal(t, model.StatusOK, row.Statuses[model.CheckCoverage])
	assert.Equal(t, model.StatusOK, row.Statuses[model.CheckFreshness])
	assert.Equal(t, model.StatusOK, row.Statuses[model.CheckImmutability],
		"recovery points in a locked vault must read as immutable")
	assert.Equal(t, model.StatusOK, row.Statuses[model.CheckRedundancy],
		"a copy in us-east-1 must satisfy cross-region redundancy")

	// It has backups but has never been restored — the wedge.
	assert.Equal(t, model.StatusFail, row.Statuses[model.CheckRestoreTested])
}

func TestUnbackedProductionDatabaseFailsCoverage(t *testing.T) {
	result, err := Scan(context.Background(), estate(), scanOpts())
	require.NoError(t, err)

	row := rowFor(t, result, "payments-db (RDS)")
	assert.Equal(t, model.StatusFail, row.Statuses[model.CheckCoverage])
	assert.True(t, row.Resource.Production, "payments-db should be detected as production")
	assert.Contains(t, row.State.Notes[0], "automated backups are disabled")

	// Freshness and redundancy must not double-penalise the same root cause.
	assert.Equal(t, model.StatusSkipped, row.Statuses[model.CheckFreshness])
	assert.Equal(t, model.StatusSkipped, row.Statuses[model.CheckRedundancy])
}

// Without --kubeconfig we have not looked inside the cluster, and AWS Backup
// genuinely cannot see Velero backups. Reporting "no backup" here would be a
// false accusation, and §5 makes score credibility non-negotiable — so this must
// read as "not assessed" with a pointer at the fix.
//
// This deliberately diverges from the sample table in spec §7, which shows etcd
// as an outright coverage failure.
func TestClusterStateIsNotAssessedWithoutKubeconfig(t *testing.T) {
	result, err := Scan(context.Background(), estate(), scanOpts())
	require.NoError(t, err)

	row := rowFor(t, result, "etcd (prod-cluster)")
	assert.Equal(t, model.TypeK8sState, row.Resource.Type)
	assert.Equal(t, model.StatusSkipped, row.Statuses[model.CheckCoverage],
		"cluster state must not be called unbacked when we never looked inside the cluster")
	assert.Contains(t, row.State.Unassessed[model.CheckCoverage], "--kubeconfig")
}

func TestClusterWithoutVeleroFailsCoverage(t *testing.T) {
	opts := scanOpts()
	opts.Cluster = &k8s.State{ClusterName: "prod-cluster", VeleroInstalled: false}

	result, err := Scan(context.Background(), estate(), opts)
	require.NoError(t, err)

	row := rowFor(t, result, "etcd (prod-cluster)")
	assert.Equal(t, model.StatusFail, row.Statuses[model.CheckCoverage],
		"we looked and found nothing backing up cluster state — that is a real failure")
	assert.Contains(t, row.State.Notes, "Velero is not installed in this cluster")
}

func TestVeleroBackupsCountAsClusterCoverage(t *testing.T) {
	backupAt := now.Add(-5 * time.Hour)
	opts := scanOpts()
	opts.Cluster = &k8s.State{
		ClusterName:      "prod-cluster",
		VeleroInstalled:  true,
		CompletedBackups: 3,
		Schedules:        1,
		LatestBackupAt:   &backupAt,
	}

	result, err := Scan(context.Background(), estate(), opts)
	require.NoError(t, err)

	row := rowFor(t, result, "etcd (prod-cluster)")
	assert.Equal(t, model.StatusOK, row.Statuses[model.CheckCoverage])
	assert.Equal(t, model.StatusOK, row.Statuses[model.CheckFreshness])
	assert.Equal(t, 3, row.State.RecoveryPoints)
}

func TestVeleroRestoreMarksClusterStateVerified(t *testing.T) {
	backupAt := now.Add(-5 * time.Hour)
	restoredAt := now.Add(-30 * time.Hour)

	opts := scanOpts()
	opts.Cluster = &k8s.State{
		ClusterName:       "prod-cluster",
		VeleroInstalled:   true,
		CompletedBackups:  2,
		Schedules:         1,
		LatestBackupAt:    &backupAt,
		CompletedRestores: 1,
		LatestRestoreAt:   &restoredAt,
	}

	result, err := Scan(context.Background(), estate(), opts)
	require.NoError(t, err)

	row := rowFor(t, result, "etcd (prod-cluster)")
	assert.Equal(t, model.StatusOK, row.Statuses[model.CheckRestoreTested],
		"a completed Velero restore is exactly the proof this tool looks for")
}

func TestMismatchedKubeconfigIsNotCreditedToTheWrongCluster(t *testing.T) {
	opts := scanOpts()
	opts.Cluster = &k8s.State{
		ClusterName:      "some-other-cluster",
		VeleroInstalled:  true,
		CompletedBackups: 9,
	}

	result, err := Scan(context.Background(), estate(), opts)
	require.NoError(t, err)

	row := rowFor(t, result, "etcd (prod-cluster)")
	assert.Equal(t, model.StatusSkipped, row.Statuses[model.CheckCoverage])
	assert.Equal(t, 0, row.State.RecoveryPoints,
		"another cluster's Velero backups must never be credited to this one")
}

func TestUnreachableClusterDegradesToNotAssessed(t *testing.T) {
	opts := scanOpts()
	opts.Cluster = &k8s.State{
		ClusterName: "prod-cluster",
		Unassessed:  "cluster unreachable: dial tcp timeout",
	}

	result, err := Scan(context.Background(), estate(), opts)
	require.NoError(t, err, "an unreachable cluster must not fail the AWS scan")

	row := rowFor(t, result, "etcd (prod-cluster)")
	assert.Equal(t, model.StatusSkipped, row.Statuses[model.CheckCoverage])
}

func TestScoreIsPenalisedAndExplained(t *testing.T) {
	result, err := Scan(context.Background(), estate(), scanOpts())
	require.NoError(t, err)

	assert.Less(t, result.Score.Value, 100)
	assert.Greater(t, result.Score.CriticalGaps, 0)
	require.NotEmpty(t, result.Score.Penalties)

	// Every penalty must name a resource and a reason — an unexplained
	// deduction would undermine the whole point of the score.
	for _, p := range result.Score.Penalties {
		assert.NotEmpty(t, p.Resource)
		assert.NotEmpty(t, p.Reason)
		assert.Greater(t, p.Points, 0)
	}
}

func TestRestoreTestingPlanDowngradesFailToWarn(t *testing.T) {
	p := estate()
	primary := p.perRegion["ap-southeast-1"]
	primary.Backup.(*fakeBackup).restorePlans = 1
	p.perRegion["ap-southeast-1"] = primary

	result, err := Scan(context.Background(), p, scanOpts())
	require.NoError(t, err)

	row := rowFor(t, result, "orders-pv (EBS)")
	assert.Equal(t, model.StatusWarn, row.Statuses[model.CheckRestoreTested],
		"a configured restore-testing plan should soften the finding, not clear it")
}

func TestActualRestoreMarksVerified(t *testing.T) {
	p := estate()
	volumeARN := "arn:aws:ec2:ap-southeast-1:123456789012:volume/vol-orders"
	restored := now.Add(-36 * time.Hour)

	primary := p.perRegion["ap-southeast-1"]
	primary.Backup.(*fakeBackup).pointsByVault["primary-vault"] = []backuptypes.RecoveryPointByBackupVault{
		completedPoint(volumeARN, now.Add(-3*time.Hour), ptrTime(restored)),
	}
	p.perRegion["ap-southeast-1"] = primary

	result, err := Scan(context.Background(), p, scanOpts())
	require.NoError(t, err)

	row := rowFor(t, result, "orders-pv (EBS)")
	assert.Equal(t, model.StatusOK, row.Statuses[model.CheckRestoreTested])
	require.NotNil(t, row.State.LastRestoreAt)
}

func TestDeniedVaultListingDegradesGracefully(t *testing.T) {
	p := estate()
	for region, c := range p.perRegion {
		c.Backup.(*fakeBackup).vaultsErr = denied()
		p.perRegion[region] = c
	}

	result, err := Scan(context.Background(), p, scanOpts())
	require.NoError(t, err, "a denied permission must never fail the whole scan")

	assert.NotEmpty(t, result.Warnings, "the denial must be surfaced, not swallowed")

	row := rowFor(t, result, "orders-pv (EBS)")
	assert.Equal(t, model.StatusSkipped, row.Statuses[model.CheckImmutability],
		"immutability must be 'not assessed', never assumed safe")
}

func TestDeniedInventoryStillReturnsOtherResources(t *testing.T) {
	p := estate()
	primary := p.perRegion["ap-southeast-1"]
	primary.EC2.(*fakeEC2).volumesErr = denied()
	p.perRegion["ap-southeast-1"] = primary

	result, err := Scan(context.Background(), p, scanOpts())
	require.NoError(t, err)

	assert.NotContains(t, displays(result), "orders-pv (EBS)")
	assert.Contains(t, displays(result), "payments-db (RDS)")

	found := false
	for _, w := range result.Warnings {
		if assert.ObjectsAreEqual(true, len(w) > 0) && contains(w, "DescribeVolumes") {
			found = true
		}
	}
	assert.True(t, found, "expected a warning naming the denied call, got %v", result.Warnings)
}

func TestNativeSnapshotFallbackCountsAsCoverage(t *testing.T) {
	p := estate()
	primary := p.perRegion["ap-southeast-1"]
	// No AWS Backup recovery points at all...
	primary.Backup.(*fakeBackup).pointsByVault = map[string][]backuptypes.RecoveryPointByBackupVault{}
	// ...but a plain EBS snapshot exists.
	primary.EC2.(*fakeEC2).snapshots = []ec2types.Snapshot{{
		SnapshotId: awssdk.String("snap-1"),
		State:      ec2types.SnapshotStateCompleted,
		StartTime:  awssdk.Time(now.Add(-5 * time.Hour)),
	}}
	p.perRegion["ap-southeast-1"] = primary

	// The DR vault would otherwise still supply a recovery point.
	secondary := p.perRegion["us-east-1"]
	secondary.Backup.(*fakeBackup).pointsByVault = map[string][]backuptypes.RecoveryPointByBackupVault{}
	p.perRegion["us-east-1"] = secondary

	result, err := Scan(context.Background(), p, scanOpts())
	require.NoError(t, err)

	row := rowFor(t, result, "orders-pv (EBS)")
	assert.Equal(t, model.StatusOK, row.Statuses[model.CheckCoverage],
		"a team using plain snapshots must not be reported as having no backups")
	assert.Equal(t, model.StatusFail, row.Statuses[model.CheckImmutability],
		"native snapshots are not WORM, and that is a known negative")
	assert.Equal(t, model.StatusFail, row.Statuses[model.CheckRedundancy],
		"a single-region snapshot is not redundant")
}

func TestExplicitRegionsSkipDiscovery(t *testing.T) {
	opts := scanOpts()
	opts.Regions = []string{"ap-southeast-1"}

	result, err := Scan(context.Background(), estate(), opts)
	require.NoError(t, err)

	assert.Equal(t, []string{"ap-southeast-1"}, result.Regions)
	// With the DR region unscanned, the volume is no longer provably redundant.
	row := rowFor(t, result, "orders-pv (EBS)")
	assert.Equal(t, model.StatusFail, row.Statuses[model.CheckRedundancy])
}

func TestScanIsDeterministic(t *testing.T) {
	first, err := Scan(context.Background(), estate(), scanOpts())
	require.NoError(t, err)
	second, err := Scan(context.Background(), estate(), scanOpts())
	require.NoError(t, err)

	assert.Equal(t, first.Score.Value, second.Score.Value)
	assert.Equal(t, displays(first), displays(second),
		"row ordering must be stable across runs despite concurrent region scanning")
}

func TestFatalIdentityFailureIsReported(t *testing.T) {
	p := estate()
	p.sts = &fakeSTS{err: denied()}
	_, err := Scan(context.Background(), p, scanOpts())
	require.Error(t, err, "without an identity we cannot build ARNs, so this must fail loudly")
}

func TestTopFindingsRanksFailuresFirst(t *testing.T) {
	result, err := Scan(context.Background(), estate(), scanOpts())
	require.NoError(t, err)

	top := TopFindings(result, 5)
	require.NotEmpty(t, top)
	assert.Equal(t, model.StatusFail, top[0].Status)
	assert.Equal(t, model.CheckCoverage, top[0].Check,
		"coverage failures are the most important thing to show first")
}

func TestCountUntested(t *testing.T) {
	result, err := Scan(context.Background(), estate(), scanOpts())
	require.NoError(t, err)
	assert.Positive(t, CountUntested(result))
}

func TestScanIncludesBucketsAndTables(t *testing.T) {
	p := &fakeProvider{
		base: "us-east-1",
		sts:  &fakeSTS{account: "123456789012"},
		perRegion: map[string]Clients{
			"us-east-1": {
				Region: "us-east-1",
				EC2:    &fakeEC2{regions: []string{"us-east-1"}},
				RDS:    &fakeRDS{},
				Backup: &fakeBackup{},
				EKS:    &fakeEKS{},
				S3: &fakeS3{
					buckets:   []string{"uploads"},
					locations: map[string]string{"uploads": ""},
				},
				DynamoDB: &fakeDynamoDB{
					tables: []string{"sessions"},
					described: map[string]dynamodbtypes.TableDescription{
						"sessions": {TableArn: awssdk.String("arn:aws:dynamodb:us-east-1:1:table/sessions")},
					},
				},
			},
		},
	}

	result, err := Scan(context.Background(), p, ScanOptions{
		Regions: []string{"us-east-1"},
		Checks:  checks.DefaultConfig(),
	})
	require.NoError(t, err)

	types := map[model.ResourceType]bool{}
	for _, row := range result.Rows {
		types[row.Resource.Type] = true
	}
	assert.True(t, types[model.TypeBucket], "buckets must appear in the inventory")
	assert.True(t, types[model.TypeTable], "tables must appear in the inventory")
}

func TestScanPreservesBucketProtectionState(t *testing.T) {
	// The regression this guards: GatherBackupState builds a fresh state and
	// would discard the S3 posture discovery already collected, leaving every
	// bucket reporting "bucket configuration not read".
	p := &fakeProvider{
		base: "us-east-1",
		sts:  &fakeSTS{account: "123456789012"},
		perRegion: map[string]Clients{
			"us-east-1": {
				Region: "us-east-1",
				EC2:    &fakeEC2{regions: []string{"us-east-1"}},
				RDS:    &fakeRDS{}, Backup: &fakeBackup{}, EKS: &fakeEKS{},
				DynamoDB: &fakeDynamoDB{},
				S3: &fakeS3{
					buckets:   []string{"uploads"},
					locations: map[string]string{"uploads": ""},
					versioning: map[string]s3.GetBucketVersioningOutput{
						"uploads": {Status: s3types.BucketVersioningStatusEnabled, MFADelete: s3types.MFADeleteStatusEnabled},
					},
				},
			},
		},
	}

	result, err := Scan(context.Background(), p, ScanOptions{
		Regions: []string{"us-east-1"},
		Checks:  checks.DefaultConfig(),
	})
	require.NoError(t, err)

	for _, row := range result.Rows {
		if row.Resource.Type != model.TypeBucket {
			continue
		}
		require.NotNil(t, row.State.S3, "bucket posture must survive into the checks")
		assert.Equal(t, model.StatusOK, row.Statuses[model.CheckCoverage])
		return
	}
	t.Fatal("no bucket row found")
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
