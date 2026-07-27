package aws

import (
	"context"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// stubAPIErr is a smithy.APIError for exercising the error classifiers.
type stubAPIErr struct {
	code string
	msg  string
}

func (e *stubAPIErr) Error() string                 { return e.code + ": " + e.msg }
func (e *stubAPIErr) ErrorCode() string             { return e.code }
func (e *stubAPIErr) ErrorMessage() string          { return e.msg }
func (e *stubAPIErr) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

// Compile-time proof the stub really is an APIError — otherwise errors.As in
// IsAccessDenied silently never matches and the classifier tests pass
// vacuously.
var _ smithy.APIError = (*stubAPIErr)(nil)

func denied() error { return &stubAPIErr{code: "AccessDeniedException", msg: "not authorized"} }

// ---------------------------------------------------------------- fake STS

type fakeSTS struct {
	account string
	err     error
}

func (f *fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &sts.GetCallerIdentityOutput{
		Account: awssdk.String(f.account),
		Arn:     awssdk.String("arn:aws:iam::" + f.account + ":user/auditor"),
	}, nil
}

// ---------------------------------------------------------------- fake EC2

type fakeEC2 struct {
	regions     []string
	volumes     []ec2types.Volume
	snapshots   []ec2types.Snapshot
	regionsErr  error
	volumesErr  error
	snapshotErr error
}

func (f *fakeEC2) DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	if f.regionsErr != nil {
		return nil, f.regionsErr
	}
	out := &ec2.DescribeRegionsOutput{}
	for _, r := range f.regions {
		out.Regions = append(out.Regions, ec2types.Region{
			RegionName:  awssdk.String(r),
			OptInStatus: awssdk.String("opt-in-not-required"),
		})
	}
	return out, nil
}

func (f *fakeEC2) DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	if f.volumesErr != nil {
		return nil, f.volumesErr
	}
	return &ec2.DescribeVolumesOutput{Volumes: f.volumes}, nil
}

func (f *fakeEC2) DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	if f.snapshotErr != nil {
		return nil, f.snapshotErr
	}
	return &ec2.DescribeSnapshotsOutput{Snapshots: f.snapshots}, nil
}

// ---------------------------------------------------------------- fake RDS

type fakeRDS struct {
	instances    []rdstypes.DBInstance
	clusters     []rdstypes.DBCluster
	snapshots    []rdstypes.DBSnapshot
	instancesErr error
}

func (f *fakeRDS) DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if f.instancesErr != nil {
		return nil, f.instancesErr
	}
	return &rds.DescribeDBInstancesOutput{DBInstances: f.instances}, nil
}

func (f *fakeRDS) DescribeDBClusters(context.Context, *rds.DescribeDBClustersInput, ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error) {
	return &rds.DescribeDBClustersOutput{DBClusters: f.clusters}, nil
}

func (f *fakeRDS) DescribeDBSnapshots(context.Context, *rds.DescribeDBSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error) {
	return &rds.DescribeDBSnapshotsOutput{DBSnapshots: f.snapshots}, nil
}

func (f *fakeRDS) DescribeDBClusterSnapshots(context.Context, *rds.DescribeDBClusterSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotsOutput, error) {
	return &rds.DescribeDBClusterSnapshotsOutput{}, nil
}

// ------------------------------------------------------------- fake Backup

type fakeBackup struct {
	vaults        []backuptypes.BackupVaultListMember
	locked        map[string]bool
	pointsByVault map[string][]backuptypes.RecoveryPointByBackupVault
	restorePlans  int
	vaultsErr     error
	pointsErr     error
}

func (f *fakeBackup) ListBackupVaults(context.Context, *backup.ListBackupVaultsInput, ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error) {
	if f.vaultsErr != nil {
		return nil, f.vaultsErr
	}
	return &backup.ListBackupVaultsOutput{BackupVaultList: f.vaults}, nil
}

func (f *fakeBackup) DescribeBackupVault(_ context.Context, in *backup.DescribeBackupVaultInput, _ ...func(*backup.Options)) (*backup.DescribeBackupVaultOutput, error) {
	name := awssdk.ToString(in.BackupVaultName)
	locked, ok := f.locked[name]
	if !ok {
		return &backup.DescribeBackupVaultOutput{}, nil
	}
	return &backup.DescribeBackupVaultOutput{Locked: awssdk.Bool(locked)}, nil
}

func (f *fakeBackup) ListRecoveryPointsByBackupVault(_ context.Context, in *backup.ListRecoveryPointsByBackupVaultInput, _ ...func(*backup.Options)) (*backup.ListRecoveryPointsByBackupVaultOutput, error) {
	if f.pointsErr != nil {
		return nil, f.pointsErr
	}
	name := awssdk.ToString(in.BackupVaultName)
	wanted := awssdk.ToString(in.ByResourceArn)

	var matched []backuptypes.RecoveryPointByBackupVault
	for _, rp := range f.pointsByVault[name] {
		if wanted == "" || awssdk.ToString(rp.ResourceArn) == wanted {
			matched = append(matched, rp)
		}
	}
	return &backup.ListRecoveryPointsByBackupVaultOutput{RecoveryPoints: matched}, nil
}

func (f *fakeBackup) ListRecoveryPointsByResource(context.Context, *backup.ListRecoveryPointsByResourceInput, ...func(*backup.Options)) (*backup.ListRecoveryPointsByResourceOutput, error) {
	return &backup.ListRecoveryPointsByResourceOutput{}, nil
}

func (f *fakeBackup) ListRestoreTestingPlans(context.Context, *backup.ListRestoreTestingPlansInput, ...func(*backup.Options)) (*backup.ListRestoreTestingPlansOutput, error) {
	out := &backup.ListRestoreTestingPlansOutput{}
	for i := 0; i < f.restorePlans; i++ {
		out.RestoreTestingPlans = append(out.RestoreTestingPlans, backuptypes.RestoreTestingPlanForList{
			RestoreTestingPlanName: awssdk.String("plan"),
		})
	}
	return out, nil
}

// ---------------------------------------------------------------- fake EKS

type fakeEKS struct {
	clusters []string
	err      error
}

func (f *fakeEKS) ListClusters(context.Context, *eks.ListClustersInput, ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &eks.ListClustersOutput{Clusters: f.clusters}, nil
}

func (f *fakeEKS) DescribeCluster(_ context.Context, in *eks.DescribeClusterInput, _ ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	name := awssdk.ToString(in.Name)
	return &eks.DescribeClusterOutput{Cluster: &ekstypes.Cluster{
		Arn:     awssdk.String("arn:aws:eks:ap-southeast-1:123456789012:cluster/" + name),
		Name:    awssdk.String(name),
		Version: awssdk.String("1.31"),
		Status:  ekstypes.ClusterStatusActive,
	}}, nil
}

// ----------------------------------------------------------------- fake S3

type fakeS3 struct{}

func (f *fakeS3) GetObjectLockConfiguration(context.Context, *s3.GetObjectLockConfigurationInput, ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error) {
	return nil, &stubAPIErr{code: "ObjectLockConfigurationNotFoundError"}
}

func (f *fakeS3) GetBucketLocation(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	return &s3.GetBucketLocationOutput{}, nil
}

// ----------------------------------------------------------- fake Provider

type fakeProvider struct {
	base      string
	sts       STSAPI
	perRegion map[string]Clients
}

func (f *fakeProvider) BaseRegion() string { return f.base }
func (f *fakeProvider) STS() STSAPI        { return f.sts }

func (f *fakeProvider) For(region string) Clients {
	if c, ok := f.perRegion[region]; ok {
		return c
	}
	// An empty-but-valid region, so scanning an unexpected region is inert
	// rather than a nil-pointer panic.
	return Clients{
		Region: region,
		EC2:    &fakeEC2{},
		RDS:    &fakeRDS{},
		Backup: &fakeBackup{},
		EKS:    &fakeEKS{},
		S3:     &fakeS3{},
	}
}

// ------------------------------------------------------------- convenience

func ptrTime(t time.Time) *time.Time { return &t }

func completedPoint(resourceArn string, created time.Time, lastRestore *time.Time) backuptypes.RecoveryPointByBackupVault {
	return backuptypes.RecoveryPointByBackupVault{
		ResourceArn:     awssdk.String(resourceArn),
		Status:          backuptypes.RecoveryPointStatusCompleted,
		CreationDate:    awssdk.Time(created),
		CompletionDate:  awssdk.Time(created),
		LastRestoreTime: lastRestore,
	}
}
