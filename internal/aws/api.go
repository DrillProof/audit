// Package aws wraps the AWS SDK behind narrow, read-only interfaces.
//
// # Read-only by construction
//
// v1 must never mutate anything. Rather than rely on review discipline, the
// interfaces below expose *only* Describe/List/Get operations — there is no
// method on any interface in this package that can create, restore, modify, or
// delete. Code elsewhere in the CLI holds these interfaces, not the SDK
// clients, so a mutating call is not merely discouraged, it does not compile.
//
// api_readonly_test.go reflects over every interface here and fails the build
// if a method name appears that is not a read verb.
package aws

import (
	"context"
	"errors"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// STSAPI is the identity surface: who are we running as?
type STSAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// EC2API covers region discovery and EBS inventory.
type EC2API interface {
	DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
	DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
}

// RDSAPI covers database inventory and native snapshot state.
type RDSAPI interface {
	DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
	DescribeDBClusters(context.Context, *rds.DescribeDBClustersInput, ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error)
	DescribeDBSnapshots(context.Context, *rds.DescribeDBSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error)
	DescribeDBClusterSnapshots(context.Context, *rds.DescribeDBClusterSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotsOutput, error)
}

// BackupAPI covers AWS Backup: recovery points, vault lock, restore history.
type BackupAPI interface {
	ListBackupVaults(context.Context, *backup.ListBackupVaultsInput, ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error)
	DescribeBackupVault(context.Context, *backup.DescribeBackupVaultInput, ...func(*backup.Options)) (*backup.DescribeBackupVaultOutput, error)
	ListRecoveryPointsByBackupVault(context.Context, *backup.ListRecoveryPointsByBackupVaultInput, ...func(*backup.Options)) (*backup.ListRecoveryPointsByBackupVaultOutput, error)
	ListRecoveryPointsByResource(context.Context, *backup.ListRecoveryPointsByResourceInput, ...func(*backup.Options)) (*backup.ListRecoveryPointsByResourceOutput, error)
	ListRestoreTestingPlans(context.Context, *backup.ListRestoreTestingPlansInput, ...func(*backup.Options)) (*backup.ListRestoreTestingPlansOutput, error)
}

// EKSAPI covers cluster inventory.
type EKSAPI interface {
	ListClusters(context.Context, *eks.ListClustersInput, ...func(*eks.Options)) (*eks.ListClustersOutput, error)
	DescribeCluster(context.Context, *eks.DescribeClusterInput, ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
}

// S3API covers Object Lock status on backup target buckets.
type S3API interface {
	GetObjectLockConfiguration(context.Context, *s3.GetObjectLockConfigurationInput, ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error)
	GetBucketLocation(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
}

// Clients is the per-region bundle the scanner works with.
type Clients struct {
	Region string
	EC2    EC2API
	RDS    RDSAPI
	Backup BackupAPI
	EKS    EKSAPI
	S3     S3API
}

// Provider builds clients. Swapped for a fake in tests.
type Provider interface {
	// For returns clients bound to a region.
	For(region string) Clients
	// STS returns the identity client (region-independent).
	STS() STSAPI
	// BaseRegion is the region resolved from the credential chain.
	BaseRegion() string
}

type sdkProvider struct {
	cfg awssdk.Config
}

// LoadProvider resolves credentials from the standard AWS chain. The profile
// and region arguments narrow it; both may be empty.
//
// Retry is configured up front: AWS Backup and EC2 throttle readily when
// scanning many regions, and the spec requires we never crash or hang on rate
// limits.
func LoadProvider(ctx context.Context, profile, region string) (Provider, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRetryer(func() awssdk.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.MaxAttempts = 8
			})
		}),
	}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	// A region is required to make any call at all. us-east-1 is the
	// conventional fallback for global operations like DescribeRegions.
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	return &sdkProvider{cfg: cfg}, nil
}

func (p *sdkProvider) BaseRegion() string { return p.cfg.Region }

func (p *sdkProvider) STS() STSAPI { return sts.NewFromConfig(p.cfg) }

func (p *sdkProvider) For(region string) Clients {
	cfg := p.cfg.Copy()
	cfg.Region = region
	return Clients{
		Region: region,
		EC2:    ec2.NewFromConfig(cfg),
		RDS:    rds.NewFromConfig(cfg),
		Backup: backup.NewFromConfig(cfg),
		EKS:    eks.NewFromConfig(cfg),
		S3:     s3.NewFromConfig(cfg),
	}
}

// IsAccessDenied reports whether an error is a permissions problem, as opposed
// to a real failure. The distinction matters: a denied call becomes a visible
// "not assessed" rather than a crash or a silent pass.
func IsAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
			"AuthFailure", "InvalidClientTokenId", "Forbidden",
			"MissingAuthenticationToken", "OptInRequired":
			return true
		}
		// Some services phrase it only in the message.
		msg := strings.ToLower(apiErr.ErrorMessage())
		if strings.Contains(msg, "not authorized") || strings.Contains(msg, "access denied") {
			return true
		}
	}
	return false
}

// IsNotFound reports whether an error means "this thing has no such
// configuration", which for several of our checks is a legitimate negative
// answer rather than a failure. A bucket with no Object Lock configuration,
// for example, answers the immutability question with "no".
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "ObjectLockConfigurationNotFoundError", "NoSuchBucket",
			"ResourceNotFoundException", "NoSuchObjectLockConfiguration":
			return true
		}
	}
	return false
}

// ErrorCode extracts an API error code for display, or "" if not an API error.
func ErrorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}
