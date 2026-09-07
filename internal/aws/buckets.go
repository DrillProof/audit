package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/drillproof/audit/internal/checks"
	"github.com/drillproof/audit/internal/model"
)

// normaliseBucketRegion maps a LocationConstraint to a real region name.
//
// Two legacy quirks, both of which silently misfile a bucket if missed — and a
// misfiled bucket reads as a same-region replication failure, which is a false
// finding rather than a cosmetic bug.
func normaliseBucketRegion(constraint string) string {
	switch constraint {
	case "":
		return "us-east-1"
	case "EU":
		return "eu-west-1"
	default:
		return constraint
	}
}

// Buckets inventories S3 buckets and reads each one's deletion-protection
// posture.
//
// Runs ONCE per account, outside the per-region fan-out: ListBuckets is global,
// so calling it per region would return every bucket once per region. Each
// bucket's config calls are then issued against a client in that bucket's own
// region, because GetBucketVersioning and friends redirect or fail against the
// wrong regional endpoint.
//
// allowList, when non-empty, replaces ListBuckets entirely — letting a customer
// grant s3:GetBucket* on named ARNs and withhold s3:ListAllMyBuckets.
func Buckets(
	ctx context.Context,
	p Provider,
	regions []string,
	allowList []string,
) ([]model.Resource, map[string]*model.BackupState, []string) {
	var (
		resources []model.Resource
		warnings  []string
	)
	states := map[string]*model.BackupState{}

	inScope := map[string]bool{}
	for _, r := range regions {
		inScope[r] = true
	}

	names := allowList
	if len(names) == 0 {
		base := p.For(p.BaseRegion())
		out, err := base.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			return nil, states, []string{describeFailure(p.BaseRegion(), "s3:ListAllMyBuckets", err)}
		}
		for _, b := range out.Buckets {
			names = append(names, awssdk.ToString(b.Name))
		}
	}
	sort.Strings(names)

	for _, name := range names {
		region, err := bucketRegion(ctx, p, name)
		if err != nil {
			warnings = append(warnings,
				fmt.Sprintf("%s: s3:GetBucketLocation failed for bucket %q — it was not assessed", p.BaseRegion(), name))
			continue
		}
		if !inScope[region] {
			// Dropped, but never silently: absence must never look like a
			// clean result.
			warnings = append(warnings,
				fmt.Sprintf("bucket %q is in %s, outside the scanned regions — not assessed", name, region))
			continue
		}

		c := p.For(region)
		state := model.NewBackupState()
		protection := &model.S3Protection{}
		state.S3 = protection

		readVersioning(ctx, c, name, state, protection)
		readObjectLock(ctx, c, name, state, protection)
		readReplication(ctx, p, c, name, region, state, protection)
		protection.Tier = checks.BucketTier(protection)

		tags := bucketTags(ctx, c, name)
		resources = append(resources, model.Resource{
			Display:    fmt.Sprintf("%s (S3)", name),
			Name:       name,
			ARN:        "arn:aws:s3:::" + name,
			Type:       model.TypeBucket,
			Region:     region,
			Production: looksProduction(name, tags),
			Attrs: map[string]string{
				"bucket":           name,
				"object_lock_mode": protection.ObjectLockMode,
				"versioning":       protection.Versioning.String(),
			},
		})
		states[name] = state
	}

	return resources, states, warnings
}

func bucketRegion(ctx context.Context, p Provider, name string) (string, error) {
	c := p.For(p.BaseRegion())
	out, err := c.S3.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: awssdk.String(name)})
	if err != nil {
		return "", err
	}
	return normaliseBucketRegion(string(out.LocationConstraint)), nil
}

func readVersioning(ctx context.Context, c Clients, name string, state *model.BackupState, p *model.S3Protection) {
	out, err := c.S3.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: awssdk.String(name)})
	if err != nil {
		// Never a FAIL. A role that predates S3 support must degrade to "not
		// assessed", naming the permission that would fix it.
		state.MarkUnassessed(model.CheckCoverage, "s3:GetBucketVersioning denied")
		return
	}

	switch out.Status {
	case s3types.BucketVersioningStatusEnabled:
		p.Versioning = model.Yes
	case s3types.BucketVersioningStatusSuspended:
		p.Versioning = model.No
	default:
		// The field is absent on a bucket that never had versioning. That is a
		// real "no", not an unknown: the API answers this one definitively.
		p.Versioning = model.No
	}

	// MFADelete is different: it is commonly omitted rather than reported
	// Disabled, so absence here genuinely means "we could not find out".
	switch out.MFADelete {
	case s3types.MFADeleteStatusEnabled:
		p.MFADelete = model.Yes
	case s3types.MFADeleteStatusDisabled:
		p.MFADelete = model.No
	default:
		p.MFADelete = model.Unknown
	}
}

func readObjectLock(ctx context.Context, c Clients, name string, state *model.BackupState, p *model.S3Protection) {
	out, err := c.S3.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: awssdk.String(name)})
	if err != nil {
		if IsNotFound(err) {
			// A definitive negative: the bucket has no Object Lock.
			p.ObjectLockMode = ""
			return
		}
		state.MarkUnassessed(model.CheckImmutability, "s3:GetBucketObjectLockConfiguration denied")
		return
	}
	if out.ObjectLockConfiguration == nil ||
		out.ObjectLockConfiguration.Rule == nil ||
		out.ObjectLockConfiguration.Rule.DefaultRetention == nil {
		// Object Lock can be enabled with no default retention rule, in which
		// case there is no mode to report. Treated as "not compliance" rather
		// than guessed at.
		p.ObjectLockMode = ""
		return
	}
	p.ObjectLockMode = string(out.ObjectLockConfiguration.Rule.DefaultRetention.Mode)
}

func readReplication(
	ctx context.Context,
	p Provider,
	c Clients,
	name, sourceRegion string,
	state *model.BackupState,
	prot *model.S3Protection,
) {
	out, err := c.S3.GetBucketReplication(ctx, &s3.GetBucketReplicationInput{Bucket: awssdk.String(name)})
	if err != nil {
		if IsNotFound(err) {
			prot.Replication.Configured = model.No
			return
		}
		prot.Replication.Configured = model.Unknown
		state.MarkUnassessed(model.CheckRedundancy, "s3:GetBucketReplication denied")
		return
	}
	if out.ReplicationConfiguration == nil || len(out.ReplicationConfiguration.Rules) == 0 {
		prot.Replication.Configured = model.No
		return
	}

	prot.Replication.Configured = model.Yes
	prot.Replication.EnabledRule = model.No
	crossRegion := model.No
	unresolved := false

	for _, rule := range out.ReplicationConfiguration.Rules {
		if rule.Status != s3types.ReplicationRuleStatusEnabled {
			continue
		}
		prot.Replication.EnabledRule = model.Yes

		if rule.Destination == nil || rule.Destination.Bucket == nil {
			unresolved = true
			continue
		}
		// The destination is an ARN, which carries no region — the region has
		// to be resolved by asking.
		dest := strings.TrimPrefix(awssdk.ToString(rule.Destination.Bucket), "arn:aws:s3:::")
		destRegion, err := bucketRegion(ctx, p, dest)
		if err != nil {
			unresolved = true
			continue
		}
		prot.Replication.DestRegions = append(prot.Replication.DestRegions, destRegion)
		if destRegion != sourceRegion {
			crossRegion = model.Yes
		}
	}

	switch {
	case crossRegion == model.Yes:
		prot.Replication.CrossRegion = model.Yes
	case unresolved:
		// We could not see where an enabled rule points. Saying "same region"
		// would be a claim we have not earned.
		prot.Replication.CrossRegion = model.Unknown
	default:
		prot.Replication.CrossRegion = crossRegion
	}
}

func bucketTags(ctx context.Context, c Clients, name string) map[string]string {
	tags := map[string]string{}
	out, err := c.S3.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: awssdk.String(name)})
	if err != nil {
		// Tags only ever raise scrutiny, so a denied read costs a possible
		// production flag and nothing else. Not worth a warning.
		return tags
	}
	for _, t := range out.TagSet {
		tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return tags
}
