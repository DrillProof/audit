package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"

	"github.com/drillproof/audit/internal/model"
)

// FileSystems inventories EFS filesystems in one region and reads each one's
// automatic-backup policy, storage class, and replication configuration.
//
// Filesystems are regional and ride the normal per-region fan-out, so states
// are keyed by ARN exactly as Tables keys tables — which is also what lets
// GatherBackupStateInto merge AWS Backup recovery points into them.
func FileSystems(ctx context.Context, c Clients) ([]model.Resource, map[string]*model.BackupState, error) {
	var resources []model.Resource
	states := map[string]*model.BackupState{}

	var marker *string
	for {
		page, err := c.EFS.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{Marker: marker})
		if err != nil {
			return resources, states, err
		}

		for _, fs := range page.FileSystems {
			id := awssdk.ToString(fs.FileSystemId)
			arn := awssdk.ToString(fs.FileSystemArn)
			name := awssdk.ToString(fs.Name)
			if name == "" {
				name = id
			}

			state := model.NewBackupState()
			protection := &model.EFSProtection{}
			state.EFS = protection

			// One Zone surfaces as an AvailabilityZoneName on the filesystem
			// itself; a Regional filesystem has none.
			az := awssdk.ToString(fs.AvailabilityZoneName)
			storageClass := "regional"
			if az != "" {
				protection.OneZone = model.Yes
				protection.AvailabilityZone = az
				storageClass = "one-zone"
			} else {
				protection.OneZone = model.No
			}

			readBackupPolicy(ctx, c, id, state, protection)
			readEFSReplication(ctx, c, id, state, protection)

			attrs := map[string]string{
				"file_system":       id,
				"storage_class":     storageClass,
				"automatic_backups": protection.AutomaticBackups.String(),
			}
			if az != "" {
				attrs["availability_zone"] = az
			}

			resources = append(resources, model.Resource{
				Display:    fmt.Sprintf("%s (EFS)", name),
				Name:       name,
				ARN:        arn,
				Type:       model.TypeFileSystem,
				Region:     c.Region,
				Production: looksProduction(name, fileSystemTags(ctx, c, arn)),
				Attrs:      attrs,
			})
			states[arn] = state
		}

		if page.NextMarker == nil || *page.NextMarker == "" {
			break
		}
		marker = page.NextMarker
	}

	return resources, states, nil
}

// readBackupPolicy reads the built-in automatic-backup feature.
//
// PolicyNotFound is a real negative — there is genuinely no automatic backup
// policy — while a denial is not: a filesystem might well be protected and we
// simply could not see it, which must never read as a finding.
func readBackupPolicy(ctx context.Context, c Clients, id string, state *model.BackupState, p *model.EFSProtection) {
	out, err := c.EFS.DescribeBackupPolicy(ctx, &efs.DescribeBackupPolicyInput{
		FileSystemId: awssdk.String(id),
	})
	if err != nil {
		if IsNotFound(err) {
			p.AutomaticBackups = model.No
			return
		}
		p.AutomaticBackups = model.Unknown
		state.MarkUnassessed(model.CheckCoverage, "elasticfilesystem:DescribeBackupPolicy denied")
		return
	}
	if out.BackupPolicy == nil {
		p.AutomaticBackups = model.Unknown
		return
	}
	switch out.BackupPolicy.Status {
	case efstypes.StatusEnabled, efstypes.StatusEnabling:
		p.AutomaticBackups = model.Yes
	default:
		p.AutomaticBackups = model.No
	}
}

// readEFSReplication reads EFS's own cross-region replication.
//
// Health and destination region are separate answers, and an unreadable status
// stays Unknown: "configured" is not "working", and neither is "healthy".
func readEFSReplication(ctx context.Context, c Clients, id string, state *model.BackupState, p *model.EFSProtection) {
	out, err := c.EFS.DescribeReplicationConfigurations(ctx, &efs.DescribeReplicationConfigurationsInput{
		FileSystemId: awssdk.String(id),
	})
	if err != nil {
		if IsNotFound(err) {
			p.Replication.Configured = model.No
			return
		}
		p.Replication.Configured = model.Unknown
		p.Replication.Healthy = model.Unknown
		p.Replication.CrossRegion = model.Unknown
		state.MarkUnassessed(model.CheckRedundancy,
			"elasticfilesystem:DescribeReplicationConfigurations denied")
		return
	}

	if len(out.Replications) == 0 {
		p.Replication.Configured = model.No
		return
	}
	p.Replication.Configured = model.Yes

	healthy, unhealthy, crossRegion := false, false, false
	for _, repl := range out.Replications {
		for _, dest := range repl.Destinations {
			region := awssdk.ToString(dest.Region)
			if region != "" {
				p.Replication.DestRegions = append(p.Replication.DestRegions, region)
				if region != c.Region {
					crossRegion = true
				}
			}
			switch dest.Status {
			case efstypes.ReplicationStatusEnabled, efstypes.ReplicationStatusEnabling:
				healthy = true
			case "":
				// No status at all is not evidence in either direction.
			default:
				unhealthy = true
			}
		}
	}

	switch {
	case healthy:
		p.Replication.Healthy = model.Yes
	case unhealthy:
		p.Replication.Healthy = model.No
	default:
		p.Replication.Healthy = model.Unknown
	}

	if len(p.Replication.DestRegions) == 0 {
		p.Replication.CrossRegion = model.Unknown
		return
	}
	if crossRegion {
		p.Replication.CrossRegion = model.Yes
	} else {
		p.Replication.CrossRegion = model.No
	}
}

func fileSystemTags(ctx context.Context, c Clients, arn string) map[string]string {
	tags := map[string]string{}
	out, err := c.EFS.ListTagsForResource(ctx, &efs.ListTagsForResourceInput{
		ResourceId: awssdk.String(arn),
	})
	if err != nil {
		return tags
	}
	for _, t := range out.Tags {
		tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return tags
}
