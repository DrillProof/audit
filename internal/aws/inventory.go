package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/drillproof/audit/internal/model"
)

// Identity is who the CLI is running as.
type Identity struct {
	AccountID string
	ARN       string
}

// WhoAmI resolves the caller. Failing here is fatal — without an account we
// cannot build resource ARNs or label the report.
func WhoAmI(ctx context.Context, api STSAPI) (Identity, error) {
	out, err := api.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Identity{}, fmt.Errorf("resolve caller identity: %w", err)
	}
	return Identity{
		AccountID: awssdk.ToString(out.Account),
		ARN:       awssdk.ToString(out.Arn),
	}, nil
}

// EnabledRegions discovers the regions this account has enabled, so the user
// never has to type --region. Falls back to the credential-chain region when
// DescribeRegions is denied.
func EnabledRegions(ctx context.Context, api EC2API, fallback string) ([]string, error) {
	out, err := api.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: awssdk.Bool(false),
	})
	if err != nil {
		if IsAccessDenied(err) && fallback != "" {
			return []string{fallback}, nil
		}
		return nil, fmt.Errorf("discover regions: %w", err)
	}

	var regions []string
	for _, r := range out.Regions {
		name := awssdk.ToString(r.RegionName)
		if name == "" {
			continue
		}
		// OptInStatus is "opt-in-not-required" or "opted-in" for usable regions.
		status := awssdk.ToString(r.OptInStatus)
		if status == "not-opted-in" {
			continue
		}
		regions = append(regions, name)
	}
	sort.Strings(regions)
	if len(regions) == 0 && fallback != "" {
		regions = []string{fallback}
	}
	return regions, nil
}

// productionHints are the substrings that make us treat a resource as
// production. Deliberately conservative and one-directional: a match raises
// scrutiny, a non-match never lowers it.
var productionHints = []string{"prod", "prd", "live", "payments", "billing"}

func looksProduction(name string, tags map[string]string) bool {
	lower := strings.ToLower(name)
	for _, hint := range productionHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	for k, v := range tags {
		kl, vl := strings.ToLower(k), strings.ToLower(v)
		if kl == "environment" || kl == "env" || kl == "stage" {
			if strings.Contains(vl, "prod") || strings.Contains(vl, "live") {
				return true
			}
		}
	}
	return false
}

func ec2Tags(tags []ec2types.Tag) map[string]string {
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return m
}

// Volumes inventories EBS volumes in a region.
func Volumes(ctx context.Context, c Clients, accountID string) ([]model.Resource, error) {
	var out []model.Resource
	var token *string

	for {
		page, err := c.EC2.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{NextToken: token})
		if err != nil {
			return out, err
		}
		for _, v := range page.Volumes {
			id := awssdk.ToString(v.VolumeId)
			tags := ec2Tags(v.Tags)
			name := tags["Name"]
			if name == "" {
				name = id
			}

			attrs := map[string]string{
				"volume_id": id,
				"state":     string(v.State),
			}
			if v.Size != nil {
				attrs["size_gib"] = fmt.Sprintf("%d", *v.Size)
			}
			if len(v.Attachments) > 0 {
				attrs["attached_to"] = awssdk.ToString(v.Attachments[0].InstanceId)
			}

			out = append(out, model.Resource{
				Display:    fmt.Sprintf("%s (EBS)", name),
				Name:       name,
				ARN:        fmt.Sprintf("arn:aws:ec2:%s:%s:volume/%s", c.Region, accountID, id),
				Type:       model.TypeVolume,
				Region:     c.Region,
				Production: looksProduction(name+" "+id, tags),
				Attrs:      attrs,
			})
		}
		if page.NextToken == nil || *page.NextToken == "" {
			break
		}
		token = page.NextToken
	}
	return out, nil
}

// Databases inventories RDS instances and clusters in a region.
//
// Cluster members are skipped: an Aurora instance inside a cluster is backed up
// at the cluster level, so listing both would double-count and distort the
// score.
func Databases(ctx context.Context, c Clients) ([]model.Resource, error) {
	var out []model.Resource

	var marker *string
	for {
		page, err := c.RDS.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{Marker: marker})
		if err != nil {
			return out, err
		}
		for _, db := range page.DBInstances {
			if awssdk.ToString(db.DBClusterIdentifier) != "" {
				continue // covered by its cluster
			}
			name := awssdk.ToString(db.DBInstanceIdentifier)
			tags := map[string]string{}
			for _, tag := range db.TagList {
				tags[awssdk.ToString(tag.Key)] = awssdk.ToString(tag.Value)
			}

			retention := int32(0)
			if db.BackupRetentionPeriod != nil {
				retention = *db.BackupRetentionPeriod
			}
			attrs := map[string]string{
				"engine":                awssdk.ToString(db.Engine),
				"backup_retention_days": fmt.Sprintf("%d", retention),
				"multi_az":              fmt.Sprintf("%t", awssdk.ToBool(db.MultiAZ)),
			}
			if db.LatestRestorableTime != nil {
				attrs["latest_restorable_time"] = db.LatestRestorableTime.UTC().Format("2006-01-02T15:04:05Z")
			}

			out = append(out, model.Resource{
				Display:    fmt.Sprintf("%s (RDS)", name),
				Name:       name,
				ARN:        awssdk.ToString(db.DBInstanceArn),
				Type:       model.TypeDatabase,
				Region:     c.Region,
				Production: looksProduction(name, tags),
				Attrs:      attrs,
			})
		}
		if page.Marker == nil || *page.Marker == "" {
			break
		}
		marker = page.Marker
	}

	marker = nil
	for {
		page, err := c.RDS.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{Marker: marker})
		if err != nil {
			return out, err
		}
		for _, cl := range page.DBClusters {
			name := awssdk.ToString(cl.DBClusterIdentifier)
			tags := map[string]string{}
			for _, tag := range cl.TagList {
				tags[awssdk.ToString(tag.Key)] = awssdk.ToString(tag.Value)
			}

			retention := int32(0)
			if cl.BackupRetentionPeriod != nil {
				retention = *cl.BackupRetentionPeriod
			}

			out = append(out, model.Resource{
				Display:    fmt.Sprintf("%s (RDS cluster)", name),
				Name:       name,
				ARN:        awssdk.ToString(cl.DBClusterArn),
				Type:       model.TypeDBCluster,
				Region:     c.Region,
				Production: looksProduction(name, tags),
				Attrs: map[string]string{
					"engine":                awssdk.ToString(cl.Engine),
					"backup_retention_days": fmt.Sprintf("%d", retention),
				},
			})
		}
		if page.Marker == nil || *page.Marker == "" {
			break
		}
		marker = page.Marker
	}

	return out, nil
}

// Clusters inventories EKS clusters. Each becomes a k8s-state resource,
// because what needs backing up about a cluster is its state, not its
// control plane.
func Clusters(ctx context.Context, c Clients) ([]model.Resource, error) {
	var out []model.Resource
	var token *string

	for {
		page, err := c.EKS.ListClusters(ctx, &eks.ListClustersInput{NextToken: token})
		if err != nil {
			return out, err
		}
		for _, name := range page.Clusters {
			res := model.Resource{
				Display:    fmt.Sprintf("etcd (%s)", name),
				Name:       name,
				Type:       model.TypeK8sState,
				Region:     c.Region,
				Production: looksProduction(name, nil),
				Attrs:      map[string]string{"cluster": name},
			}

			// Detail is best-effort: a denied DescribeCluster should not drop
			// the cluster from the inventory.
			if d, err := c.EKS.DescribeCluster(ctx, &eks.DescribeClusterInput{
				Name: awssdk.String(name),
			}); err == nil && d.Cluster != nil {
				res.ARN = awssdk.ToString(d.Cluster.Arn)
				res.Attrs["version"] = awssdk.ToString(d.Cluster.Version)
				res.Attrs["status"] = string(d.Cluster.Status)
				tags := d.Cluster.Tags
				if looksProduction(name, tags) {
					res.Production = true
				}
			}

			out = append(out, res)
		}
		if page.NextToken == nil || *page.NextToken == "" {
			break
		}
		token = page.NextToken
	}
	return out, nil
}
