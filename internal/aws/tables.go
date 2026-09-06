package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/drillproof/audit/internal/model"
)

// Tables inventories DynamoDB tables in one region and reads each one's
// Point-in-Time Recovery status.
//
// Unlike buckets, tables are genuinely regional and ride the normal per-region
// fan-out. States are keyed by table ARN so the caller can merge AWS Backup
// recovery points into them.
func Tables(ctx context.Context, c Clients) ([]model.Resource, map[string]*model.BackupState, error) {
	var resources []model.Resource
	states := map[string]*model.BackupState{}

	var start *string
	for {
		page, err := c.DynamoDB.ListTables(ctx, &dynamodb.ListTablesInput{
			ExclusiveStartTableName: start,
		})
		if err != nil {
			return resources, states, err
		}

		for _, name := range page.TableNames {
			desc, err := c.DynamoDB.DescribeTable(ctx, &dynamodb.DescribeTableInput{
				TableName: awssdk.String(name),
			})
			if err != nil || desc.Table == nil {
				// One table failing must not drop the rest of the region.
				continue
			}
			arn := awssdk.ToString(desc.Table.TableArn)

			state := model.NewBackupState()
			protection := &model.DynamoProtection{}
			state.Dynamo = protection

			// A global-table replica is recorded, never counted as redundancy:
			// a delete propagates to it, so it is availability, not backup.
			for _, replica := range desc.Table.Replicas {
				protection.GlobalTableReplicas = append(
					protection.GlobalTableReplicas, awssdk.ToString(replica.RegionName))
			}

			readPITR(ctx, c, name, state, protection)

			resources = append(resources, model.Resource{
				Display:    fmt.Sprintf("%s (DynamoDB)", name),
				Name:       name,
				ARN:        arn,
				Type:       model.TypeTable,
				Region:     c.Region,
				Production: looksProduction(name, tableTags(ctx, c, arn)),
				Attrs: map[string]string{
					"table": name,
					"pitr":  protection.PITR.String(),
				},
			})
			states[arn] = state
		}

		if page.LastEvaluatedTableName == nil || *page.LastEvaluatedTableName == "" {
			break
		}
		start = page.LastEvaluatedTableName
	}

	return resources, states, nil
}

func readPITR(ctx context.Context, c Clients, name string, state *model.BackupState, p *model.DynamoProtection) {
	out, err := c.DynamoDB.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{
		TableName: awssdk.String(name),
	})
	if err != nil {
		// Never a FAIL — a table might well be PITR-protected and we simply
		// could not see it.
		p.PITR = model.Unknown
		state.MarkUnassessed(model.CheckCoverage, "dynamodb:DescribeContinuousBackups denied")
		return
	}
	if out.ContinuousBackupsDescription == nil ||
		out.ContinuousBackupsDescription.PointInTimeRecoveryDescription == nil {
		p.PITR = model.Unknown
		return
	}
	if out.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus ==
		dynamodbtypes.PointInTimeRecoveryStatusEnabled {
		p.PITR = model.Yes
		return
	}
	p.PITR = model.No
}

func tableTags(ctx context.Context, c Clients, arn string) map[string]string {
	tags := map[string]string{}
	out, err := c.DynamoDB.ListTagsOfResource(ctx, &dynamodb.ListTagsOfResourceInput{
		ResourceArn: awssdk.String(arn),
	})
	if err != nil {
		return tags
	}
	for _, t := range out.Tags {
		tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return tags
}
