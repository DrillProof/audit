package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/drillproof/audit/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tableClients(f *fakeDynamoDB) Clients {
	return Clients{Region: "us-east-1", DynamoDB: f}
}

func TestTablesReadPITRStatus(t *testing.T) {
	f := &fakeDynamoDB{
		tables: []string{"sessions", "audit-log"},
		described: map[string]dynamodbtypes.TableDescription{
			"sessions":  {TableArn: awssdk.String("arn:aws:dynamodb:us-east-1:1:table/sessions")},
			"audit-log": {TableArn: awssdk.String("arn:aws:dynamodb:us-east-1:1:table/audit-log")},
		},
		pitr: map[string]dynamodbtypes.PointInTimeRecoveryStatus{
			"sessions": dynamodbtypes.PointInTimeRecoveryStatusEnabled,
		},
	}
	resources, states, err := Tables(context.Background(), tableClients(f))
	require.NoError(t, err)
	require.Len(t, resources, 2)

	assert.Equal(t, model.TypeTable, resources[0].Type)
	assert.Contains(t, resources[0].Display, "(DynamoDB)")
	assert.Equal(t, model.Yes, states["arn:aws:dynamodb:us-east-1:1:table/sessions"].Dynamo.PITR)
	assert.Equal(t, model.No, states["arn:aws:dynamodb:us-east-1:1:table/audit-log"].Dynamo.PITR)
}

func TestTablesRecordGlobalTableReplicas(t *testing.T) {
	f := &fakeDynamoDB{
		tables: []string{"sessions"},
		described: map[string]dynamodbtypes.TableDescription{
			"sessions": {
				TableArn: awssdk.String("arn:aws:dynamodb:us-east-1:1:table/sessions"),
				Replicas: []dynamodbtypes.ReplicaDescription{
					{RegionName: awssdk.String("eu-west-1")},
				},
			},
		},
	}
	_, states, err := Tables(context.Background(), tableClients(f))
	require.NoError(t, err)
	assert.Equal(t,
		[]string{"eu-west-1"},
		states["arn:aws:dynamodb:us-east-1:1:table/sessions"].Dynamo.GlobalTableReplicas)
}

func TestDeniedPITRMarksCoverageUnassessedNamingTheAction(t *testing.T) {
	f := &fakeDynamoDB{
		tables: []string{"sessions"},
		described: map[string]dynamodbtypes.TableDescription{
			"sessions": {TableArn: awssdk.String("arn:aws:dynamodb:us-east-1:1:table/sessions")},
		},
		pitrErr: denied(),
	}
	_, states, err := Tables(context.Background(), tableClients(f))
	require.NoError(t, err)

	state := states["arn:aws:dynamodb:us-east-1:1:table/sessions"]
	reason, ok := state.Unassessed[model.CheckCoverage]
	require.True(t, ok)
	assert.Contains(t, reason, "dynamodb:DescribeContinuousBackups")
}

func TestDeniedListTablesReturnsTheError(t *testing.T) {
	// A denied ListTables means we did not inventory the region at all. The
	// caller turns this into a scan warning, so absence is never mistaken for
	// an account with no tables.
	f := &fakeDynamoDB{listErr: denied()}
	_, _, err := Tables(context.Background(), tableClients(f))
	assert.Error(t, err)
	assert.True(t, IsAccessDenied(err))
}
