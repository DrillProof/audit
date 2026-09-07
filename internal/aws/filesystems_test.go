package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drillproof/audit/internal/model"
)

func fsDesc(id, name, az string) efstypes.FileSystemDescription {
	d := efstypes.FileSystemDescription{
		FileSystemId:  awssdk.String(id),
		FileSystemArn: awssdk.String("arn:aws:elasticfilesystem:us-east-1:111122223333:file-system/" + id),
		Name:          awssdk.String(name),
	}
	if az != "" {
		d.AvailabilityZoneName = awssdk.String(az)
	}
	return d
}

func TestFileSystemsReadsAutomaticBackupsAndStorageClass(t *testing.T) {
	c := Clients{Region: "us-east-1", EFS: &fakeEFS{
		filesystems: []efstypes.FileSystemDescription{fsDesc("fs-1", "shared-data", "")},
		policy:      map[string]efstypes.Status{"fs-1": efstypes.StatusEnabled},
	}}

	resources, states, err := FileSystems(context.Background(), c)
	require.NoError(t, err)
	require.Len(t, resources, 1)

	assert.Equal(t, model.TypeFileSystem, resources[0].Type)
	assert.Equal(t, "shared-data (EFS)", resources[0].Display)
	assert.Equal(t, "regional", resources[0].Attrs["storage_class"])

	state := states[resources[0].ARN]
	require.NotNil(t, state)
	require.NotNil(t, state.EFS)
	assert.Equal(t, model.Yes, state.EFS.AutomaticBackups)
	assert.Equal(t, model.No, state.EFS.OneZone)
}

func TestFileSystemsDetectsOneZone(t *testing.T) {
	c := Clients{Region: "us-east-1", EFS: &fakeEFS{
		filesystems: []efstypes.FileSystemDescription{fsDesc("fs-2", "cheap-data", "us-east-1a")},
	}}

	resources, states, err := FileSystems(context.Background(), c)
	require.NoError(t, err)
	require.Len(t, resources, 1)

	assert.Equal(t, "one-zone", resources[0].Attrs["storage_class"])
	assert.Equal(t, "us-east-1a", resources[0].Attrs["availability_zone"])
	assert.Equal(t, model.Yes, states[resources[0].ARN].EFS.OneZone)
	// PolicyNotFound is a real negative — there is no automatic backup
	// policy — not an access gap.
	assert.Equal(t, model.No, states[resources[0].ARN].EFS.AutomaticBackups)
	assert.Empty(t, states[resources[0].ARN].Unassessed)
}

func TestFileSystemsDeniedBackupPolicyIsNotAssessed(t *testing.T) {
	c := Clients{Region: "us-east-1", EFS: &fakeEFS{
		filesystems: []efstypes.FileSystemDescription{fsDesc("fs-3", "prod-data", "")},
		policyErr:   &smithy.GenericAPIError{Code: "AccessDeniedException"},
	}}

	_, states, err := FileSystems(context.Background(), c)
	require.NoError(t, err)

	state := states["arn:aws:elasticfilesystem:us-east-1:111122223333:file-system/fs-3"]
	require.NotNil(t, state)
	assert.Equal(t, model.Unknown, state.EFS.AutomaticBackups)
	assert.Equal(t,
		"elasticfilesystem:DescribeBackupPolicy denied",
		state.Unassessed[model.CheckCoverage])
}

func TestFileSystemsReadsReplicationHealthAndRegion(t *testing.T) {
	c := Clients{Region: "us-east-1", EFS: &fakeEFS{
		filesystems: []efstypes.FileSystemDescription{fsDesc("fs-4", "replicated", "")},
		replication: map[string][]efstypes.Destination{"fs-4": {{
			Region: awssdk.String("us-west-2"),
			Status: efstypes.ReplicationStatusEnabled,
		}}},
	}}

	_, states, err := FileSystems(context.Background(), c)
	require.NoError(t, err)
	repl := states["arn:aws:elasticfilesystem:us-east-1:111122223333:file-system/fs-4"].EFS.Replication
	assert.Equal(t, model.Yes, repl.Configured)
	assert.Equal(t, model.Yes, repl.Healthy)
	assert.Equal(t, model.Yes, repl.CrossRegion)
	assert.Equal(t, []string{"us-west-2"}, repl.DestRegions)
}

func TestFileSystemsUnhealthyAndSameRegionReplication(t *testing.T) {
	c := Clients{Region: "us-east-1", EFS: &fakeEFS{
		filesystems: []efstypes.FileSystemDescription{
			fsDesc("fs-5", "broken", ""),
			fsDesc("fs-6", "local-copy", ""),
		},
		replication: map[string][]efstypes.Destination{
			"fs-5": {{Region: awssdk.String("us-west-2"), Status: efstypes.ReplicationStatusError}},
			"fs-6": {{Region: awssdk.String("us-east-1"), Status: efstypes.ReplicationStatusEnabled}},
		},
	}}

	_, states, err := FileSystems(context.Background(), c)
	require.NoError(t, err)
	base := "arn:aws:elasticfilesystem:us-east-1:111122223333:file-system/"

	broken := states[base+"fs-5"].EFS.Replication
	assert.Equal(t, model.Yes, broken.Configured)
	assert.Equal(t, model.No, broken.Healthy)

	local := states[base+"fs-6"].EFS.Replication
	assert.Equal(t, model.No, local.CrossRegion)
}

func TestFileSystemsDeniedReplicationIsUnknownNotHealthy(t *testing.T) {
	c := Clients{Region: "us-east-1", EFS: &fakeEFS{
		filesystems: []efstypes.FileSystemDescription{fsDesc("fs-7", "opaque", "")},
		replErr:     &smithy.GenericAPIError{Code: "AccessDeniedException"},
	}}

	_, states, err := FileSystems(context.Background(), c)
	require.NoError(t, err)
	state := states["arn:aws:elasticfilesystem:us-east-1:111122223333:file-system/fs-7"]
	assert.Equal(t, model.Unknown, state.EFS.Replication.Healthy)
	assert.Equal(t, model.Unknown, state.EFS.Replication.CrossRegion)
	assert.Equal(t,
		"elasticfilesystem:DescribeReplicationConfigurations denied",
		state.Unassessed[model.CheckRedundancy])
}

func TestFileSystemsPaginates(t *testing.T) {
	// Two pages must both be returned. A discovery loop that stops at the
	// first page silently under-reports an estate, which reads as "we found
	// nothing wrong" rather than "we did not look".
	c := Clients{Region: "us-east-1", EFS: &pagedEFS{}}
	resources, _, err := FileSystems(context.Background(), c)
	require.NoError(t, err)
	assert.Len(t, resources, 2)
}

// pagedEFS returns one filesystem per page across two pages.
type pagedEFS struct{ fakeEFS }

func (p *pagedEFS) DescribeFileSystems(_ context.Context, in *efs.DescribeFileSystemsInput, _ ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
	if in.Marker == nil {
		return &efs.DescribeFileSystemsOutput{
			FileSystems: []efstypes.FileSystemDescription{fsDesc("fs-a", "a", "")},
			NextMarker:  awssdk.String("page-2"),
		}, nil
	}
	return &efs.DescribeFileSystemsOutput{
		FileSystems: []efstypes.FileSystemDescription{fsDesc("fs-b", "b", "")},
	}, nil
}
