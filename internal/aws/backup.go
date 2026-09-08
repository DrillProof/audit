package aws

import (
	"context"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/drillproof/audit/internal/model"
)

// Vault is one AWS Backup vault, with the fact that decides immutability.
type Vault struct {
	Name   string
	ARN    string
	Region string
	// Locked reports AWS Backup Vault Lock. This is the WORM guarantee: while
	// locked, recovery points cannot be deleted before their retention expires,
	// even by a root credential.
	Locked   Tristate3
	LockDate *time.Time
}

// Tristate3 mirrors model.Tristate inside this package to avoid the AWS layer
// importing presentation concerns. Converted on the way out.
type Tristate3 = model.Tristate

// VaultIndex is every vault we can see, by region.
type VaultIndex struct {
	ByRegion map[string][]Vault
	// Denied records regions where vault enumeration was refused, so
	// immutability and redundancy can be reported as unassessed rather than
	// guessed.
	Denied map[string]string
	// RestoreTestingTypes are resource types covered by a restore-testing plan.
	// AWS reports plans at account level per region.
	RestoreTestingPlans int
}

// LoadVaults enumerates vaults across the given regions and reads each one's
// lock state. This is what makes cross-region redundancy answerable: a resource
// in ap-southeast-1 whose recovery point also sits in a us-east-1 vault is
// genuinely redundant.
func LoadVaults(ctx context.Context, p Provider, regions []string) *VaultIndex {
	idx := &VaultIndex{
		ByRegion: map[string][]Vault{},
		Denied:   map[string]string{},
	}

	for _, region := range regions {
		c := p.For(region)
		var token *string
		var vaults []Vault

		for {
			page, err := c.Backup.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{NextToken: token})
			if err != nil {
				reason := "backup:ListBackupVaults denied"
				if !IsAccessDenied(err) {
					reason = "backup:ListBackupVaults failed: " + firstLine(err.Error())
				}
				idx.Denied[region] = reason
				break
			}
			for _, v := range page.BackupVaultList {
				vault := Vault{
					Name:   awssdk.ToString(v.BackupVaultName),
					ARN:    awssdk.ToString(v.BackupVaultArn),
					Region: region,
					Locked: model.Unknown,
				}
				// The list response carries Locked for most vault types, but
				// DescribeBackupVault is authoritative.
				if v.Locked != nil {
					vault.Locked = boolToTristate(*v.Locked)
					vault.LockDate = v.LockDate
				}
				if vault.Locked == model.Unknown {
					if d, err := c.Backup.DescribeBackupVault(ctx, &backup.DescribeBackupVaultInput{
						BackupVaultName: v.BackupVaultName,
					}); err == nil {
						if d.Locked != nil {
							vault.Locked = boolToTristate(*d.Locked)
						}
						vault.LockDate = d.LockDate
					}
				}
				vaults = append(vaults, vault)
			}
			if page.NextToken == nil || *page.NextToken == "" {
				break
			}
			token = page.NextToken
		}

		if len(vaults) > 0 {
			idx.ByRegion[region] = vaults
		}

		// Restore-testing plans are the strongest available signal that a team
		// is testing restores rather than assuming them.
		if plans, err := c.Backup.ListRestoreTestingPlans(ctx, &backup.ListRestoreTestingPlansInput{}); err == nil {
			idx.RestoreTestingPlans += len(plans.RestoreTestingPlans)
		}
	}

	return idx
}

func boolToTristate(b bool) model.Tristate {
	if b {
		return model.Yes
	}
	return model.No
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// GatherBackupState assembles everything the checks need about one resource.
//
// The evidence comes from AWS Backup recovery points where possible, because
// they are the only source that reports lock state, cross-region copies, and
// restore history together. Native snapshots are consulted as a fallback so a
// team not using AWS Backup is not reported as having no backups at all.
func GatherBackupState(
	ctx context.Context,
	p Provider,
	res model.Resource,
	idx *VaultIndex,
	accountID string,
) *model.BackupState {
	return GatherBackupStateInto(ctx, p, res, idx, accountID, model.NewBackupState())
}

// GatherBackupStateInto merges AWS Backup evidence into a state that discovery
// may already have populated.
//
// Buckets and tables arrive with their S3/DynamoDB posture already read (see
// Buckets and Tables), and resetting Immutable/CrossRegion to Unknown — or
// clearing state.S3/state.Dynamo — here would silently discard that work. That
// reads downstream as "configuration not read" on every single bucket, even
// though discovery genuinely read it. So this only ever tightens Unknown into
// a real answer; it never overwrites an answer discovery already gave.
func GatherBackupStateInto(
	ctx context.Context,
	p Provider,
	res model.Resource,
	idx *VaultIndex,
	accountID string,
	state *model.BackupState,
) *model.BackupState {
	// The old body of this function unconditionally reset Immutable/CrossRegion
	// to Unknown here. Unknown is already the zero value on a fresh state, so
	// that was a no-op for GatherBackupState's own callers — but for a state
	// discovery already populated (S3 Object Lock, replication) it would have
	// silently stomped a real Yes/No back to Unknown. Deliberately not done:
	// both fields are left exactly as the caller passed them in, and only
	// tightened below when this function itself finds evidence.
	state.RestoreTestingConfigured = idx.RestoreTestingPlans > 0

	// --- AWS Backup recovery points, searched across every visible vault ---
	anyVaultVisible := false
	lockedSeen, unlockedSeen := false, false
	regionsWithCopies := map[string]bool{}
	var latest *time.Time
	var lastRestore *time.Time
	var keyARNs []string
	points := 0

	if res.ARN != "" {
		for region, vaults := range idx.ByRegion {
			c := p.For(region)
			for _, vault := range vaults {
				anyVaultVisible = true
				var token *string
				for {
					page, err := c.Backup.ListRecoveryPointsByBackupVault(ctx, &backup.ListRecoveryPointsByBackupVaultInput{
						BackupVaultName: awssdk.String(vault.Name),
						ByResourceArn:   awssdk.String(res.ARN),
						NextToken:       token,
					})
					if err != nil {
						if IsAccessDenied(err) {
							state.MarkUnassessed(model.CheckCoverage,
								"backup:ListRecoveryPointsByBackupVault denied")
						}
						break
					}
					for _, rp := range page.RecoveryPoints {
						if rp.Status != backuptypes.RecoveryPointStatusCompleted {
							continue
						}
						points++
						regionsWithCopies[region] = true

						if rp.EncryptionKeyArn != nil {
							keyARNs = append(keyARNs, *rp.EncryptionKeyArn)
						}

						switch vault.Locked {
						case model.Yes:
							lockedSeen = true
						case model.No:
							unlockedSeen = true
						case model.Unknown:
							// Neither: an unreadable lock state must not count
							// as evidence in either direction.
						}

						when := rp.CompletionDate
						if when == nil {
							when = rp.CreationDate
						}
						if when != nil && (latest == nil || when.After(*latest)) {
							latest = when
						}
						// The restore-history signal the whole product turns on.
						if rp.LastRestoreTime != nil &&
							(lastRestore == nil || rp.LastRestoreTime.After(*lastRestore)) {
							lastRestore = rp.LastRestoreTime
						}
					}
					if page.NextToken == nil || *page.NextToken == "" {
						break
					}
					token = page.NextToken
				}
			}
		}
	}

	// --- Native snapshot fallback ---
	// Only consulted when AWS Backup showed nothing, so a team using plain
	// snapshots still gets accurate coverage and freshness.
	if points == 0 {
		nativePoints, nativeLatest, nativeKeyARNs := nativeSnapshots(ctx, p, res, state)
		if nativePoints > 0 {
			points = nativePoints
			if nativeLatest != nil && (latest == nil || nativeLatest.After(*latest)) {
				latest = nativeLatest
			}
			keyARNs = append(keyARNs, nativeKeyARNs...)
			regionsWithCopies[res.Region] = true
			// Native EBS/RDS snapshots are not on WORM storage. That is a
			// known negative, not an unknown.
			unlockedSeen = true
			state.Notes = append(state.Notes,
				"backups found as native snapshots rather than AWS Backup recovery points")
		}
	}

	state.RecoveryPoints = points
	state.LatestBackupAt = latest
	state.LastRestoreAt = lastRestore

	resolveKeys(ctx, p, accountID, keyARNs, res.Region, state)

	// --- Immutability ---
	switch {
	case lockedSeen:
		state.Immutable = model.Yes
	case unlockedSeen:
		state.Immutable = model.No
	case !anyVaultVisible && len(idx.Denied) > 0:
		state.MarkUnassessed(model.CheckImmutability, denialReason(idx))
	}

	// --- Cross-region redundancy ---
	if points > 0 {
		other := false
		for region := range regionsWithCopies {
			if region != res.Region {
				other = true
				break
			}
		}
		if other {
			state.CrossRegion = model.Yes
		} else if len(idx.Denied) == 0 {
			state.CrossRegion = model.No
		} else {
			state.MarkUnassessed(model.CheckRedundancy, denialReason(idx))
		}
	}

	// RDS with automated backups disabled is a coverage fact worth stating
	// explicitly, since it is the single most common cause of "no backup".
	if retention, ok := res.Attrs["backup_retention_days"]; ok && retention == "0" {
		state.Notes = append(state.Notes, "automated backups are disabled (retention 0 days)")
	}

	return state
}

func denialReason(idx *VaultIndex) string {
	for _, reason := range idx.Denied {
		return reason
	}
	return "backup vault enumeration denied"
}

// nativeSnapshots counts EBS/RDS snapshots owned by this account for the
// resource, as the fallback coverage signal. It also returns the KMS key ARNs
// those snapshots were encrypted with, since AWS Backup showing nothing is
// exactly the case resolveKeys still needs a key source for.
func nativeSnapshots(
	ctx context.Context,
	p Provider,
	res model.Resource,
	state *model.BackupState,
) (int, *time.Time, []string) {
	c := p.For(res.Region)
	var latest *time.Time
	var keyARNs []string
	count := 0

	switch res.Type {
	case model.TypeVolume:
		volumeID := res.Attrs["volume_id"]
		if volumeID == "" {
			return 0, nil, nil
		}
		out, err := c.EC2.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
			OwnerIds: []string{"self"},
			Filters: []ec2types.Filter{{
				Name:   awssdk.String("volume-id"),
				Values: []string{volumeID},
			}},
		})
		if err != nil {
			if IsAccessDenied(err) {
				state.MarkUnassessed(model.CheckCoverage, "ec2:DescribeSnapshots denied")
			}
			return 0, nil, nil
		}
		for _, s := range out.Snapshots {
			if s.State != ec2types.SnapshotStateCompleted {
				continue
			}
			count++
			if s.StartTime != nil && (latest == nil || s.StartTime.After(*latest)) {
				latest = s.StartTime
			}
			if s.KmsKeyId != nil {
				keyARNs = append(keyARNs, *s.KmsKeyId)
			}
		}

	case model.TypeDatabase:
		out, err := c.RDS.DescribeDBSnapshots(ctx, &rds.DescribeDBSnapshotsInput{
			DBInstanceIdentifier: awssdk.String(res.Name),
		})
		if err != nil {
			if IsAccessDenied(err) {
				state.MarkUnassessed(model.CheckCoverage, "rds:DescribeDBSnapshots denied")
			}
			return 0, nil, nil
		}
		for _, s := range out.DBSnapshots {
			if awssdk.ToString(s.Status) != "available" {
				continue
			}
			count++
			if s.SnapshotCreateTime != nil && (latest == nil || s.SnapshotCreateTime.After(*latest)) {
				latest = s.SnapshotCreateTime
			}
			if s.KmsKeyId != nil {
				keyARNs = append(keyARNs, *s.KmsKeyId)
			}
		}

	case model.TypeDBCluster:
		out, err := c.RDS.DescribeDBClusterSnapshots(ctx, &rds.DescribeDBClusterSnapshotsInput{
			DBClusterIdentifier: awssdk.String(res.Name),
		})
		if err != nil {
			if IsAccessDenied(err) {
				state.MarkUnassessed(model.CheckCoverage, "rds:DescribeDBClusterSnapshots denied")
			}
			return 0, nil, nil
		}
		for _, s := range out.DBClusterSnapshots {
			if awssdk.ToString(s.Status) != "available" {
				continue
			}
			count++
			if s.SnapshotCreateTime != nil && (latest == nil || s.SnapshotCreateTime.After(*latest)) {
				latest = s.SnapshotCreateTime
			}
			if s.KmsKeyId != nil {
				keyARNs = append(keyARNs, *s.KmsKeyId)
			}
		}
	}

	return count, latest, keyARNs
}
