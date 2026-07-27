package aws

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/drillproof/audit/internal/checks"
	"github.com/drillproof/audit/internal/k8s"
	"github.com/drillproof/audit/internal/model"
	"github.com/drillproof/audit/internal/score"
)

// ScanOptions controls a scan.
type ScanOptions struct {
	Regions []string
	Checks  checks.Config
	Version string
	// Concurrency caps parallel region work. AWS throttles readily, so this is
	// deliberately modest.
	Concurrency int
	// Cluster carries optional in-cluster evidence for the cluster-state check.
	// Nil means no --kubeconfig was given, in which case cluster state is
	// reported as "not assessed" rather than guessed at.
	Cluster *k8s.State
}

// DefaultConcurrency is a compromise between a fast scan and AWS rate limits.
const DefaultConcurrency = 4

// Scan runs the full read-only audit and returns a complete Result.
//
// Failure policy throughout: a denied or failing call degrades that one check
// to "not assessed" and records a warning. Nothing here is allowed to crash the
// scan or hang it — a partial, honest answer beats no answer.
func Scan(ctx context.Context, p Provider, opts ScanOptions) (*model.Result, error) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.Checks.Now.IsZero() {
		opts.Checks = checks.DefaultConfig()
	}

	identity, err := WhoAmI(ctx, p.STS())
	if err != nil {
		return nil, err
	}

	result := &model.Result{
		AccountID:   identity.AccountID,
		AccountArn:  identity.ARN,
		GeneratedAt: opts.Checks.Now,
		Version:     opts.Version,
	}

	regions := opts.Regions
	if len(regions) == 0 {
		base := p.For(p.BaseRegion())
		regions, err = EnabledRegions(ctx, base.EC2, p.BaseRegion())
		if err != nil {
			return nil, err
		}
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("scanned all %d enabled regions; narrow with --region", len(regions)))
	}
	result.Regions = regions

	// Vault index first: cross-region redundancy cannot be answered per-region.
	vaults := LoadVaults(ctx, p, regions)
	for region, reason := range vaults.Denied {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("%s: %s — immutability and redundancy not assessed there", region, reason))
	}

	// --- Inventory, in parallel across regions ---
	type regionResult struct {
		resources []model.Resource
		warnings  []string
	}

	var (
		mu        sync.Mutex
		collected []regionResult
		wg        sync.WaitGroup
		sem       = make(chan struct{}, opts.Concurrency)
	)

	for _, region := range regions {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			c := p.For(region)
			rr := regionResult{}

			if vols, err := Volumes(ctx, c, identity.AccountID); err != nil {
				rr.warnings = append(rr.warnings, describeFailure(region, "ec2:DescribeVolumes", err))
			} else {
				rr.resources = append(rr.resources, vols...)
			}

			if dbs, err := Databases(ctx, c); err != nil {
				rr.warnings = append(rr.warnings, describeFailure(region, "rds:Describe*", err))
			} else {
				rr.resources = append(rr.resources, dbs...)
			}

			if cl, err := Clusters(ctx, c); err != nil {
				rr.warnings = append(rr.warnings, describeFailure(region, "eks:ListClusters", err))
			} else {
				rr.resources = append(rr.resources, cl...)
			}

			mu.Lock()
			collected = append(collected, rr)
			mu.Unlock()
		}(region)
	}
	wg.Wait()

	var resources []model.Resource
	for _, rr := range collected {
		resources = append(resources, rr.resources...)
		result.Warnings = append(result.Warnings, rr.warnings...)
	}

	// Stable ordering so output and score are reproducible run to run.
	sort.SliceStable(resources, func(i, j int) bool {
		if resources[i].Region != resources[j].Region {
			return resources[i].Region < resources[j].Region
		}
		if resources[i].Type != resources[j].Type {
			return resources[i].Type < resources[j].Type
		}
		return resources[i].Display < resources[j].Display
	})

	// --- Evidence + checks per resource ---
	for _, res := range resources {
		state := GatherBackupState(ctx, p, res, vaults)

		// Cluster state is the one resource type AWS cannot answer for. Merge
		// in-cluster evidence when we have it, and be explicit when we do not.
		if res.Type == model.TypeK8sState {
			applyClusterEvidence(res, state, opts.Cluster, result)
		}

		findings := checks.Run(res, state, opts.Checks)

		statuses := make(map[model.CheckID]model.Status, len(findings))
		for _, f := range findings {
			statuses[f.Check] = f.Status
		}

		result.Rows = append(result.Rows, model.Row{
			Resource: res,
			State:    state,
			Statuses: statuses,
		})
		result.Findings = append(result.Findings, findings...)
	}

	result.Score = score.Compute(result.Findings)

	sort.Strings(result.Warnings)
	return result, nil
}

// applyClusterEvidence merges Velero findings into a cluster-state resource.
//
// The honesty rule here matters more than the mechanics: without --kubeconfig we
// have not looked inside the cluster, so we must not claim its state is
// unbacked. AWS Backup genuinely cannot see Velero backups, so "no recovery
// points in AWS" is not evidence of "no cluster backup".
func applyClusterEvidence(
	res model.Resource,
	state *model.BackupState,
	cluster *k8s.State,
	result *model.Result,
) {
	if cluster == nil {
		if state.RecoveryPoints == 0 {
			state.MarkUnassessed(model.CheckCoverage,
				"cluster state needs in-cluster access; pass --kubeconfig")
			state.Notes = append(state.Notes,
				"AWS Backup cannot see Velero backups — rerun with --kubeconfig to assess cluster state")
		}
		return
	}

	if cluster.Unassessed != "" {
		state.MarkUnassessed(model.CheckCoverage, cluster.Unassessed)
		return
	}

	// Only credit this cluster if the kubeconfig plausibly points at it.
	if !cluster.MatchesCluster(res.Name) {
		state.MarkUnassessed(model.CheckCoverage,
			fmt.Sprintf("kubeconfig points at %q, not this cluster", cluster.ClusterName))
		return
	}

	if !cluster.VeleroInstalled {
		// A real negative: we looked, and nothing is backing this state up.
		state.Notes = append(state.Notes, "Velero is not installed in this cluster")
		return
	}

	state.RecoveryPoints += cluster.CompletedBackups
	if cluster.LatestBackupAt != nil &&
		(state.LatestBackupAt == nil || cluster.LatestBackupAt.After(*state.LatestBackupAt)) {
		state.LatestBackupAt = cluster.LatestBackupAt
	}
	if cluster.LatestRestoreAt != nil &&
		(state.LastRestoreAt == nil || cluster.LatestRestoreAt.After(*state.LastRestoreAt)) {
		state.LastRestoreAt = cluster.LatestRestoreAt
	}
	state.Notes = append(state.Notes, cluster.Summary())

	// Velero writes to object storage whose lock posture we have not inspected
	// per-backup, and its backup location is a separate concern from AWS Backup
	// vaults. Say so rather than inferring either way.
	if state.Immutable == model.Unknown {
		state.MarkUnassessed(model.CheckImmutability,
			"Velero backup storage location lock state not inspected")
	}
	if state.CrossRegion == model.Unknown {
		state.MarkUnassessed(model.CheckRedundancy,
			"Velero backup storage location region not inspected")
	}
	if cluster.Schedules == 0 && cluster.CompletedBackups > 0 {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("%s: Velero has backups but no Schedule — these may be one-off, manual backups", res.Name))
	}
}

func describeFailure(region, op string, err error) string {
	if IsAccessDenied(err) {
		return fmt.Sprintf("%s: %s denied — those resources were not inventoried", region, op)
	}
	if code := ErrorCode(err); code != "" {
		return fmt.Sprintf("%s: %s failed (%s)", region, op, code)
	}
	return fmt.Sprintf("%s: %s failed: %s", region, op, firstLine(err.Error()))
}

// TopFindings selects the findings worth printing under the score: failures
// first, then warnings, heaviest checks before lighter ones.
func TopFindings(result *model.Result, limit int) []model.Finding {
	weight := map[model.CheckID]int{
		model.CheckCoverage:      5,
		model.CheckImmutability:  4,
		model.CheckFreshness:     3,
		model.CheckRedundancy:    2,
		model.CheckRestoreTested: 1,
	}
	statusRank := map[model.Status]int{
		model.StatusFail: 2,
		model.StatusWarn: 1,
	}

	var notable []model.Finding
	for _, f := range result.Findings {
		if f.Status == model.StatusFail || f.Status == model.StatusWarn {
			notable = append(notable, f)
		}
	}

	sort.SliceStable(notable, func(i, j int) bool {
		if statusRank[notable[i].Status] != statusRank[notable[j].Status] {
			return statusRank[notable[i].Status] > statusRank[notable[j].Status]
		}
		if weight[notable[i].Check] != weight[notable[j].Check] {
			return weight[notable[i].Check] > weight[notable[j].Check]
		}
		return notable[i].Resource.Display < notable[j].Resource.Display
	})

	if limit > 0 && len(notable) > limit {
		notable = notable[:limit]
	}
	return notable
}

// CountUntested reports how many resources have backups that were never
// test-restored. This is the number the report leads with.
func CountUntested(result *model.Result) int {
	n := 0
	for _, f := range result.Findings {
		if f.Check == model.CheckRestoreTested && f.Status == model.StatusFail {
			n++
		}
	}
	return n
}

// ScanDuration is a convenience for reporting.
func ScanDuration(start time.Time) time.Duration {
	return time.Since(start).Round(time.Millisecond)
}
