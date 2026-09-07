// Package score turns findings into the Recoverability Score.
//
// # Why the weights are what they are
//
// The score answers one question: "if I lost this resource right now, how
// likely is it that I get it back?" The weights follow that question, in the
// order the spec fixes them:
//
//	Coverage      A resource with no backup at all is unrecoverable. Nothing
//	              else about it matters, so this dominates. Cluster state
//	              (etcd) and production databases carry an extra penalty
//	              because losing them is unrecoverable in a way a rebuildable
//	              volume is not.
//	Immutability  A backup an attacker (or a bad script) can delete is a
//	              backup you may not have during the incident that needs it.
//	Freshness     A stale backup is a real backup, just an expensive one — you
//	              lose the delta. Silent schedule failure is the common cause,
//	              so age is graded rather than binary.
//	Redundancy    A backup in the same region as the resource survives most
//	              incidents but not a region-level one.
//	RestoreTested An untested restore is the assumption this whole tool exists
//	              to challenge. It is weighted last not because it matters
//	              least, but because it is the one gap that is *universal* —
//	              penalising it heavily would flatten every score to zero and
//	              destroy the signal that makes the rest actionable.
//
// Every weight is a named constant, the arithmetic is pure, and every
// deduction is returned as a Penalty carrying its own reason. `report` prints
// them. If the score is ever wrong, it is wrong visibly.
package score

import (
	"fmt"
	"sort"

	"github.com/drillproof/audit/internal/model"
)

// Weights are the point deductions per failing check. Tunable in one place;
// changing one of these is a deliberate, reviewable act.
const (
	WeightCoverageFail = 25
	// Applied on top of WeightCoverageFail when the unbacked resource is
	// cluster state or a production database.
	WeightCoverageCriticalBonus = 10

	WeightImmutabilityFail = 10
	WeightFreshnessFail    = 8
	WeightFreshnessWarn    = 4
	WeightRedundancyFail   = 6
	WeightRestoreUntested  = 5
)

// PerfectScore is the ceiling.
const PerfectScore = 100

// Compute derives the score from findings. Deterministic: same findings in any
// order produce the same score, and penalties come back sorted heaviest-first.
//
// The estate score is a criticality-weighted mean of per-resource scores, NOT a
// sum of absolute deductions. With absolute deductions the fourth unbacked
// resource zeroed any account of any size, so a 96%-protected estate reported
// the same 0 as one with nothing backed up. Penalties and RawDeduction are
// unchanged and still carry the absolute arithmetic.
func Compute(findings []model.Finding) model.Score {
	s := model.Score{Value: PerfectScore}

	// One accumulator per resource. `order` preserves first-seen order so the
	// output is deterministic no matter what order regions returned in.
	type acc struct {
		resource     model.Resource
		coverageFail bool
		deduction    int
	}
	byResource := map[string]*acc{}
	var order []string

	for _, f := range findings {
		if f.Status == model.StatusSkipped {
			s.Skipped++
			if f.SkipIsAccessGap {
				s.Blocked++
			} else {
				s.Moot++
			}
			continue
		}
		s.Assessed++

		key := resourceKey(f.Resource)
		a := byResource[key]
		if a == nil {
			a = &acc{resource: f.Resource}
			byResource[key] = a
			order = append(order, key)
		}

		points, reason := weigh(f)
		if points == 0 {
			continue
		}
		if f.Status == model.StatusFail {
			s.CriticalGaps++
		}
		s.Penalties = append(s.Penalties, model.Penalty{
			Check:    f.Check,
			Resource: f.Resource.Display,
			Points:   points,
			Reason:   reason,
		})
		s.RawDeduction += points

		// Coverage is existence: failing it makes the resource unrecoverable,
		// so it zeroes the resource rather than deducting from it. Every other
		// gap is a quality gap against a backup that does exist.
		if f.Check == model.CheckCoverage {
			a.coverageFail = true
		} else {
			a.deduction += points
		}
	}

	// Sort heaviest first, then by resource, so output is stable.
	sort.SliceStable(s.Penalties, func(i, j int) bool {
		if s.Penalties[i].Points != s.Penalties[j].Points {
			return s.Penalties[i].Points > s.Penalties[j].Points
		}
		return s.Penalties[i].Resource < s.Penalties[j].Resource
	})

	weightedSum, totalWeight := 0, 0
	for _, key := range order {
		a := byResource[key]

		value := PerfectScore - a.deduction
		if a.coverageFail {
			value = 0
		}
		if value < 0 {
			value = 0
		}

		weight := 1
		if isCritical(a.resource) {
			weight = 2
		}

		s.ResourceScores = append(s.ResourceScores, model.ResourceScore{
			Resource: a.resource.Display,
			Score:    value,
			Weight:   weight,
		})
		weightedSum += weight * value
		totalWeight += weight
	}

	// Worst first, then by resource: the reader wants the resources dragging
	// the score down, in the order they should be fixed.
	sort.SliceStable(s.ResourceScores, func(i, j int) bool {
		if s.ResourceScores[i].Score != s.ResourceScores[j].Score {
			return s.ResourceScores[i].Score < s.ResourceScores[j].Score
		}
		return s.ResourceScores[i].Resource < s.ResourceScores[j].Resource
	})

	// Round-half-up in integer arithmetic. Float division here is how two
	// implementations drift by a point, and a one-point disagreement between
	// the CLI and the dashboard destroys the credibility of both numbers.
	if totalWeight > 0 {
		s.Value = (2*weightedSum + totalWeight) / (2 * totalWeight)
	}

	// Nothing was assessable — report 0 rather than a misleading 100. A user
	// with no permissions must not be told their estate is perfect.
	if s.Assessed == 0 {
		s.Value = 0
	}

	return s
}

// resourceKey groups findings by the resource they describe.
//
// model.Resource cannot be a map key: Attrs is a map, so the struct is not
// comparable.
//
// Deliberately NOT keyed on the ARN, even though this struct has one. The
// TypeScript Resource has no `arn` — it has `externalId` ("ARN or
// provider-native id"), populated by the app's own stableExternalId() — so
// keying on identifiers would mean the two implementations grouping by
// different values for the same resource. The golden fixtures carry neither
// field, so that divergence would pass every parity test and only surface as
// two different scores for one customer. Type, region and display are present
// and identical on both sides.
//
// The NUL separator keeps two different resources from colliding through a
// field value that happens to contain the delimiter.
func resourceKey(r model.Resource) string {
	return string(r.Type) + "\x00" + r.Region + "\x00" + r.Display
}

// weigh returns the deduction for one finding and the reason to show for it.
func weigh(f model.Finding) (int, string) {
	switch f.Check {
	case model.CheckCoverage:
		if f.Status != model.StatusFail {
			return 0, ""
		}
		points := WeightCoverageFail
		reason := "no backup exists"
		if isCritical(f.Resource) {
			points += WeightCoverageCriticalBonus
			reason = "no backup exists for critical resource"
		}
		return points, reason

	case model.CheckImmutability:
		if f.Status == model.StatusFail {
			return WeightImmutabilityFail, "backups are deletable (no WORM/Object Lock)"
		}
		return 0, ""

	case model.CheckFreshness:
		switch f.Status {
		case model.StatusFail:
			return WeightFreshnessFail, "most recent backup is beyond the failure threshold"
		case model.StatusWarn:
			return WeightFreshnessWarn, "most recent backup is beyond the warning threshold"
		}
		return 0, ""

	case model.CheckRedundancy:
		if f.Status == model.StatusFail {
			return WeightRedundancyFail, "backups exist in only one region"
		}
		return 0, ""

	case model.CheckRestoreTested:
		if f.Status == model.StatusFail {
			return WeightRestoreUntested, "never test-restored"
		}
		return 0, ""
	}
	return 0, ""
}

// isCritical marks resources whose loss is not recoverable by rebuilding.
func isCritical(r model.Resource) bool {
	if r.Type == model.TypeK8sState {
		return true
	}
	return r.Production && (r.Type == model.TypeDatabase ||
		r.Type == model.TypeDBCluster ||
		r.Type == model.TypeBucket ||
		r.Type == model.TypeTable)
}

// Explain renders the score arithmetic as lines suitable for a report or
// `--explain`. The point is that a skeptical engineer can check our maths.
//
// The value is a weighted mean of per-resource scores, so the per-resource
// table is the arithmetic; the deduction list explains how each resource got
// the score it did.
func Explain(s model.Score) []string {
	lines := []string{"Per-resource recoverability:"}
	for _, rs := range s.ResourceScores {
		suffix := ""
		if rs.Weight > 1 {
			suffix = fmt.Sprintf("   (counts %dx: critical resource)", rs.Weight)
		}
		lines = append(lines, fmt.Sprintf("  %3d/100  %s%s", rs.Score, rs.Resource, suffix))
	}
	if len(s.ResourceScores) == 0 {
		lines = append(lines, "  (nothing was assessable)")
	}

	lines = append(lines, "", "Deductions:")
	for _, p := range s.Penalties {
		lines = append(lines, fmt.Sprintf("  -%-3d %s — %s (%s)", p.Points, p.Resource, p.Reason, p.Check))
	}
	if len(s.Penalties) == 0 {
		lines = append(lines, "  (no deductions)")
	}

	lines = append(lines,
		"",
		fmt.Sprintf("Recoverability Score: %d/100  (weighted mean of %d resource(s))",
			s.Value, len(s.ResourceScores)),
		fmt.Sprintf("Total raw deduction: %d", s.RawDeduction),
		fmt.Sprintf("Checks assessed: %d — %d blocked by permissions, %d not applicable",
			s.Assessed, s.Blocked, s.Moot),
	)
	return lines
}
