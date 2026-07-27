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
func Compute(findings []model.Finding) model.Score {
	s := model.Score{Value: PerfectScore}

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
	}

	// Sort heaviest first, then by resource, so output is stable.
	sort.SliceStable(s.Penalties, func(i, j int) bool {
		if s.Penalties[i].Points != s.Penalties[j].Points {
			return s.Penalties[i].Points > s.Penalties[j].Points
		}
		return s.Penalties[i].Resource < s.Penalties[j].Resource
	})

	s.Value = PerfectScore - s.RawDeduction
	if s.Value < 0 {
		s.Value = 0
	}

	// Nothing was assessable — report 0 rather than a misleading 100. A user
	// with no permissions must not be told their estate is perfect.
	if s.Assessed == 0 {
		s.Value = 0
	}

	return s
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
	return r.Production && (r.Type == model.TypeDatabase || r.Type == model.TypeDBCluster)
}

// Explain renders the score arithmetic as lines suitable for a report or
// `--explain`. The point is that a skeptical engineer can check our maths.
func Explain(s model.Score) []string {
	lines := []string{
		fmt.Sprintf("Starting score: %d", PerfectScore),
	}
	for _, p := range s.Penalties {
		lines = append(lines, fmt.Sprintf("  -%-3d %s — %s (%s)", p.Points, p.Resource, p.Reason, p.Check))
	}
	if len(s.Penalties) == 0 {
		lines = append(lines, "  (no deductions)")
	}
	lines = append(lines,
		fmt.Sprintf("Total deduction: %d", s.RawDeduction),
		fmt.Sprintf("Recoverability Score: %d/100", s.Value),
		fmt.Sprintf("Checks assessed: %d — %d blocked by permissions, %d not applicable",
			s.Assessed, s.Blocked, s.Moot),
	)
	return lines
}
