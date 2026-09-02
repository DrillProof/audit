package score

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/drillproof/audit/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func finding(check model.CheckID, status model.Status, r model.Resource) model.Finding {
	return model.Finding{Resource: r, Check: check, Status: status}
}

var (
	vol      = model.Resource{Display: "orders-pv", Type: model.TypeVolume, Region: "ap-southeast-1"}
	prodDB   = model.Resource{Display: "payments-db", Type: model.TypeDatabase, Region: "ap-southeast-1", Production: true}
	stateRes = model.Resource{Display: "etcd (prod-cluster)", Type: model.TypeK8sState, Region: "ap-southeast-1"}
)

func TestPerfectEstateScores100(t *testing.T) {
	var findings []model.Finding
	for _, c := range model.AllChecks {
		findings = append(findings, finding(c, model.StatusOK, vol))
	}
	s := Compute(findings)
	assert.Equal(t, 100, s.Value)
	assert.Equal(t, 0, s.CriticalGaps)
	assert.Empty(t, s.Penalties)
}

func TestCoverageFailZeroesTheResource(t *testing.T) {
	s := Compute([]model.Finding{finding(model.CheckCoverage, model.StatusFail, vol)})

	assert.Equal(t, 0, s.Value, "a lone resource with no backup is 0% recoverable")
	assert.Equal(t, 1, s.CriticalGaps)
	assert.Equal(t, WeightCoverageFail, s.RawDeduction, "raw deduction keeps the absolute depth")
	require.Len(t, s.ResourceScores, 1)
	assert.Equal(t, 0, s.ResourceScores[0].Score)
}

// A resource with a backup that is stale, deletable, single-region and never
// test-restored keeps credit for existing at all: 100 - 8 - 10 - 6 - 5.
func TestQualityGapsDeductFromTheResource(t *testing.T) {
	s := Compute([]model.Finding{
		finding(model.CheckCoverage, model.StatusOK, vol),
		finding(model.CheckFreshness, model.StatusFail, vol),
		finding(model.CheckImmutability, model.StatusFail, vol),
		finding(model.CheckRedundancy, model.StatusFail, vol),
		finding(model.CheckRestoreTested, model.StatusFail, vol),
	})

	assert.Equal(t, 71, s.Value)
}

// The +10 critical bonus no longer moves the resource score (an unbacked
// resource is 0 either way), so criticality has to survive as weight in the
// estate mean instead. One perfect volume plus one unbacked resource:
//
//	plain    (100*1 + 0*1) / 2 = 50
//	critical (100*1 + 0*2) / 3 = 33
func TestCriticalResourcesWeighDoubleInTheEstate(t *testing.T) {
	perfect := []model.Finding{}
	for _, c := range model.AllChecks {
		perfect = append(perfect, finding(c, model.StatusOK, vol))
	}
	other := model.Resource{Display: "spare-vol", Type: model.TypeVolume, Region: "ap-southeast-1"}

	plain := Compute(append(append([]model.Finding{}, perfect...),
		finding(model.CheckCoverage, model.StatusFail, other)))
	critical := Compute(append(append([]model.Finding{}, perfect...),
		finding(model.CheckCoverage, model.StatusFail, stateRes)))

	assert.Equal(t, 50, plain.Value)
	assert.Equal(t, 33, critical.Value, "an unbacked critical resource must drag the estate further")
	assert.Less(t, critical.Value, plain.Value)
}

// Under absolute deductions this asserted 100-25=75. A lone resource with no
// backup is now 0 regardless of the bonus (it is unrecoverable either way), so
// the no-bonus invariant is only visible in RawDeduction now.
func TestNonProductionDatabaseIsNotBonusPenalised(t *testing.T) {
	devDB := model.Resource{Display: "dev-db", Type: model.TypeDatabase, Production: false}
	s := Compute([]model.Finding{finding(model.CheckCoverage, model.StatusFail, devDB)})
	assert.Equal(t, 0, s.Value)
	assert.Equal(t, WeightCoverageFail, s.RawDeduction, "no critical bonus for a non-production database")
}

func TestWeightOrderingMatchesSpec(t *testing.T) {
	// The spec fixes this ordering: coverage > immutability > freshness >
	// redundancy > untested-restore.
	assert.Greater(t, WeightCoverageFail, WeightImmutabilityFail)
	assert.Greater(t, WeightImmutabilityFail, WeightFreshnessFail)
	assert.Greater(t, WeightFreshnessFail, WeightRedundancyFail)
	assert.Greater(t, WeightRedundancyFail, WeightRestoreUntested)
	assert.Greater(t, WeightFreshnessFail, WeightFreshnessWarn)
}

func TestSkippedChecksNeitherPenaliseNorCount(t *testing.T) {
	s := Compute([]model.Finding{
		finding(model.CheckCoverage, model.StatusOK, vol),
		finding(model.CheckImmutability, model.StatusSkipped, vol),
	})
	assert.Equal(t, 100, s.Value)
	assert.Equal(t, 1, s.Skipped)
	assert.Equal(t, 1, s.Assessed)
}

func TestNothingAssessableScoresZeroNotPerfect(t *testing.T) {
	// A user with no permissions must never be told their estate is perfect.
	s := Compute([]model.Finding{
		finding(model.CheckCoverage, model.StatusSkipped, vol),
		finding(model.CheckImmutability, model.StatusSkipped, vol),
	})
	assert.Equal(t, 0, s.Value)
	assert.Equal(t, 0, s.Assessed)
}

func TestScoreIsClampedAtZero(t *testing.T) {
	var findings []model.Finding
	for i := 0; i < 20; i++ {
		findings = append(findings, finding(model.CheckCoverage, model.StatusFail, stateRes))
	}
	s := Compute(findings)
	assert.Equal(t, 0, s.Value)
	assert.Greater(t, s.RawDeduction, 100, "raw deduction should still show the true depth of the problem")
}

func TestDeterministicRegardlessOfInputOrder(t *testing.T) {
	a := []model.Finding{
		finding(model.CheckCoverage, model.StatusFail, stateRes),
		finding(model.CheckImmutability, model.StatusFail, prodDB),
		finding(model.CheckRestoreTested, model.StatusFail, vol),
	}
	b := []model.Finding{a[2], a[0], a[1]}

	sa, sb := Compute(a), Compute(b)
	assert.Equal(t, sa.Value, sb.Value)
	assert.Equal(t, sa.CriticalGaps, sb.CriticalGaps)
	require.Equal(t, len(sa.Penalties), len(sb.Penalties))
	for i := range sa.Penalties {
		assert.Equal(t, sa.Penalties[i], sb.Penalties[i], "penalty ordering must be stable")
	}
}

func TestPenaltiesSortedHeaviestFirst(t *testing.T) {
	s := Compute([]model.Finding{
		finding(model.CheckRestoreTested, model.StatusFail, vol),
		finding(model.CheckCoverage, model.StatusFail, stateRes),
		finding(model.CheckRedundancy, model.StatusFail, vol),
	})
	require.Len(t, s.Penalties, 3)
	for i := 1; i < len(s.Penalties); i++ {
		assert.GreaterOrEqual(t, s.Penalties[i-1].Points, s.Penalties[i].Points)
	}
}

func TestWarnCountsAsPenaltyButNotCriticalGap(t *testing.T) {
	s := Compute([]model.Finding{finding(model.CheckFreshness, model.StatusWarn, vol)})
	assert.Equal(t, 100-WeightFreshnessWarn, s.Value)
	assert.Equal(t, 0, s.CriticalGaps, "a warning is not a critical gap")
}

// skipped builds a moot skip — the normal outcome for a check with nothing to
// assess, as opposed to one a permission blocked.
func skipped(c model.CheckID, r model.Resource) model.Finding {
	return model.Finding{Resource: r, Check: c, Status: model.StatusSkipped}
}

// estateWithGaps builds findings for `unbacked` resources with no backup at all
// (whose other four checks are therefore moot) and `untested` resources that
// are fully backed up but never test-restored.
func estateWithGaps(unbacked, untested int) []model.Finding {
	var f []model.Finding
	for i := 0; i < unbacked; i++ {
		r := model.Resource{Display: fmt.Sprintf("gap-%03d", i), Type: model.TypeVolume, Region: "eu-west-1"}
		f = append(f,
			finding(model.CheckCoverage, model.StatusFail, r),
			skipped(model.CheckFreshness, r),
			skipped(model.CheckImmutability, r),
			skipped(model.CheckRedundancy, r),
			skipped(model.CheckRestoreTested, r),
		)
	}
	for i := 0; i < untested; i++ {
		r := model.Resource{Display: fmt.Sprintf("ok-%03d", i), Type: model.TypeVolume, Region: "eu-west-1"}
		f = append(f,
			finding(model.CheckCoverage, model.StatusOK, r),
			finding(model.CheckFreshness, model.StatusOK, r),
			finding(model.CheckImmutability, model.StatusOK, r),
			finding(model.CheckRedundancy, model.StatusOK, r),
			finding(model.CheckRestoreTested, model.StatusFail, r),
		)
	}
	return f
}

// The bug this whole change exists to fix. Four unprotected resources among a
// hundred is a 96%-protected estate; with absolute weights it scored 0, the
// same as an estate with nothing backed up at all. Doubling every resource must
// not move the score.
func TestScoreIsIndependentOfEstateSize(t *testing.T) {
	small := Compute(estateWithGaps(4, 96))
	doubled := Compute(estateWithGaps(8, 192))

	assert.Equal(t, 91, small.Value, "4 unprotected + 96 backed-but-untested")
	assert.Equal(t, small.Value, doubled.Value, "doubling the estate must not move the score")
	// CriticalGaps and RawDeduction count every failing check, not just the
	// unbacked resources: 4 coverage fails + 96 untested-restore fails = 100
	// gaps, and 4*25 + 96*5 = 580 points of absolute deduction. Both still
	// scale with estate size — only Value is size-independent.
	assert.Equal(t, 100, small.CriticalGaps)
	assert.Equal(t, 580, small.RawDeduction, "raw deduction still records absolute depth")
}

// "Not assessed is never a pass" — and never a fail either. A resource we could
// not look at drops out of the mean rather than scoring 0, which would report a
// permission gap as a recoverability gap.
func TestResourceWithOnlySkippedChecksIsExcluded(t *testing.T) {
	perfect := []model.Finding{}
	for _, c := range model.AllChecks {
		perfect = append(perfect, finding(c, model.StatusOK, vol))
	}
	blind := model.Resource{Display: "unreadable-vol", Type: model.TypeVolume, Region: "ap-southeast-1"}
	f := append(perfect, model.Finding{
		Resource: blind, Check: model.CheckCoverage,
		Status: model.StatusSkipped, SkipIsAccessGap: true,
	})

	s := Compute(f)

	assert.Equal(t, 100, s.Value, "the estate is what we could see, and what we saw was perfect")
	assert.Equal(t, 1, s.Blocked)
	require.Len(t, s.ResourceScores, 1)
	assert.Equal(t, "orders-pv", s.ResourceScores[0].Resource)
}

func TestNothingAssessableScoresZero(t *testing.T) {
	s := Compute([]model.Finding{{
		Resource: vol, Check: model.CheckCoverage,
		Status: model.StatusSkipped, SkipIsAccessGap: true,
	}})

	assert.Equal(t, 0, s.Value, "an account we cannot read is not an account with perfect backups")
	assert.Empty(t, s.ResourceScores)
}

// 50 unprotected + 50 backed-but-untested is a weighted mean of exactly 47.5.
// Half-up must give 48 here and in the TypeScript port.
func TestRoundingIsHalfUp(t *testing.T) {
	assert.Equal(t, 48, Compute(estateWithGaps(50, 50)).Value)
}

func TestScoreIsDeterministicUnderShuffle(t *testing.T) {
	f := estateWithGaps(3, 7)
	want := Compute(f)

	shuffled := append([]model.Finding{}, f...)
	rand.New(rand.NewSource(1)).Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	got := Compute(shuffled)

	assert.Equal(t, want.Value, got.Value)
	assert.Equal(t, want.ResourceScores, got.ResourceScores, "per-resource output must not depend on input order")
	assert.Equal(t, want.Penalties, got.Penalties)
}

func TestExplainShowsTheArithmetic(t *testing.T) {
	// One perfect volume and one unbacked cluster state: (100*1 + 0*2)/3 = 33.
	perfect := []model.Finding{}
	for _, c := range model.AllChecks {
		perfect = append(perfect, finding(c, model.StatusOK, vol))
	}
	s := Compute(append(perfect, finding(model.CheckCoverage, model.StatusFail, stateRes)))

	joined := ""
	for _, l := range Explain(s) {
		joined += l + "\n"
	}

	assert.Contains(t, joined, "Per-resource recoverability")
	assert.Contains(t, joined, "etcd (prod-cluster)")
	assert.Contains(t, joined, "counts 2x", "the reader must see why a critical resource moved the score further")
	assert.Contains(t, joined, "Recoverability Score: 33/100")
	assert.Contains(t, joined, "weighted mean of 2 resource(s)")
	assert.Contains(t, joined, "Total raw deduction: 35")
	assert.NotContains(t, joined, "Starting score: 100", "that arithmetic no longer produces the value")
}
