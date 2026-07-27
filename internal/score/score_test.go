package score

import (
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

func TestCoverageDominates(t *testing.T) {
	s := Compute([]model.Finding{finding(model.CheckCoverage, model.StatusFail, vol)})
	assert.Equal(t, 100-WeightCoverageFail, s.Value)
	assert.Equal(t, 1, s.CriticalGaps)
}

func TestCriticalResourcesCostMore(t *testing.T) {
	plain := Compute([]model.Finding{finding(model.CheckCoverage, model.StatusFail, vol)})
	state := Compute([]model.Finding{finding(model.CheckCoverage, model.StatusFail, stateRes)})
	prod := Compute([]model.Finding{finding(model.CheckCoverage, model.StatusFail, prodDB)})

	assert.Less(t, state.Value, plain.Value, "unbacked cluster state must cost more than an unbacked volume")
	assert.Less(t, prod.Value, plain.Value, "unbacked production database must cost more than a volume")
	assert.Equal(t, 100-WeightCoverageFail-WeightCoverageCriticalBonus, state.Value)
}

func TestNonProductionDatabaseIsNotBonusPenalised(t *testing.T) {
	devDB := model.Resource{Display: "dev-db", Type: model.TypeDatabase, Production: false}
	s := Compute([]model.Finding{finding(model.CheckCoverage, model.StatusFail, devDB)})
	assert.Equal(t, 100-WeightCoverageFail, s.Value)
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

func TestExplainShowsTheArithmetic(t *testing.T) {
	s := Compute([]model.Finding{finding(model.CheckCoverage, model.StatusFail, stateRes)})
	lines := Explain(s)
	joined := ""
	for _, l := range lines {
		joined += l + "\n"
	}
	assert.Contains(t, joined, "Starting score: 100")
	assert.Contains(t, joined, "etcd (prod-cluster)")
	assert.Contains(t, joined, "Total deduction: 35")
	assert.Contains(t, joined, "Recoverability Score: 65/100")
}
