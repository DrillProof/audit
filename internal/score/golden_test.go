package score

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/drillproof/audit/internal/model"
)

// TestEmitGoldenFixtures writes the canonical scorer inputs/outputs so the
// TypeScript port in the control plane can be proven identical to this one.
//
// The web app and this CLI must never disagree about a customer's score — a
// disagreement would destroy the credibility the whole product rests on. Rather
// than trusting two implementations to stay in step, the Go scorer is the
// source of truth and emits fixtures the TypeScript port is tested against.
//
// Regenerate after any change to weights or scoring logic:
//
//	EMIT_GOLDEN=1 GOLDEN_OUT=../app/packages/shared/src/__fixtures__/scorer-golden.json \
//	  go test -run TestEmitGoldenFixtures ./internal/score/
//
// Skipped by default so it never runs in normal CI.
func TestEmitGoldenFixtures(t *testing.T) {
	if os.Getenv("EMIT_GOLDEN") == "" {
		t.Skip("set EMIT_GOLDEN=1")
	}

	res := func(display string, typ model.ResourceType, prod bool) model.Resource {
		return model.Resource{Display: display, Name: display, Type: typ, Region: "us-east-1", Production: prod}
	}
	vol := res("orders-pv", model.TypeVolume, false)
	prodDB := res("payments-db", model.TypeDatabase, true)
	devDB := res("dev-db", model.TypeDatabase, false)
	etcd := res("etcd (prod-cluster)", model.TypeK8sState, false)
	cluster := res("aurora-main", model.TypeDBCluster, true)

	f := func(r model.Resource, c model.CheckID, s model.Status, accessGap bool) model.Finding {
		return model.Finding{Resource: r, Check: c, Status: s, SkipIsAccessGap: accessGap}
	}

	cases := []struct {
		Name     string          `json:"name"`
		Findings []model.Finding `json:"findings"`
		Expected model.Score     `json:"expected"`
	}{
		{Name: "empty", Findings: []model.Finding{}},
		{Name: "all-ok", Findings: []model.Finding{
			f(vol, model.CheckCoverage, model.StatusOK, false),
			f(vol, model.CheckFreshness, model.StatusOK, false),
			f(vol, model.CheckImmutability, model.StatusOK, false),
			f(vol, model.CheckRedundancy, model.StatusOK, false),
			f(vol, model.CheckRestoreTested, model.StatusOK, false),
		}},
		{Name: "coverage-fail-plain", Findings: []model.Finding{
			f(vol, model.CheckCoverage, model.StatusFail, false),
		}},
		{Name: "coverage-fail-k8s-state", Findings: []model.Finding{
			f(etcd, model.CheckCoverage, model.StatusFail, false),
		}},
		{Name: "coverage-fail-prod-db", Findings: []model.Finding{
			f(prodDB, model.CheckCoverage, model.StatusFail, false),
		}},
		{Name: "coverage-fail-dev-db-no-bonus", Findings: []model.Finding{
			f(devDB, model.CheckCoverage, model.StatusFail, false),
		}},
		{Name: "coverage-fail-prod-cluster", Findings: []model.Finding{
			f(cluster, model.CheckCoverage, model.StatusFail, false),
		}},
		{Name: "freshness-warn-vs-fail", Findings: []model.Finding{
			f(vol, model.CheckFreshness, model.StatusWarn, false),
			f(prodDB, model.CheckFreshness, model.StatusFail, false),
		}},
		{Name: "each-check-failing", Findings: []model.Finding{
			f(vol, model.CheckImmutability, model.StatusFail, false),
			f(vol, model.CheckRedundancy, model.StatusFail, false),
			f(vol, model.CheckRestoreTested, model.StatusFail, false),
		}},
		{Name: "skipped-blocked-and-moot", Findings: []model.Finding{
			f(vol, model.CheckCoverage, model.StatusOK, false),
			f(vol, model.CheckImmutability, model.StatusSkipped, true),
			f(vol, model.CheckRedundancy, model.StatusSkipped, false),
		}},
		{Name: "nothing-assessable", Findings: []model.Finding{
			f(vol, model.CheckCoverage, model.StatusSkipped, true),
			f(vol, model.CheckImmutability, model.StatusSkipped, true),
		}},
		{Name: "clamped-at-zero", Findings: []model.Finding{
			f(etcd, model.CheckCoverage, model.StatusFail, false),
			f(prodDB, model.CheckCoverage, model.StatusFail, false),
			f(vol, model.CheckCoverage, model.StatusFail, false),
			f(cluster, model.CheckCoverage, model.StatusFail, false),
		}},
		{Name: "realistic-mixed-estate", Findings: []model.Finding{
			f(prodDB, model.CheckCoverage, model.StatusOK, false),
			f(prodDB, model.CheckFreshness, model.StatusOK, false),
			f(prodDB, model.CheckImmutability, model.StatusFail, false),
			f(prodDB, model.CheckRedundancy, model.StatusFail, false),
			f(prodDB, model.CheckRestoreTested, model.StatusFail, false),
			f(vol, model.CheckCoverage, model.StatusOK, false),
			f(vol, model.CheckFreshness, model.StatusWarn, false),
			f(vol, model.CheckImmutability, model.StatusOK, false),
			f(vol, model.CheckRedundancy, model.StatusOK, false),
			f(vol, model.CheckRestoreTested, model.StatusOK, false),
			f(etcd, model.CheckCoverage, model.StatusFail, false),
			f(etcd, model.CheckFreshness, model.StatusSkipped, false),
			f(etcd, model.CheckImmutability, model.StatusSkipped, false),
			f(etcd, model.CheckRedundancy, model.StatusSkipped, false),
			f(etcd, model.CheckRestoreTested, model.StatusSkipped, false),
		}},
	}

	for i := range cases {
		cases[i].Expected = Compute(cases[i].Findings)
	}

	out, err := json.MarshalIndent(cases, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("GOLDEN_OUT"), out, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d cases", len(cases))
}
