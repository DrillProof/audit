package score

import (
	"encoding/json"
	"fmt"
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
//	EMIT_GOLDEN=1 GOLDEN_OUT=../../../app/packages/shared/src/__fixtures__/scorer-golden.json \
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
	prodBucket := res("customer-uploads", model.TypeBucket, true)
	devBucket := res("build-artifacts", model.TypeBucket, false)
	prodTable := res("sessions", model.TypeTable, true)
	efsRegional := model.Resource{
		Display: "shared-data (EFS)", Name: "shared-data", Type: model.TypeFileSystem,
		Region: "us-east-1", Attrs: map[string]string{"storage_class": "regional"},
	}
	efsOneZone := model.Resource{
		Display: "cheap-data (EFS)", Name: "cheap-data", Type: model.TypeFileSystem,
		Region: "us-east-1", Attrs: map[string]string{"storage_class": "one-zone"},
	}
	prodEFS := model.Resource{
		Display: "prod-data (EFS)", Name: "prod-data", Type: model.TypeFileSystem,
		Region: "us-east-1", Production: true, Attrs: map[string]string{"storage_class": "regional"},
	}

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
		{Name: "every-resource-unbacked", Findings: []model.Finding{
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

		// The bug. 4 unbacked resources among 100 scored 0 under absolute
		// weights, identically to an estate with nothing backed up. None of
		// the older fixtures is a large partially-protected estate.
		{Name: "large-estate-mostly-protected", Findings: func() []model.Finding {
			var out []model.Finding
			for i := 0; i < 4; i++ {
				r := res(fmt.Sprintf("gap-%03d", i), model.TypeVolume, false)
				out = append(out,
					f(r, model.CheckCoverage, model.StatusFail, false),
					f(r, model.CheckFreshness, model.StatusSkipped, false),
					f(r, model.CheckImmutability, model.StatusSkipped, false),
					f(r, model.CheckRedundancy, model.StatusSkipped, false),
					f(r, model.CheckRestoreTested, model.StatusSkipped, false),
				)
			}
			for i := 0; i < 96; i++ {
				r := res(fmt.Sprintf("ok-%03d", i), model.TypeVolume, false)
				out = append(out,
					f(r, model.CheckCoverage, model.StatusOK, false),
					f(r, model.CheckFreshness, model.StatusOK, false),
					f(r, model.CheckImmutability, model.StatusOK, false),
					f(r, model.CheckRedundancy, model.StatusOK, false),
					f(r, model.CheckRestoreTested, model.StatusFail, false),
				)
			}
			return out
		}()},

		// Criticality now lives in the weight, not in a bigger penalty. This
		// pins that a critical gap drags the estate further than a plain one.
		{Name: "mixed-critical-and-plain-gaps", Findings: []model.Finding{
			f(vol, model.CheckCoverage, model.StatusOK, false),
			f(vol, model.CheckFreshness, model.StatusOK, false),
			f(vol, model.CheckImmutability, model.StatusOK, false),
			f(vol, model.CheckRedundancy, model.StatusOK, false),
			f(vol, model.CheckRestoreTested, model.StatusOK, false),
			f(etcd, model.CheckCoverage, model.StatusFail, false),
			f(prodDB, model.CheckCoverage, model.StatusOK, false),
			f(prodDB, model.CheckFreshness, model.StatusWarn, false),
			f(prodDB, model.CheckImmutability, model.StatusFail, false),
			f(prodDB, model.CheckRedundancy, model.StatusFail, false),
			f(prodDB, model.CheckRestoreTested, model.StatusFail, false),
		}},

		// Every check moot: the resource drops out of the mean, and with
		// nothing assessed the estate is 0, not 100.
		{Name: "all-moot-nothing-assessed", Findings: []model.Finding{
			f(vol, model.CheckCoverage, model.StatusSkipped, false),
			f(vol, model.CheckFreshness, model.StatusSkipped, false),
			f(vol, model.CheckImmutability, model.StatusSkipped, false),
			f(vol, model.CheckRedundancy, model.StatusSkipped, false),
			f(vol, model.CheckRestoreTested, model.StatusSkipped, false),
		}},

		// resourceKey groups by (Type, Region, Display), not Display alone.
		// Every other fixture happens to use one Display per resource, so
		// none of them would catch resourceKey degrading to Display-only.
		// Two "orders-pv" volumes, one in each region, with different
		// findings, pin that they are scored and reported as two distinct
		// resources rather than merged into one.
		{Name: "same-display-different-region", Findings: []model.Finding{
			f(vol, model.CheckCoverage, model.StatusOK, false),
			f(vol, model.CheckFreshness, model.StatusOK, false),
			f(vol, model.CheckImmutability, model.StatusOK, false),
			f(vol, model.CheckRedundancy, model.StatusOK, false),
			f(vol, model.CheckRestoreTested, model.StatusOK, false),
			f(model.Resource{Display: "orders-pv", Name: "orders-pv", Type: model.TypeVolume, Region: "eu-west-1", Production: false}, model.CheckCoverage, model.StatusFail, false),
		}},

		{Name: "bucket-na-checks-deduct-nothing", Findings: []model.Finding{
			f(devBucket, model.CheckCoverage, model.StatusOK, false),
			f(devBucket, model.CheckImmutability, model.StatusOK, false),
			f(devBucket, model.CheckRedundancy, model.StatusOK, false),
			f(devBucket, model.CheckFreshness, model.StatusSkipped, false),
			f(devBucket, model.CheckRestoreTested, model.StatusSkipped, false),
		}},
		{Name: "coverage-fail-prod-bucket", Findings: []model.Finding{
			f(prodBucket, model.CheckCoverage, model.StatusFail, false),
		}},
		{Name: "coverage-fail-dev-bucket-no-bonus", Findings: []model.Finding{
			f(devBucket, model.CheckCoverage, model.StatusFail, false),
		}},
		{Name: "coverage-fail-prod-table", Findings: []model.Finding{
			f(prodTable, model.CheckCoverage, model.StatusFail, false),
		}},
		{Name: "bucket-partial-tier-warn-and-redundancy-fail", Findings: []model.Finding{
			f(devBucket, model.CheckCoverage, model.StatusWarn, false),
			f(devBucket, model.CheckImmutability, model.StatusFail, false),
			f(devBucket, model.CheckRedundancy, model.StatusFail, false),
			f(devBucket, model.CheckFreshness, model.StatusSkipped, false),
			f(devBucket, model.CheckRestoreTested, model.StatusSkipped, false),
		}},
		{Name: "table-pitr-only-redundancy-fail", Findings: []model.Finding{
			f(prodTable, model.CheckCoverage, model.StatusOK, false),
			f(prodTable, model.CheckFreshness, model.StatusSkipped, false),
			f(prodTable, model.CheckImmutability, model.StatusSkipped, false),
			f(prodTable, model.CheckRedundancy, model.StatusFail, false),
			f(prodTable, model.CheckRestoreTested, model.StatusFail, false),
		}},
		{Name: "coverage-fail-efs-regional-no-bonus", Findings: []model.Finding{
			f(efsRegional, model.CheckCoverage, model.StatusFail, false),
		}},
		{Name: "coverage-fail-efs-one-zone-bonus", Findings: []model.Finding{
			f(efsOneZone, model.CheckCoverage, model.StatusFail, false),
		}},
		{Name: "efs-one-zone-backed-up-not-weighted", Findings: []model.Finding{
			f(efsOneZone, model.CheckCoverage, model.StatusOK, false),
			f(efsOneZone, model.CheckRedundancy, model.StatusFail, false),
		}},
		{Name: "coverage-fail-prod-efs", Findings: []model.Finding{
			f(prodEFS, model.CheckCoverage, model.StatusFail, false),
		}},
		{Name: "new-permission-denied-is-blocked-never-fail", Findings: []model.Finding{
			f(devBucket, model.CheckCoverage, model.StatusSkipped, true),
			f(devBucket, model.CheckImmutability, model.StatusSkipped, true),
			f(devBucket, model.CheckRedundancy, model.StatusSkipped, true),
		}},

		// KeyAvailability: a deleted/pending-deletion key is fatal (zeroes the
		// resource via keyFatal, like coverageFail does), a disabled/missing
		// key is a plain 15-point deduction, and a cross-account key is an
		// advisory 3-point warn.
		{Name: "key-fatal-deleted", Findings: []model.Finding{
			f(vol, model.CheckCoverage, model.StatusOK, false),
			{Resource: vol, Check: model.CheckKeyAvailability, Status: model.StatusFail,
				Summary: "the KMS key protecting these recovery points no longer exists (key/abc; 1 key(s)) — they cannot be restored"},
		}},
		{Name: "key-disabled-fail", Findings: []model.Finding{
			f(vol, model.CheckCoverage, model.StatusOK, false),
			{Resource: vol, Check: model.CheckKeyAvailability, Status: model.StatusFail,
				Summary: "the KMS key protecting these recovery points is disabled (key/abc; 1 key(s)) — a restore will fail until it is re-enabled"},
		}},
		{Name: "key-cross-account-warn", Findings: []model.Finding{
			f(vol, model.CheckCoverage, model.StatusOK, false),
			{Resource: vol, Check: model.CheckKeyAvailability, Status: model.StatusWarn,
				Summary: "these recovery points depend on a KMS key in another account (key/x; 1 key(s)) — the owning account can revoke access without warning"},
		}},

		// The required interaction case: coverage FAIL and a fatal key FAIL
		// on the SAME resource. Both flags zero the resource independently
		// (coverageFail || keyFatal), so this must score 0 exactly once, not
		// be double-penalised — and RawDeduction still carries both points'
		// worth of arithmetic for the printed breakdown.
		{Name: "coverage-fail-and-key-fatal-no-double-penalty", Findings: []model.Finding{
			f(prodDB, model.CheckCoverage, model.StatusFail, false),
			{Resource: prodDB, Check: model.CheckKeyAvailability, Status: model.StatusFail,
				Summary: "the KMS key protecting these recovery points is scheduled for deletion on 2026-09-14, 6 day(s) from now (key/abc; 1 key(s))"},
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
