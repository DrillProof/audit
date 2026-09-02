package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drillproof/audit/internal/checks"
	"github.com/drillproof/audit/internal/model"
	"github.com/drillproof/audit/internal/score"
)

var now = time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

// sample mirrors the spec's §7 example estate: an untested database, a verified
// volume, and cluster state with no backup at all.
func sample() *model.Result {
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }

	db := model.Resource{Display: "payments-db (RDS)", Name: "payments-db", Type: model.TypeDatabase, Region: "ap-southeast-1", Production: true, ARN: "arn:aws:rds:ap-southeast-1:123456789012:db:payments-db"}
	vol := model.Resource{Display: "orders-pv (EKS/EBS)", Name: "orders-pv", Type: model.TypeVolume, Region: "ap-southeast-1", ARN: "arn:aws:ec2:ap-southeast-1:123456789012:volume/vol-1"}
	etcd := model.Resource{Display: "etcd (prod-cluster)", Name: "prod-cluster", Type: model.TypeK8sState, Region: "ap-southeast-1"}

	dbState := model.NewBackupState()
	dbState.RecoveryPoints = 4
	dbState.LatestBackupAt = ago(6 * time.Hour)
	dbState.Immutable = model.No
	dbState.CrossRegion = model.No

	volState := model.NewBackupState()
	volState.RecoveryPoints = 2
	volState.LatestBackupAt = ago(3 * time.Hour)
	volState.Immutable = model.Yes
	volState.CrossRegion = model.Yes
	volState.LastRestoreAt = ago(72 * time.Hour)

	etcdState := model.NewBackupState()

	findings := []model.Finding{
		{Resource: etcd, Check: model.CheckCoverage, Status: model.StatusFail,
			Summary:     "no backup of cluster state — the cluster is unrecoverable",
			Remediation: "Install Velero and schedule a backup."},
		{Resource: db, Check: model.CheckCoverage, Status: model.StatusOK, Summary: "4 recovery point(s) found"},
		{Resource: db, Check: model.CheckImmutability, Status: model.StatusFail,
			Summary: "backups can be deleted — no Vault Lock or Object Lock"},
		{Resource: db, Check: model.CheckRedundancy, Status: model.StatusFail,
			Summary: "all backups are in ap-southeast-1, the same region as the resource"},
		{Resource: db, Check: model.CheckRestoreTested, Status: model.StatusFail,
			Summary: `never test-restored — "backed up" is not "recoverable"`},
		{Resource: vol, Check: model.CheckCoverage, Status: model.StatusOK, Summary: "2 recovery point(s) found"},
		{Resource: vol, Check: model.CheckRestoreTested, Status: model.StatusOK, Summary: "a restore was performed on 2026-07-23"},
		// An access gap: actionable by granting a permission.
		{Resource: vol, Check: model.CheckImmutability, Status: model.StatusSkipped,
			Summary:    "not assessed (backup:ListBackupVaults denied)",
			SkipReason: "backup:ListBackupVaults denied", SkipIsAccessGap: true},
		// A moot check: nothing to assess, and no permission would change that.
		{Resource: etcd, Check: model.CheckFreshness, Status: model.StatusSkipped,
			Summary: "not applicable (no backup to age)", SkipReason: "no backup to age"},
	}

	result := &model.Result{
		AccountID:   "123456789012",
		Regions:     []string{"ap-southeast-1"},
		GeneratedAt: now,
		Version:     "1.0.0-test",
		Warnings:    []string{"us-east-1: backup:ListBackupVaults denied"},
		Rows: []model.Row{
			{Resource: db, State: dbState, Statuses: map[model.CheckID]model.Status{
				model.CheckCoverage: model.StatusOK, model.CheckFreshness: model.StatusOK,
				model.CheckImmutability: model.StatusFail, model.CheckRedundancy: model.StatusFail,
				model.CheckRestoreTested: model.StatusFail}},
			{Resource: vol, State: volState, Statuses: map[model.CheckID]model.Status{
				model.CheckCoverage: model.StatusOK, model.CheckFreshness: model.StatusOK,
				model.CheckImmutability: model.StatusOK, model.CheckRedundancy: model.StatusOK,
				model.CheckRestoreTested: model.StatusOK}},
			{Resource: etcd, State: etcdState, Statuses: map[model.CheckID]model.Status{
				model.CheckCoverage: model.StatusFail, model.CheckFreshness: model.StatusSkipped,
				model.CheckImmutability: model.StatusSkipped, model.CheckRedundancy: model.StatusSkipped,
				model.CheckRestoreTested: model.StatusSkipped}},
		},
		Findings: findings,
	}
	result.Score = score.Compute(findings)
	return result
}

func tableOpts() Options {
	cfg := checks.DefaultConfig()
	cfg.Now = now
	return Options{NoColor: true, Checks: cfg}
}

func TestTableMatchesSpecShape(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, RenderTable(&buf, sample(), tableOpts()))
	out := buf.String()

	// Header, formatted account, region.
	assert.Contains(t, out, "DrillProof Audit")
	assert.Contains(t, out, "1234-5678-9012", "account should be grouped as in the spec")
	assert.Contains(t, out, "ap-southeast-1")

	// All seven spec columns.
	for _, col := range []string{"RESOURCE", "TYPE", "BACKUP", "AGE", "IMMUTABLE", "X-REGION", "RESTORE"} {
		assert.Contains(t, out, col, "missing column %s", col)
	}

	// The spec's own sample rows and vocabulary.
	assert.Contains(t, out, "payments-db (RDS)")
	assert.Contains(t, out, "untested")
	assert.Contains(t, out, "verified")
	assert.Contains(t, out, "none", "a resource with no backup shows 'none'")
	assert.Contains(t, out, "6h")
	assert.Contains(t, out, "3h")

	// Score line and the funnel.
	assert.Contains(t, out, "Recoverability Score:")
	assert.Contains(t, out, "critical gap")
	assert.Contains(t, out, "Top findings:")
	assert.Contains(t, out, AuditURL)
	assert.Contains(t, out, "drillproof audit init")
}

func TestTableShowsFailedRestoreForUnbackedResource(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, RenderTable(&buf, sample(), tableOpts()))

	// Per the spec sample, etcd with no backup reads "failed" in the RESTORE
	// column, not a blank — you cannot restore what does not exist.
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "etcd (prod-cluster)") {
			assert.Contains(t, line, "failed")
			return
		}
	}
	t.Fatal("no etcd row rendered")
}

func TestTableNoColorEmitsNoEscapes(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, RenderTable(&buf, sample(), tableOpts()))
	assert.NotContains(t, buf.String(), "\x1b[", "NoColor must suppress ANSI escapes")
}

func TestTableSurfacesSkippedChecksHonestly(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, RenderTable(&buf, sample(), tableOpts()))
	out := buf.String()

	assert.Contains(t, out, "could not be assessed")
	assert.Contains(t, out, "not applicable")
	assert.Contains(t, out, "Notes:")
	assert.Contains(t, out, "backup:ListBackupVaults denied")
}

func TestTableExplainShowsArithmetic(t *testing.T) {
	opts := tableOpts()
	opts.Explain = true

	var buf bytes.Buffer
	require.NoError(t, RenderTable(&buf, sample(), opts))
	out := buf.String()

	assert.Contains(t, out, "How this score was calculated")
	assert.Contains(t, out, "Per-resource recoverability")
	assert.Contains(t, out, "Total raw deduction:")
}

func TestTableHandlesEmptyEstate(t *testing.T) {
	empty := &model.Result{AccountID: "123456789012", Regions: []string{"eu-west-1"}, GeneratedAt: now}
	var buf bytes.Buffer
	require.NoError(t, RenderTable(&buf, empty, tableOpts()))
	assert.Contains(t, buf.String(), "No EBS volumes")
}

func TestJSONIsValidAndCarriesTheExplanation(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, RenderJSON(&buf, sample()))

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	assert.Equal(t, SchemaVersion, parsed["schema_version"])
	assert.Equal(t, "drillproof-audit", parsed["tool"])
	assert.Equal(t, "123456789012", parsed["account_id"])
	assert.NotEmpty(t, parsed["rows"])
	assert.NotEmpty(t, parsed["findings"])
	assert.NotEmpty(t, parsed["score_explained"], "consumers should not have to re-derive the score")

	scoreObj, ok := parsed["score"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, scoreObj, "value")
	assert.Contains(t, scoreObj, "penalties")
}

func TestSARIFIsWellFormed(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, RenderSARIF(&buf, sample()))

	var log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID              string                `json:"ruleId"`
				RuleIndex           int                   `json:"ruleIndex"`
				Level               string                `json:"level"`
				Message             struct{ Text string } `json:"message"`
				PartialFingerprints map[string]string     `json:"partialFingerprints"`
				Locations           []struct {
					LogicalLocations []struct {
						Name string `json:"name"`
						Kind string `json:"kind"`
					} `json:"logicalLocations"`
				} `json:"locations"`
			} `json:"results"`
			Properties map[string]any `json:"properties"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &log))

	assert.Equal(t, "2.1.0", log.Version)
	assert.Contains(t, log.Schema, "sarif")
	require.Len(t, log.Runs, 1)

	run := log.Runs[0]
	assert.Equal(t, "drillproof-audit", run.Tool.Driver.Name)
	assert.Len(t, run.Tool.Driver.Rules, len(model.AllChecks), "one rule per check")
	require.NotEmpty(t, run.Results)

	for _, r := range run.Results {
		assert.Contains(t, r.RuleID, "drillproof/")
		assert.Contains(t, []string{"error", "warning", "note"}, r.Level)
		assert.NotEmpty(t, r.Message.Text)
		assert.NotEmpty(t, r.PartialFingerprints, "fingerprints keep CI from re-reporting the same gap as new")
		require.NotEmpty(t, r.Locations)
		assert.NotEmpty(t, r.Locations[0].LogicalLocations[0].Name)
		assert.Less(t, r.RuleIndex, len(run.Tool.Driver.Rules), "ruleIndex must point at a real rule")
	}

	assert.EqualValues(t, sample().Score.Value, run.Properties["recoverabilityScore"])
}

func TestSARIFExcludesPassingAndSkippedFindings(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, RenderSARIF(&buf, sample()))

	var log struct {
		Runs []struct {
			Results []struct {
				Message struct{ Text string } `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &log))

	// The sample has 4 fail findings; OK and skipped must not appear.
	assert.Len(t, log.Runs[0].Results, 4)
	for _, r := range log.Runs[0].Results {
		assert.NotContains(t, r.Message.Text, "recovery point(s) found")
		assert.NotContains(t, r.Message.Text, "not assessed")
	}
}

func TestSARIFFingerprintsAreStable(t *testing.T) {
	extract := func() map[string]string {
		var buf bytes.Buffer
		require.NoError(t, RenderSARIF(&buf, sample()))
		var log struct {
			Runs []struct {
				Results []struct {
					RuleID              string            `json:"ruleId"`
					PartialFingerprints map[string]string `json:"partialFingerprints"`
				} `json:"results"`
			} `json:"runs"`
		}
		require.NoError(t, json.Unmarshal(buf.Bytes(), &log))
		out := map[string]string{}
		for _, r := range log.Runs[0].Results {
			out[r.RuleID] += r.PartialFingerprints["drillproof/v1"]
		}
		return out
	}
	assert.Equal(t, extract(), extract(), "fingerprints must not vary between runs")
}

func TestHTMLIsSelfContained(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, RenderHTML(&buf, sample()))
	out := buf.String()

	assert.Contains(t, out, "<!doctype html>")
	assert.Contains(t, out, "Recoverability Score")
	assert.Contains(t, out, "payments-db (RDS)")
	assert.Contains(t, out, "How this score was calculated")
	assert.Contains(t, out, AuditURL)

	// Self-contained: no external requests of any kind.
	for _, external := range []string{"<script src", "<link rel=\"stylesheet\"", "https://fonts.", "cdn."} {
		assert.NotContains(t, out, external, "HTML report must not fetch %s", external)
	}
}

func TestHTMLEscapesContent(t *testing.T) {
	result := sample()
	result.Rows[0].Resource.Display = `<img src=x onerror="alert(1)">`

	var buf bytes.Buffer
	require.NoError(t, RenderHTML(&buf, result))

	assert.NotContains(t, buf.String(), `<img src=x onerror=`)
	assert.Contains(t, buf.String(), "&lt;img", "resource names must be escaped")
}

func TestFormatAccount(t *testing.T) {
	assert.Equal(t, "1234-5678-9012", formatAccount("123456789012"))
	assert.Equal(t, "short", formatAccount("short"), "non-12-digit ids pass through unchanged")
}
