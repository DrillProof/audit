package report

import (
	"html/template"
	"io"

	"github.com/drillproof/audit/internal/aws"
	"github.com/drillproof/audit/internal/checks"
	"github.com/drillproof/audit/internal/model"
	"github.com/drillproof/audit/internal/score"
)

// RenderHTML writes a single self-contained file — no external CSS, fonts, or
// scripts — so it can be emailed or attached to a ticket and still render. The
// palette matches the DrillProof brand tokens.
func RenderHTML(w io.Writer, result *model.Result) error {
	cfg := checks.DefaultConfig()

	type htmlSkip struct {
		Resource string
		Summary  string
		Cls      string
	}

	type htmlRow struct {
		Resource   string
		Type       string
		Region     string
		Backup     string
		BackupCls  string
		Age        string
		Immutable  string
		ImmutCls   string
		CrossReg   string
		CrossCls   string
		Restore    string
		RestoreCls string
	}

	data := struct {
		Account   string
		Regions   []string
		Generated string
		Score     model.Score
		Band      string
		Rows      []htmlRow
		Findings  []model.Finding
		Skipped   []htmlSkip
		Explain   []string
		Warnings  []string
		Untested  int
		AuditURL  string
		Version   string
	}{
		Account:   formatAccount(result.AccountID),
		Regions:   result.Regions,
		Generated: result.GeneratedAt.Format("2 January 2006, 15:04 MST"),
		Score:     result.Score,
		Band:      band(result.Score.Value),
		Explain:   score.Explain(result.Score),
		Warnings:  result.Warnings,
		Untested:  aws.CountUntested(result),
		AuditURL:  AuditURL,
		Version:   result.Version,
	}

	for _, row := range result.Rows {
		data.Rows = append(data.Rows, htmlRow{
			Resource:   row.Resource.Display,
			Type:       string(row.Resource.Type),
			Region:     row.Resource.Region,
			Backup:     backupCell(row),
			BackupCls:  cls(row.Statuses[model.CheckCoverage]),
			Age:        checks.Age(row.State, cfg),
			Immutable:  tristateCell(row.State.Immutable, row.Statuses[model.CheckImmutability]),
			ImmutCls:   cls(row.Statuses[model.CheckImmutability]),
			CrossReg:   tristateCell(row.State.CrossRegion, row.Statuses[model.CheckRedundancy]),
			CrossCls:   cls(row.Statuses[model.CheckRedundancy]),
			Restore:    restoreCell(row),
			RestoreCls: cls(row.Statuses[model.CheckRestoreTested]),
		})
	}

	data.Findings = aws.TopFindings(result, 20)

	// Skipped checks split into two lists that must never look alike: an
	// access gap (a permission we lack, and the reader can fix) versus not
	// applicable (nothing to assess, no permission would change that).
	// Telling a customer to grant a permission they already hold is a false
	// statement about their estate, so the two are never merged into one
	// generic "skipped" bucket.
	for _, f := range result.Findings {
		if f.Status != model.StatusSkipped {
			continue
		}
		skipCls := "na"
		if f.SkipIsAccessGap {
			skipCls = "gap"
		}
		data.Skipped = append(data.Skipped, htmlSkip{
			Resource: f.Resource.Display,
			Summary:  f.Summary,
			Cls:      skipCls,
		})
	}

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, data)
}

func cls(s model.Status) string {
	switch s {
	case model.StatusOK:
		return "ok"
	case model.StatusWarn:
		return "warn"
	case model.StatusFail:
		return "fail"
	default:
		return "skip"
	}
}

func band(value int) string {
	switch {
	case value >= 80:
		return "ok"
	case value >= 50:
		return "warn"
	default:
		return "fail"
	}
}

const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DrillProof Audit — account {{.Account}}</title>
<style>
  :root {
    --blue: #2E6BF6; --blue-deep: #1B3A8C; --teal: #2FC39E;
    --ink: #0F1B33; --slate: #5A6B85; --bg: #fff; --bg-soft: #F5F8FF;
    --bg-dark: #0B1220; --line: #E3E9F5;
    --ok: #0F7A61; --warn: #B3701A; --fail: #C0392F;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 2.5rem 1.5rem; background: var(--bg); color: var(--ink);
    font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    -webkit-font-smoothing: antialiased;
  }
  .wrap { max-width: 60rem; margin: 0 auto; }
  h1 { font-size: 1.5rem; letter-spacing: -0.02em; margin: 0 0 .35rem; }
  .meta { color: var(--slate); font-size: .875rem; margin-bottom: 2rem; }
  .score {
    display: flex; align-items: baseline; gap: .75rem; flex-wrap: wrap;
    padding: 1.25rem 1.5rem; border: 1px solid var(--line); border-radius: 12px;
    background: var(--bg-soft); margin-bottom: 2rem;
  }
  .score .value { font-size: 2.5rem; font-weight: 650; letter-spacing: -0.03em; line-height: 1; }
  .score .value.ok { color: var(--ok); } .score .value.warn { color: var(--warn); }
  .score .value.fail { color: var(--fail); }
  .score .gaps { color: var(--slate); font-size: .9375rem; }
  table { width: 100%; border-collapse: collapse; font-size: .8125rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  th { text-align: left; font-weight: 600; color: var(--slate); font-size: .6875rem;
    letter-spacing: .04em; text-transform: uppercase; padding: 0 1rem .5rem 0;
    border-bottom: 1px solid var(--line); }
  td { padding: .55rem 1rem .55rem 0; border-bottom: 1px solid var(--line); white-space: nowrap; }
  .ok { color: var(--ok); } .warn { color: var(--warn); }
  .fail { color: var(--fail); } .skip { color: var(--slate); }
  h2 { font-size: 1rem; letter-spacing: -0.01em; margin: 2.5rem 0 .75rem; }
  ul.findings { list-style: none; padding: 0; margin: 0; }
  ul.findings li { padding: .6rem 0; border-bottom: 1px solid var(--line); font-size: .9375rem; }
  ul.findings .res { font-weight: 600; }
  ul.findings li.gap { color: var(--warn); }
  ul.findings li.na { color: var(--slate); }
  ul.findings .rem { color: var(--slate); display: block; font-size: .875rem; margin-top: .15rem; }
  pre.explain { background: var(--bg-dark); color: #D6E0F2; padding: 1rem 1.25rem;
    border-radius: 10px; overflow-x: auto; font-size: .75rem; line-height: 1.7; }
  .notes { color: var(--slate); font-size: .8125rem; }
  .cta { margin-top: 2.5rem; padding: 1.25rem 1.5rem; border-radius: 12px;
    background: var(--bg-dark); color: #fff; }
  .cta a { color: #57E0C0; }
  footer { margin-top: 2rem; color: var(--slate); font-size: .75rem; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #0B1220; --ink: #E8EEF9; --bg-soft: #111A2C; --line: #1E2A41; --slate: #8FA1BF;
            --ok: #2FC39E; --warn: #F0B45E; --fail: #FF8F84; }
  }
</style>
</head>
<body>
<div class="wrap">
  <h1>DrillProof Audit</h1>
  <p class="meta">
    Account {{.Account}} · {{range $i, $r := .Regions}}{{if $i}}, {{end}}{{$r}}{{end}}<br>
    Generated {{.Generated}} · read-only scan, no data left this machine
  </p>

  <div class="score">
    <span class="value {{.Band}}">{{.Score.Value}}<span style="font-size:1rem;font-weight:400">/100</span></span>
    <span class="gaps">Recoverability Score · {{.Score.CriticalGaps}} critical gap{{if ne .Score.CriticalGaps 1}}s{{end}}{{if .Untested}} · {{.Untested}} resource{{if ne .Untested 1}}s{{end}} never test-restored{{end}}</span>
  </div>

  {{if .Rows}}
  <table>
    <thead><tr>
      <th>Resource</th><th>Type</th><th>Region</th><th>Backup</th>
      <th>Age</th><th>Immutable</th><th>X-Region</th><th>Restore</th>
    </tr></thead>
    <tbody>
      {{range .Rows}}
      <tr>
        <td>{{.Resource}}</td><td class="skip">{{.Type}}</td><td class="skip">{{.Region}}</td>
        <td class="{{.BackupCls}}">{{.Backup}}</td><td>{{.Age}}</td>
        <td class="{{.ImmutCls}}">{{.Immutable}}</td>
        <td class="{{.CrossCls}}">{{.CrossReg}}</td>
        <td class="{{.RestoreCls}}">{{.Restore}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}
  <p class="notes">No EBS volumes, RDS databases, EKS clusters, S3 buckets, DynamoDB tables, or EFS filesystems found in the scanned regions.</p>
  {{end}}

  {{if .Findings}}
  <h2>Findings</h2>
  <ul class="findings">
    {{range .Findings}}
    <li>
      <span class="{{if eq .Status "fail"}}fail{{else}}warn{{end}}">{{if eq .Status "fail"}}✕{{else}}!{{end}}</span>
      <span class="res">{{.Resource.Display}}</span> — {{.Summary}}
      {{if .Remediation}}<span class="rem">{{.Remediation}}</span>{{end}}
    </li>
    {{end}}
  </ul>
  {{end}}

  <h2>How this score was calculated</h2>
  <pre class="explain">{{range .Explain}}{{.}}
{{end}}</pre>

  {{if .Skipped}}
  <h2>Checks not assessed or not applicable</h2>
  <ul class="findings">
    {{range .Skipped}}
    <li class="{{.Cls}}"><span class="res">{{.Resource}}</span> — {{.Summary}}</li>
    {{end}}
  </ul>
  {{end}}

  {{if .Warnings}}
  <h2>Not assessed</h2>
  <ul class="notes">{{range .Warnings}}<li>{{.}}</li>{{end}}</ul>
  {{end}}

  <h2>Scope &amp; method</h2>

  <h3>S3 protection hierarchy</h3>
  <p>S3 is not a volume — it <em>is</em> the storage — so a bucket is graded on
  how hard it is to delete, not on whether a backup of it exists:</p>
  <ul>
    <li><strong>strongest</strong> — Object Lock in compliance mode. Nothing,
        including root, can delete before retention expires.</li>
    <li><strong>strong</strong> — versioning and MFA Delete both enabled.</li>
    <li><strong>partial</strong> — versioning enabled, MFA Delete off or
        unreadable.</li>
    <li><strong>weak</strong> — Object Lock in governance mode only, which any
        principal holding s3:BypassGovernanceRetention can override.</li>
    <li><strong>unprotected</strong> — neither versioning nor Object Lock.</li>
  </ul>

  <h3>EFS coverage and redundancy</h3>
  <p>EFS is protected by AWS Backup, so all five checks apply. Two of them
  accept more than one path, because both are genuine:</p>
  <ul>
    <li><strong>Coverage</strong> — either EFS <em>automatic backups</em> (the
        built-in policy enabled on the filesystem) or a user-defined AWS Backup
        plan. A filesystem protected by automatic backups alone is protected.</li>
    <li><strong>Redundancy</strong> — either an AWS Backup cross-region copy or
        <em>EFS Replication</em> to another region. Replication into the same
        region does not survive the loss of that region, and a replication that
        is configured but unhealthy is reported as a failure, not as a copy.</li>
    <li><strong>One Zone</strong> — a single-AZ filesystem is reported as
        context. With backups it passes; with no backup at all it is weighted
        as critical, because single-AZ durability and no recovery path compound.</li>
  </ul>

  <h3>Checks that do not apply</h3>
  <p>Some checks have no meaning for some resource types, and are reported as
  <em>not applicable</em>. They deduct nothing, and are shown separately from
  <em>not assessed</em>, which means a permission stopped us from looking:</p>
  <ul>
    <li><strong>S3 freshness</strong> — a live bucket has no "last backup age".
        Last-modified time answers a different question and is not substituted.</li>
    <li><strong>S3 restore-testing</strong> — not implemented for buckets in this
        release. No bucket is reported as verified.</li>
    <li><strong>DynamoDB freshness and immutability</strong>, when the table is
        protected by Point-in-Time Recovery alone — PITR is continuous and has no
        vault to lock.</li>
  </ul>

  <div class="cta">
    <strong>Want these gaps closed with evidence?</strong><br>
    A free Restore-Assurance Audit test-restores your latest backups and reports back:
    <a href="{{.AuditURL}}">{{.AuditURL}}</a>
  </div>

  <footer>
    Generated by drillproof-audit {{.Version}} — read-only, local, no telemetry.
  </footer>
</div>
</body>
</html>
`
