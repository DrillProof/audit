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
  <p class="notes">No EBS volumes, RDS databases, or EKS clusters found in the scanned regions.</p>
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

  {{if .Warnings}}
  <h2>Not assessed</h2>
  <ul class="notes">{{range .Warnings}}<li>{{.}}</li>{{end}}</ul>
  {{end}}

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
