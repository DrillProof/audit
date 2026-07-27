// Package report renders a scan as a table, JSON, or SARIF.
package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/drillproof/audit/internal/aws"
	"github.com/drillproof/audit/internal/checks"
	"github.com/drillproof/audit/internal/model"
	"github.com/drillproof/audit/internal/score"
)

// AuditURL is where the CLI points people who want the gaps closed.
const AuditURL = "https://drillproof.com/audit"

// Options controls rendering.
type Options struct {
	NoColor bool
	Quiet   bool
	// Explain appends the score arithmetic.
	Explain bool
	Checks  checks.Config
}

// palette holds the colour functions, already resolved for the NO_COLOR case so
// call sites never branch.
type palette struct {
	ok, warn, fail, dim, bold, teal func(a ...interface{}) string
}

func newPalette(noColor bool) palette {
	// Respect NO_COLOR (https://no-color.org) as well as the flag.
	if noColor || os.Getenv("NO_COLOR") != "" {
		plain := func(a ...interface{}) string { return fmt.Sprint(a...) }
		return palette{plain, plain, plain, plain, plain, plain}
	}
	return palette{
		ok:   color.New(color.FgGreen).SprintFunc(),
		warn: color.New(color.FgYellow).SprintFunc(),
		fail: color.New(color.FgRed).SprintFunc(),
		dim:  color.New(color.Faint).SprintFunc(),
		bold: color.New(color.Bold).SprintFunc(),
		teal: color.New(color.FgCyan).SprintFunc(),
	}
}

// errWriter records the first write failure and turns every later write into a
// no-op, so the renderer can stay readable while still reporting a broken pipe
// or a full disk. Rob Pike's errWriter idiom.
//
// The alternative — ignoring the errors, as this originally did — meant
// RenderTable's error return was always nil and a failed write was invisible.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}

func (e *errWriter) println(args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintln(e.w, args...)
}

// Write lets go-pretty render into the same error-tracking writer.
func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		// Report the bytes as consumed: the caller cannot act on the failure
		// any better than we already have, and a short write would make
		// go-pretty retry pointlessly.
		return len(p), nil
	}
	n, err := e.w.Write(p)
	e.err = err
	return n, err
}

// RenderTable writes the default human-facing report.
func RenderTable(dst io.Writer, result *model.Result, opts Options) error {
	p := newPalette(opts.NoColor)
	w := &errWriter{w: dst}

	header := fmt.Sprintf("DrillProof Audit — account %s — %s",
		formatAccount(result.AccountID), strings.Join(result.Regions, ", "))
	w.println(p.bold(header))
	w.println(p.dim(strings.Repeat("─", min(len(header), 78))))

	if len(result.Rows) == 0 {
		w.println(p.dim("No EBS volumes, RDS databases, or EKS clusters found in the scanned regions."))
		w.println()
	} else {
		t := table.NewWriter()
		t.SetOutputMirror(w)
		t.SetStyle(table.StyleLight)
		t.Style().Options.DrawBorder = false
		t.Style().Options.SeparateColumns = false
		t.Style().Options.SeparateHeader = false
		t.Style().Options.SeparateRows = false
		t.Style().Box.PaddingLeft = ""
		t.Style().Box.PaddingRight = "  "
		t.Style().Format.Header = text.FormatUpper

		t.AppendHeader(table.Row{
			"RESOURCE", "TYPE", "BACKUP", "AGE", "IMMUTABLE", "X-REGION", "RESTORE",
		})

		for _, row := range result.Rows {
			t.AppendRow(table.Row{
				row.Resource.Display,
				string(row.Resource.Type),
				colorCell(p, backupCell(row), row.Statuses[model.CheckCoverage]),
				checks.Age(row.State, opts.Checks),
				colorCell(p, tristateCell(row.State.Immutable, row.Statuses[model.CheckImmutability]), row.Statuses[model.CheckImmutability]),
				colorCell(p, tristateCell(row.State.CrossRegion, row.Statuses[model.CheckRedundancy]), row.Statuses[model.CheckRedundancy]),
				colorCell(p, restoreCell(row), row.Statuses[model.CheckRestoreTested]),
			})
		}
		t.Render()
		w.println(p.dim(strings.Repeat("─", min(len(header), 78))))
	}

	// --- Score ---
	scoreText := fmt.Sprintf("Recoverability Score: %d/100", result.Score.Value)
	gaps := fmt.Sprintf("(%d critical gap%s)", result.Score.CriticalGaps, plural(result.Score.CriticalGaps))
	w.printf("%s   %s\n", p.bold(scoreBand(p, result.Score.Value, scoreText)), p.dim(gaps))

	// Access gaps and moot checks are reported separately. Conflating them would
	// tell people to grant permissions they already have.
	if gaps := model.AccessGaps(result.Findings); gaps > 0 {
		w.println(p.warn(fmt.Sprintf(
			"%d check(s) could not be assessed — run `drillproof audit init` for the exact policy.", gaps)))
		for _, reason := range model.AccessGapReasons(result.Findings) {
			w.println(p.dim("  · " + reason))
		}
	}
	if moot := model.NotApplicable(result.Findings); moot > 0 {
		w.println(p.dim(fmt.Sprintf(
			"%d check(s) not applicable (nothing to assess — usually a resource with no backup).", moot)))
	}

	// --- Top findings ---
	if top := aws.TopFindings(result, 6); len(top) > 0 {
		w.println()
		w.println(p.bold("Top findings:"))
		for _, f := range top {
			colorise, glyph := p.fail, "x"
			if f.Status == model.StatusWarn {
				colorise, glyph = p.warn, "!"
			}
			w.printf("  %s %s — %s\n",
				colorise(glyph), f.Resource.Display, f.Summary)
		}
	}

	// --- Warnings ---
	if len(result.Warnings) > 0 && !opts.Quiet {
		w.println()
		w.println(p.dim("Notes:"))
		for _, warning := range result.Warnings {
			w.println(p.dim("  · " + warning))
		}
	}

	// --- Score explanation ---
	if opts.Explain {
		w.println()
		w.println(p.bold("How this score was calculated:"))
		for _, line := range score.Explain(result.Score) {
			w.println("  " + line)
		}
	}

	w.println()
	w.printf("Fix these free: %s   %s\n",
		p.teal(AuditURL), p.dim("(or run `drillproof audit init`)"))

	return nil
}

// backupCell renders the coverage column using the spec's vocabulary.
func backupCell(row model.Row) string {
	switch row.Statuses[model.CheckCoverage] {
	case model.StatusOK:
		return "ok"
	case model.StatusFail:
		return "none"
	default:
		return "?"
	}
}

// restoreCell renders the column the whole tool exists for.
func restoreCell(row model.Row) string {
	// A resource with no backup cannot be restored at all — the spec's sample
	// shows this as "failed" rather than a blank.
	if row.Statuses[model.CheckCoverage] == model.StatusFail {
		return "failed"
	}
	switch row.Statuses[model.CheckRestoreTested] {
	case model.StatusOK:
		return "verified"
	case model.StatusWarn:
		return "pending"
	case model.StatusFail:
		return "untested"
	default:
		return "-"
	}
}

// tristateCell shows yes/no, or "-" when the answer is genuinely unknown.
func tristateCell(t model.Tristate, status model.Status) string {
	if status == model.StatusSkipped {
		if t == model.Unknown {
			return "-"
		}
	}
	switch t {
	case model.Yes:
		return "yes"
	case model.No:
		return "no"
	default:
		return "-"
	}
}

func colorCell(p palette, value string, status model.Status) string {
	switch status {
	case model.StatusOK:
		return p.ok(value)
	case model.StatusWarn:
		return p.warn(value)
	case model.StatusFail:
		return p.fail(value)
	default:
		return p.dim(value)
	}
}

// scoreBand colours the score by severity so it reads at a glance.
func scoreBand(p palette, value int, text string) string {
	switch {
	case value >= 80:
		return p.ok(text)
	case value >= 50:
		return p.warn(text)
	default:
		return p.fail(text)
	}
}

// formatAccount groups a 12-digit account id as 1234-5678-9012.
func formatAccount(id string) string {
	if len(id) != 12 {
		return id
	}
	return fmt.Sprintf("%s-%s-%s", id[0:4], id[4:8], id[8:12])
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
