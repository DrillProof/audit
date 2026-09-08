package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/drillproof/audit/internal/model"
)

func keyRes() model.Resource {
	return model.Resource{Display: "data (EBS)", Name: "data", Type: model.TypeVolume, Region: "us-east-1"}
}

func stateWithKeys(keys ...model.RecoveryPointKey) *model.BackupState {
	s := model.NewBackupState()
	s.RecoveryPoints = 1
	s.Keys = keys
	return s
}

func inAccount(state string) model.RecoveryPointKey {
	return model.RecoveryPointKey{
		KeyARN:       "arn:aws:kms:us-east-1:111122223333:key/abc",
		State:        state,
		CrossAccount: model.No,
	}
}

func TestKeyAvailabilityStates(t *testing.T) {
	deletionDate := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	cfg := Config{Now: time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)}

	cases := []struct {
		name    string
		key     model.RecoveryPointKey
		want    model.Status
		gap     bool
		contain string
	}{
		{"enabled", inAccount("Enabled"), model.StatusOK, false, "enabled"},
		{"disabled", inAccount("Disabled"), model.StatusFail, false, "disabled"},
		{"pending import", inAccount("PendingImport"), model.StatusFail, false, "key material"},
		{"unavailable", inAccount("Unavailable"), model.StatusFail, false, "key material"},
		{
			"aws managed",
			model.RecoveryPointKey{KeyARN: "arn:aws:kms:us-east-1:111122223333:key/aws", State: "Enabled", AWSManaged: true, CrossAccount: model.No},
			model.StatusOK, false, "AWS-managed",
		},
		{
			"cross account enabled",
			model.RecoveryPointKey{KeyARN: "arn:aws:kms:us-east-1:999988887777:key/x", State: "Enabled", CrossAccount: model.Yes},
			model.StatusWarn, false, "another account",
		},
		{
			"cross account unresolvable",
			model.RecoveryPointKey{KeyARN: "arn:aws:kms:us-east-1:999988887777:key/x", CrossAccount: model.Yes},
			model.StatusSkipped, true, "cross-account",
		},
		{
			"account id unknown",
			model.RecoveryPointKey{KeyARN: "arn:aws:kms:us-east-1:999988887777:key/x", State: "Enabled", CrossAccount: model.Unknown},
			model.StatusSkipped, false, "could not determine",
		},
		{"deleted", inAccount("Deleted"), model.StatusFail, false, "no longer exists"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := KeyAvailability(keyRes(), stateWithKeys(tc.key), cfg)
			if f.Status != tc.want {
				t.Fatalf("status = %q, want %q (%s)", f.Status, tc.want, f.Summary)
			}
			if f.Status == model.StatusSkipped && f.SkipIsAccessGap != tc.gap {
				t.Fatalf("SkipIsAccessGap = %v, want %v", f.SkipIsAccessGap, tc.gap)
			}
			if !strings.Contains(f.Summary, tc.contain) {
				t.Fatalf("summary %q does not contain %q", f.Summary, tc.contain)
			}
		})
	}

	t.Run("pending deletion carries the countdown", func(t *testing.T) {
		k := inAccount("PendingDeletion")
		k.DeletionDate = &deletionDate
		f := KeyAvailability(keyRes(), stateWithKeys(k), cfg)
		if f.Status != model.StatusFail {
			t.Fatalf("status = %q", f.Status)
		}
		if !strings.Contains(f.Summary, "2026-09-14") {
			t.Fatalf("summary missing deletion date: %q", f.Summary)
		}
		if !strings.Contains(f.Summary, "7 day") {
			t.Fatalf("summary missing days remaining: %q", f.Summary)
		}
		if !strings.Contains(f.Remediation, "CancelKeyDeletion") {
			t.Fatalf("remediation missing CancelKeyDeletion: %q", f.Remediation)
		}
	})

	t.Run("deleted key offers no remediation", func(t *testing.T) {
		f := KeyAvailability(keyRes(), stateWithKeys(inAccount("Deleted")), cfg)
		if f.Remediation != "" {
			t.Fatalf("deleted key must not offer remediation, got %q", f.Remediation)
		}
	})
}

func TestKeyAvailabilityAggregation(t *testing.T) {
	cfg := Config{Now: time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)}

	t.Run("worst key wins and the others are named", func(t *testing.T) {
		bad := inAccount("Disabled")
		bad.KeyARN = "arn:aws:kms:us-east-1:111122223333:key/bad"
		f := KeyAvailability(keyRes(), stateWithKeys(inAccount("Enabled"), bad, inAccount("Enabled")), cfg)
		if f.Status != model.StatusFail {
			t.Fatalf("status = %q, want fail", f.Status)
		}
		if !strings.Contains(f.Summary, "3 key") {
			t.Fatalf("summary should report the key count: %q", f.Summary)
		}
	})

	t.Run("an unreadable key outranks an OK one", func(t *testing.T) {
		unreadable := model.RecoveryPointKey{KeyARN: "arn:aws:kms:us-east-1:999988887777:key/x", CrossAccount: model.Yes}
		f := KeyAvailability(keyRes(), stateWithKeys(inAccount("Enabled"), unreadable), cfg)
		if f.Status != model.StatusSkipped {
			t.Fatalf("status = %q, want skipped", f.Status)
		}
	})
}

func TestKeyAvailabilityHonesty(t *testing.T) {
	cfg := Config{Now: time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)}

	t.Run("describe key denied is an access gap", func(t *testing.T) {
		s := stateWithKeys(inAccount("Enabled"))
		s.MarkUnassessed(model.CheckKeyAvailability, "kms:DescribeKey denied")
		f := KeyAvailability(keyRes(), s, cfg)
		if f.Status != model.StatusSkipped || !f.SkipIsAccessGap {
			t.Fatalf("want blocked access gap, got %q gap=%v", f.Status, f.SkipIsAccessGap)
		}
		if !strings.Contains(f.SkipReason, "kms:DescribeKey") {
			t.Fatalf("reason must name the action: %q", f.SkipReason)
		}
	})

	t.Run("no encrypted backups is moot, not blocked", func(t *testing.T) {
		s := model.NewBackupState()
		s.RecoveryPoints = 2
		f := KeyAvailability(keyRes(), s, cfg)
		if f.Status != model.StatusSkipped || f.SkipIsAccessGap {
			t.Fatalf("want moot, got %q gap=%v", f.Status, f.SkipIsAccessGap)
		}
	})

	t.Run("no backup at all is moot — no double penalty", func(t *testing.T) {
		s := model.NewBackupState()
		f := KeyAvailability(keyRes(), s, cfg)
		if f.Status != model.StatusSkipped || f.SkipIsAccessGap {
			t.Fatalf("want moot, got %q gap=%v", f.Status, f.SkipIsAccessGap)
		}
		if !strings.Contains(f.SkipReason, "no backup") {
			t.Fatalf("reason should say why: %q", f.SkipReason)
		}
	})

	t.Run("a same-account key that could not be read is moot, not an access gap", func(t *testing.T) {
		// State == "" with CrossAccount == No: resolveKeys' default branch
		// (throttle, 5xx, malformed ARN) — never a permission denial, since a
		// genuine denial is caught by the Unassessed lookup above and never
		// reaches classify() at all. Must not be reported as cross-account
		// (there is no other account) and must not be reported as an access
		// gap (the customer already holds every permission that matters).
		unreadable := model.RecoveryPointKey{
			KeyARN:       "arn:aws:kms:us-east-1:111122223333:key/abc",
			State:        "",
			CrossAccount: model.No,
		}
		f := KeyAvailability(keyRes(), stateWithKeys(unreadable), cfg)
		if f.Status != model.StatusSkipped {
			t.Fatalf("want skipped, got %q", f.Status)
		}
		if f.SkipIsAccessGap {
			t.Fatalf("want SkipIsAccessGap = false, got true — a same-account read failure is not a permission gap")
		}
		if strings.Contains(f.Summary, "cross-account") || strings.Contains(f.Summary, "owning account") {
			t.Fatalf("summary must not claim another account is involved: %q", f.Summary)
		}
	})
}

// TestSummariesCarryTheSubstringsTheScorerMatches guards the coupling
// between this check and internal/score/score.go's weigh(), which decides
// whether a KEY_AVAILABILITY finding is fatal (zeroes the resource) or
// merely bad by substring-matching this check's Summary prose — it does not
// look at the rank computed above. The golden fixtures cannot catch a
// reworded summary because they are regenerated from this same code, so a
// reword plus a fixture regen passes green even though it silently changes
// scoring. Whoever breaks this test must update weigh() in BOTH the Go and
// TypeScript scorers, not just adjust the test.
func TestSummariesCarryTheSubstringsTheScorerMatches(t *testing.T) {
	cfg := Config{Now: time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)}

	deleted := KeyAvailability(keyRes(), stateWithKeys(inAccount("Deleted")), cfg)
	if !strings.Contains(deleted.Summary, "no longer exists") {
		t.Fatalf("Deleted summary must contain %q (score.go matches on it): %q", "no longer exists", deleted.Summary)
	}

	pendingDeletion := KeyAvailability(keyRes(), stateWithKeys(inAccount("PendingDeletion")), cfg)
	if !strings.Contains(pendingDeletion.Summary, "scheduled for deletion") {
		t.Fatalf("PendingDeletion summary must contain %q (score.go matches on it): %q", "scheduled for deletion", pendingDeletion.Summary)
	}

	// Converse: a Disabled key is bad but recoverable, and must NOT trip
	// either fatal substring — an accidental reword INTO one of these
	// phrases would silently zero a recoverable resource's score.
	disabled := KeyAvailability(keyRes(), stateWithKeys(inAccount("Disabled")), cfg)
	if strings.Contains(disabled.Summary, "no longer exists") || strings.Contains(disabled.Summary, "scheduled for deletion") {
		t.Fatalf("Disabled summary must not contain either fatal substring: %q", disabled.Summary)
	}
}

func TestRunReturnsSixChecks(t *testing.T) {
	got := Run(keyRes(), stateWithKeys(inAccount("Enabled")), DefaultConfig())
	if len(got) != 6 {
		t.Fatalf("Run returned %d findings, want 6", len(got))
	}
	if got[5].Check != model.CheckKeyAvailability {
		t.Fatalf("last check = %q", got[5].Check)
	}
}
