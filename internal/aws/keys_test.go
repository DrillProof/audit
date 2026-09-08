package aws

import (
	"context"
	"testing"

	"github.com/drillproof/audit/internal/model"
)

func TestResolveKeys(t *testing.T) {
	const self = "111122223333"
	inAcct := "arn:aws:kms:us-east-1:111122223333:key/abc"
	foreign := "arn:aws:kms:us-east-1:999988887777:key/xyz"

	t.Run("enabled customer key", func(t *testing.T) {
		p := providerWithKMS(&fakeKMS{states: map[string]kmsFakeKey{
			inAcct: {state: "Enabled", manager: "CUSTOMER"},
		}})
		s := model.NewBackupState()
		resolveKeys(context.Background(), p, self, []string{inAcct}, "us-east-1", s)
		if len(s.Keys) != 1 {
			t.Fatalf("keys = %+v", s.Keys)
		}
		if s.Keys[0].State != "Enabled" || s.Keys[0].AWSManaged || s.Keys[0].CrossAccount != model.No {
			t.Fatalf("key = %+v", s.Keys[0])
		}
	})

	t.Run("pending deletion carries the date", func(t *testing.T) {
		p := providerWithKMS(&fakeKMS{states: map[string]kmsFakeKey{
			inAcct: {state: "PendingDeletion", manager: "CUSTOMER", deletionDay: "2026-09-14"},
		}})
		s := model.NewBackupState()
		resolveKeys(context.Background(), p, self, []string{inAcct}, "us-east-1", s)
		if s.Keys[0].DeletionDate == nil {
			t.Fatal("DeletionDate not captured")
		}
	})

	t.Run("aws managed key is marked", func(t *testing.T) {
		p := providerWithKMS(&fakeKMS{states: map[string]kmsFakeKey{
			inAcct: {state: "Enabled", manager: "AWS"},
		}})
		s := model.NewBackupState()
		resolveKeys(context.Background(), p, self, []string{inAcct}, "us-east-1", s)
		if !s.Keys[0].AWSManaged {
			t.Fatal("AWSManaged not set")
		}
	})

	t.Run("not found becomes Deleted, not an error", func(t *testing.T) {
		p := providerWithKMS(&fakeKMS{notFound: map[string]bool{inAcct: true}})
		s := model.NewBackupState()
		resolveKeys(context.Background(), p, self, []string{inAcct}, "us-east-1", s)
		if s.Keys[0].State != "Deleted" {
			t.Fatalf("state = %q, want Deleted", s.Keys[0].State)
		}
		if _, blocked := s.Unassessed[model.CheckKeyAvailability]; blocked {
			t.Fatal("a missing key is a verdict, not a permission gap")
		}
	})

	t.Run("access denied blocks the check and names the action", func(t *testing.T) {
		p := providerWithKMS(&fakeKMS{denied: map[string]bool{inAcct: true}})
		s := model.NewBackupState()
		resolveKeys(context.Background(), p, self, []string{inAcct}, "us-east-1", s)
		reason, ok := s.Unassessed[model.CheckKeyAvailability]
		if !ok || reason != "kms:DescribeKey denied" {
			t.Fatalf("unassessed = %q ok=%v", reason, ok)
		}
	})

	t.Run("a throttle leaves the key unreadable, not denied", func(t *testing.T) {
		p := providerWithKMS(&fakeKMS{throttled: map[string]bool{inAcct: true}})
		s := model.NewBackupState()
		resolveKeys(context.Background(), p, self, []string{inAcct}, "us-east-1", s)
		if _, blocked := s.Unassessed[model.CheckKeyAvailability]; blocked {
			t.Fatal("a throttle is not a permission the customer can grant")
		}
		if s.Keys[0].State != "" {
			t.Fatalf("state = %q, want empty (unreadable)", s.Keys[0].State)
		}
	})

	t.Run("cross-account key is flagged even when describable", func(t *testing.T) {
		p := providerWithKMS(&fakeKMS{states: map[string]kmsFakeKey{
			foreign: {state: "Enabled", manager: "CUSTOMER"},
		}})
		s := model.NewBackupState()
		resolveKeys(context.Background(), p, self, []string{foreign}, "us-east-1", s)
		if s.Keys[0].CrossAccount != model.Yes {
			t.Fatalf("CrossAccount = %v, want Yes", s.Keys[0].CrossAccount)
		}
	})

	t.Run("unknown scanned account never resolves ownership", func(t *testing.T) {
		p := providerWithKMS(&fakeKMS{states: map[string]kmsFakeKey{
			inAcct: {state: "Enabled", manager: "CUSTOMER"},
		}})
		s := model.NewBackupState()
		resolveKeys(context.Background(), p, "unknown", []string{inAcct}, "us-east-1", s)
		if s.Keys[0].CrossAccount != model.Unknown {
			t.Fatalf("CrossAccount = %v, want Unknown", s.Keys[0].CrossAccount)
		}
	})

	t.Run("duplicate ARNs are described once", func(t *testing.T) {
		f := &fakeKMS{states: map[string]kmsFakeKey{inAcct: {state: "Enabled", manager: "CUSTOMER"}}}
		p := providerWithKMS(f)
		s := model.NewBackupState()
		resolveKeys(context.Background(), p, self, []string{inAcct, inAcct, inAcct}, "us-east-1", s)
		if f.calls != 1 {
			t.Fatalf("DescribeKey called %d times, want 1", f.calls)
		}
		if len(s.Keys) != 1 {
			t.Fatalf("keys = %+v", s.Keys)
		}
	})
}
