package checks

import (
	"fmt"
	"math"
	"strings"

	"github.com/drillproof/audit/internal/model"
)

// keyRank orders key outcomes from worst to best. One resource can have
// recovery points under several keys, and it produces exactly ONE finding —
// both scorers accumulate deductions per resource, so N findings for one
// resource would deduct N times.
type keyRank int

const (
	rankDeleted keyRank = iota
	rankPendingDeletion
	rankNoMaterial
	rankDisabled
	rankUnreadable // includes cross-account we cannot describe, and unknown account
	rankCrossAccountOK
	rankOK
)

// classify maps one key to its rank. Anything we could not read outranks any
// OK: a resource where one of three keys is unknown is not a resource we
// verified.
func classify(k model.RecoveryPointKey) keyRank {
	// Account attribution failed — we do not know whose key this is, so we
	// must not claim it is fine and must not claim it is broken.
	if k.CrossAccount == model.Unknown {
		return rankUnreadable
	}
	if k.State == "" {
		return rankUnreadable
	}
	// An AWS-managed key cannot be disabled or deleted by the customer.
	// Flagging one would be a false positive with no action behind it.
	if k.AWSManaged {
		return rankOK
	}
	switch k.State {
	case "Deleted":
		return rankDeleted
	case "PendingDeletion":
		return rankPendingDeletion
	case "PendingImport", "Unavailable":
		return rankNoMaterial
	case "Disabled":
		return rankDisabled
	}
	if k.CrossAccount == model.Yes {
		return rankCrossAccountOK
	}
	return rankOK
}

// KeyAvailability — can these recovery points still be decrypted?
//
// Deliberately NOT "is encryption enabled": that is security posture, which
// DrillProof does not do. The only question here is whether the key a restore
// would need will actually be there.
func KeyAvailability(r model.Resource, s *model.BackupState, cfg Config) model.Finding {
	if reason, ok := s.Unassessed[model.CheckKeyAvailability]; ok {
		return blocked(r, model.CheckKeyAvailability, reason)
	}
	// A resource with no backup is already zeroed by coverage. Deducting here
	// too would penalise the same gap twice.
	if s.RecoveryPoints == 0 {
		return moot(r, model.CheckKeyAvailability, "no backup exists to decrypt")
	}
	if len(s.Keys) == 0 {
		return moot(r, model.CheckKeyAvailability, "backups are not encrypted with a KMS key")
	}

	worst, worstRank := s.Keys[0], classify(s.Keys[0])
	for _, k := range s.Keys[1:] {
		if rk := classify(k); rk < worstRank {
			worst, worstRank = k, rk
		}
	}

	count := fmt.Sprintf("%d key(s)", len(s.Keys))
	f := model.Finding{Resource: r, Check: model.CheckKeyAvailability}

	switch worstRank {
	case rankDeleted:
		f.Status = model.StatusFail
		f.Summary = fmt.Sprintf("the KMS key protecting these recovery points no longer exists (%s; %s) — they cannot be restored", short(worst.KeyARN), count)
		// No remediation: there is nothing the customer can do. Offering one
		// would be worse than silence.
		return f

	case rankPendingDeletion:
		when := "an unreported date"
		days := ""
		if worst.DeletionDate != nil {
			when = worst.DeletionDate.Format("2006-01-02")
			d := int(math.Ceil(worst.DeletionDate.Sub(cfg.Now).Hours() / 24))
			days = fmt.Sprintf(", %d day(s) from now", d)
		}
		f.Status = model.StatusFail
		f.Summary = fmt.Sprintf("the KMS key protecting these recovery points is scheduled for deletion on %s%s (%s; %s)", when, days, short(worst.KeyARN), count)
		f.Remediation = fmt.Sprintf("Cancel the key deletion (kms:CancelKeyDeletion on %s) before %s, or these recovery points become permanently unrecoverable.", short(worst.KeyARN), when)
		return f

	case rankNoMaterial:
		f.Status = model.StatusFail
		f.Summary = fmt.Sprintf("the KMS key protecting these recovery points has no key material available (%s, state %s; %s)", short(worst.KeyARN), worst.State, count)
		f.Remediation = "Re-import the key material for this key, or the recovery points it protects cannot be decrypted."
		return f

	case rankDisabled:
		f.Status = model.StatusFail
		f.Summary = fmt.Sprintf("the KMS key protecting these recovery points is disabled (%s; %s) — a restore will fail until it is re-enabled", short(worst.KeyARN), count)
		f.Remediation = fmt.Sprintf("Re-enable the key (kms:EnableKey on %s).", short(worst.KeyARN))
		return f

	case rankUnreadable:
		if worst.CrossAccount == model.Unknown {
			return moot(r, model.CheckKeyAvailability,
				fmt.Sprintf("could not determine which account owns %s", short(worst.KeyARN)))
		}
		return blocked(r, model.CheckKeyAvailability,
			fmt.Sprintf("cross-account key %s could not be described — kms:DescribeKey in the owning account", short(worst.KeyARN)))

	case rankCrossAccountOK:
		f.Status = model.StatusWarn
		f.Summary = fmt.Sprintf("these recovery points depend on a KMS key in another account (%s; %s) — the owning account can revoke access without warning", short(worst.KeyARN), count)
		f.Remediation = "Confirm with the key's owning account that access will not be revoked, or re-encrypt these backups with a key you control."
		return f
	}

	f.Status = model.StatusOK
	if worst.AWSManaged {
		f.Summary = fmt.Sprintf("recovery points are protected by an AWS-managed KMS key (%s)", count)
		return f
	}
	f.Summary = fmt.Sprintf("every KMS key protecting these recovery points is enabled (%s)", count)
	return f
}

// short trims a key ARN to its trailing id so a finding reads as prose rather
// than as a wrapped ARN in a terminal table.
func short(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 && i < len(arn)-1 {
		return arn[i+1:]
	}
	return arn
}
