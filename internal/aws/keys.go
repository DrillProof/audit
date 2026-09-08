package aws

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/drillproof/audit/internal/model"
)

// resolveKeys describes each distinct KMS key protecting a resource's recovery
// points and records its state on the BackupState.
//
// It reads key STATE only. No key material is accessed and no decryption is
// attempted — that is the claim the customer-facing template description makes,
// and api_readonly_test.go is what keeps it true.
func resolveKeys(ctx context.Context, p Provider, accountID string, arns []string, region string, state *model.BackupState) {
	if len(arns) == 0 {
		return
	}

	// Describe each key once. A resource with forty recovery points under one
	// key must not make forty identical API calls.
	seen := map[string]bool{}
	var distinct []string
	for _, a := range arns {
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		distinct = append(distinct, a)
	}
	sort.Strings(distinct) // deterministic output; the table order must not depend on AWS

	for _, arn := range distinct {
		k := model.RecoveryPointKey{KeyARN: arn, CrossAccount: keyOwnership(accountID, arn)}

		// A cross-region AWS Backup copy's recovery point is encrypted with a
		// key in the *destination* region, not the resource's own region. The
		// ARN carries that region in field 3, so the client must be chosen per
		// key — describing every key with the resource's regional endpoint
		// would return NotFoundException for an out-of-region key and record a
		// perfectly-live key as "Deleted", the worst false positive this check
		// can produce.
		c := p.For(keyRegion(arn, region))

		keyID := arn
		out, err := c.KMS.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &keyID})
		switch {
		case err == nil && out.KeyMetadata != nil:
			k.State = string(out.KeyMetadata.KeyState)
			k.AWSManaged = out.KeyMetadata.KeyManager == kmstypes.KeyManagerTypeAws
			k.DeletionDate = out.KeyMetadata.DeletionDate

		case isKeyNotFound(err):
			// The key is gone. That is a verdict — the strongest one this
			// check produces — not a failure to look.
			k.State = "Deleted"

		case IsAccessDenied(err):
			// Only a real denial. A throttle below must NOT land here: telling
			// a customer to grant a permission they already hold is a false
			// statement about their estate.
			state.MarkUnassessed(model.CheckKeyAvailability, "kms:DescribeKey denied")

		default:
			// Throttle, 5xx, malformed ARN: unreadable, but not a permission
			// gap. State stays empty and the check reports "not assessed".
		}

		state.Keys = append(state.Keys, k)
	}
}

// arnField returns field idx of a colon-delimited ARN (0="arn", 1=partition,
// 2=service, 3=region, 4=account, 5+=resource), and whether it was present and
// non-empty. Shared by every caller that needs to pick a field out of an ARN
// so there is exactly one guarded splitter, not several subtly different ones.
func arnField(arn string, idx int) (string, bool) {
	parts := strings.Split(arn, ":")
	if len(parts) <= idx || parts[idx] == "" {
		return "", false
	}
	return parts[idx], true
}

// keyRegion returns the region a key ARN names (field 3), falling back to
// fallback when the ARN is unparsable or the field is empty — which leaves an
// unparsable ARN exactly as unreadable as it already was, since it will still
// land in resolveKeys' default branch.
func keyRegion(arn, fallback string) string {
	if r, ok := arnField(arn, 3); ok {
		return r
	}
	return fallback
}

// keyOwnership reports whether a key ARN belongs to the account being scanned.
//
// Unknown when the scanned account id could not be resolved — GetCallerIdentity
// falls back to the literal "unknown", and comparing an ARN against that string
// would classify every key as foreign. Unknown makes the check skip, which is
// the honest answer.
func keyOwnership(accountID, arn string) model.Tristate {
	if accountID == "" || accountID == "unknown" {
		return model.Unknown
	}
	acct, ok := arnField(arn, 4)
	if !ok {
		return model.Unknown
	}
	if acct == accountID {
		return model.No
	}
	return model.Yes
}

func isKeyNotFound(err error) bool {
	var nf *kmstypes.NotFoundException
	return errors.As(err, &nf)
}
