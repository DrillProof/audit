package checks

import (
	"fmt"
	"strings"

	"github.com/drillproof/audit/internal/model"
)

// S3 is not a volume — it *is* the storage — so "does a backup exist" is the
// wrong question. Coverage is reinterpreted as deletion protection, and the two
// checks that have no meaning for a live bucket (freshness, restore-testing)
// report "not applicable" rather than inventing a semantic. A fabricated
// verdict is worse than an honest N/A.

// mfaDeleteRemediation is stated in full because the constraint is real and
// non-obvious: MFA Delete cannot be set from the console or by an IAM user.
// Telling someone to "enable MFA Delete" without saying so sends them into a
// dead end.
const mfaDeleteRemediation = "MFA Delete can only be enabled by the account root user via the AWS CLI or API — it cannot be set from the console or by an IAM user. If root access is restricted in your organisation, Object Lock (compliance mode) is a stronger alternative that IAM users can configure."

// BucketTier grades a bucket's deletion protection.
//
// Object Lock in COMPLIANCE mode satisfies protection on its own. It is
// strictly stronger than MFA Delete — nothing, including root, can delete
// before retention expires — so failing a compliance-locked bucket because MFA
// Delete happens to be off would be a false positive.
//
// Exported (rather than the brief's unexported bucketTier) because internal/aws
// needs the identical grading logic and already imports this package.
func BucketTier(p *model.S3Protection) model.ProtectionTier {
	switch {
	case p.ObjectLockMode == "COMPLIANCE":
		return model.TierStrongest
	case p.Versioning == model.Yes && p.MFADelete == model.Yes:
		return model.TierStrong
	case p.Versioning == model.Yes:
		return model.TierPartial
	case p.ObjectLockMode == "GOVERNANCE":
		return model.TierWeak
	default:
		return model.TierUnprotected
	}
}

// coverageBucket reports the deletion-protection tier.
func coverageBucket(r model.Resource, s *model.BackupState) model.Finding {
	if s.S3 == nil {
		return blocked(r, model.CheckCoverage, "bucket configuration not read")
	}

	f := model.Finding{Resource: r, Check: model.CheckCoverage}
	tier := BucketTier(s.S3)

	switch tier {
	case model.TierStrongest:
		f.Status = model.StatusOK
		f.Summary = fmt.Sprintf("%s — Object Lock (compliance mode): objects cannot be deleted before retention expires", tier)
	case model.TierStrong:
		f.Status = model.StatusOK
		f.Summary = fmt.Sprintf("%s — versioning and MFA Delete are both enabled", tier)
	case model.TierPartial:
		f.Status = model.StatusWarn
		if s.S3.MFADelete == model.Unknown {
			f.Summary = fmt.Sprintf("%s — versioning is enabled; MFA Delete state could not be determined", tier)
		} else {
			f.Summary = fmt.Sprintf("%s — versioning is enabled but MFA Delete is off", tier)
		}
		f.Remediation = mfaDeleteRemediation
	case model.TierWeak:
		f.Status = model.StatusWarn
		f.Summary = fmt.Sprintf("%s — Object Lock is in governance mode only, which is overridable by anyone holding s3:BypassGovernanceRetention", tier)
		f.Remediation = "Switch the bucket to Object Lock compliance mode, or enable versioning with MFA Delete."
	default:
		f.Status = model.StatusFail
		f.Summary = fmt.Sprintf("%s — neither versioning nor Object Lock is enabled; a delete is permanent", tier)
		f.Remediation = "Enable versioning on the bucket, then add Object Lock (compliance mode) or MFA Delete."
	}
	return f
}

// immutabilityBucket reports Object Lock, independently of coverage.
//
// Deliberately does NOT short-circuit on RecoveryPoints: every bucket has zero,
// so the shared path would report every bucket as "not applicable".
func immutabilityBucket(r model.Resource, s *model.BackupState) model.Finding {
	if s.S3 == nil {
		return blocked(r, model.CheckImmutability, "s3:GetBucketObjectLockConfiguration not read")
	}

	f := model.Finding{Resource: r, Check: model.CheckImmutability}
	switch s.S3.ObjectLockMode {
	case "COMPLIANCE":
		f.Status = model.StatusOK
		f.Summary = "Object Lock is in compliance mode — objects are on WORM storage"
	case "GOVERNANCE":
		f.Status = model.StatusWarn
		f.Summary = "Object Lock is in governance mode — overridable by a principal with s3:BypassGovernanceRetention"
		f.Remediation = "Compliance mode cannot be overridden by any principal, including root. Use it where the retention guarantee has to hold under a compromised credential."
	default:
		f.Status = model.StatusFail
		f.Summary = "objects can be deleted — no Object Lock"
		f.Remediation = "Enable Object Lock (compliance mode) on the bucket. Note it can only be enabled at bucket creation unless AWS Support enables it retroactively."
	}
	return f
}

// redundancyBucket reports Cross-Region Replication.
//
// A rule that exists is not enough. A configured-but-disabled rule is the S3
// analogue of a silently failing backup schedule and is called out explicitly,
// because that is exactly the finding a customer cannot see for themselves.
func redundancyBucket(r model.Resource, s *model.BackupState) model.Finding {
	if s.S3 == nil {
		return blocked(r, model.CheckRedundancy, "s3:GetBucketReplication not read")
	}

	rep := s.S3.Replication
	f := model.Finding{Resource: r, Check: model.CheckRedundancy}

	if rep.Configured == model.Unknown {
		return blocked(r, model.CheckRedundancy, "s3:GetBucketReplication denied")
	}
	if rep.Configured == model.No {
		f.Status = model.StatusFail
		f.Summary = fmt.Sprintf("no replication is configured — every object exists only in %s", r.Region)
		f.Remediation = "Add a Cross-Region Replication rule targeting a bucket in another region, so a region-level event does not take the data with it."
		return f
	}
	if rep.EnabledRule == model.No {
		f.Status = model.StatusFail
		f.Summary = "replication is configured but disabled — no object is being copied anywhere"
		f.Remediation = "Set the replication rule's status to Enabled. A disabled rule looks like protection in the console and provides none."
		return f
	}
	if rep.CrossRegion == model.Unknown {
		return blocked(r, model.CheckRedundancy,
			"s3:GetBucketLocation denied on the replication destination")
	}
	if rep.CrossRegion == model.No {
		f.Status = model.StatusFail
		f.Summary = fmt.Sprintf("replication targets the same region (%s) as the source", strings.Join(rep.DestRegions, ", "))
		f.Remediation = "Point at least one enabled replication rule at a bucket in a different region."
		return f
	}

	f.Status = model.StatusOK
	f.Summary = fmt.Sprintf("replicated to %s", strings.Join(rep.DestRegions, ", "))
	return f
}
