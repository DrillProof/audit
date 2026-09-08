# `drillproof audit` — how it works and how to run it

Companion to [`audit_cli_guide.md`](audit_cli_guide.md), which is the *spec*.
This document is the *implementation*: what actually happens when you run the
tool, why it is built this way, and how to operate it.

---

## 1. Quick start

```sh
cd cli
go build -o drillproof ./cmd/drillproof

# The provider and regions are auto-detected from your credential chain
./drillproof audit scan --profile <your-aws-profile>

# Faster: narrow to the regions you actually use
./drillproof audit scan --profile <your-aws-profile> --region us-east-1,eu-west-1
```

Requires Go 1.24+ to build. Nothing else — no config file, no signup, no account.

If a permission is missing, the scan still completes and tells you which call was
denied. Run `./drillproof audit init` to get the exact policy.

---

## 2. What happens during a scan

```
                        ┌─────────────────────────┐
  credential chain ───► │  sts:GetCallerIdentity  │  who am I? (fatal if this fails —
                        └───────────┬─────────────┘   without an account we cannot
                                    │                  build ARNs)
                                    ▼
                        ┌─────────────────────────┐
                        │  ec2:DescribeRegions    │  which regions are enabled?
                        └───────────┬─────────────┘  (--region only narrows this)
                                    ▼
                        ┌─────────────────────────┐
                        │  Vault index            │  every AWS Backup vault in every
                        │  (all regions first)    │  region + its Vault Lock state
                        └───────────┬─────────────┘
                                    │  ← must be global: "is there a copy in
                                    │    another region?" is unanswerable
                                    │    one region at a time
                                    ▼
        ┌───────────────────────────────────────────────────┐
        │  Inventory, 4 regions in parallel                  │
        │    ec2:DescribeVolumes      → EBS volumes          │
        │    rds:DescribeDBInstances  → databases            │
        │    rds:DescribeDBClusters   → clusters             │
        │    eks:ListClusters         → cluster state        │
        └───────────────────────┬───────────────────────────┘
                                ▼
        ┌───────────────────────────────────────────────────┐
        │  Per resource: gather evidence → model.BackupState │
        │    recovery points, newest backup time,            │
        │    lock state, cross-region copies, restore history │
        └───────────────────────┬───────────────────────────┘
                                ▼
        ┌───────────────────────────────────────────────────┐
        │  Five pure checks  →  findings  →  score            │
        └───────────────────────────────────────────────────┘
```

The important architectural line: **discovery talks to AWS, checks do not.**
Discovery translates SDK responses into one plain struct (`model.BackupState`),
and the six checks are pure functions of that struct. That is why the whole test
suite runs with no AWS credentials, and why the score is reproducible.

---

## 3. Where each check's answer comes from

This is the part worth reading before trusting a result.

| Check | Signal used | Notes |
| --- | --- | --- |
| **Coverage** | AWS Backup recovery points with status `COMPLETED` for the resource ARN. Falls back to native EBS/RDS snapshots. | The fallback matters: a team using plain snapshots is not "unprotected", and reporting them as such would be wrong. |
| **Freshness** | `CompletionDate` (or `CreationDate`) of the newest completed recovery point. | Skipped as *not applicable* when there is no backup — coverage already reports that, and double-penalising one root cause would distort the score. |
| **Immutability** | AWS Backup **Vault Lock** (`DescribeBackupVault.Locked`). | Native snapshots are reported as **not** immutable — a known negative, not an unknown. If we cannot read lock state at all, the check is *blocked*, never assumed safe. |
| **Redundancy** | Whether the same resource ARN has a recovery point in a vault in a *different* region. | This is why vaults are indexed across all regions before inventory runs. Narrowing `--region` narrows what redundancy can prove. |
| **Restore-testing** | `RecoveryPointByBackupVault.LastRestoreTime`, plus `ListRestoreTestingPlans`. | A real restore → **ok**. A restore-testing plan configured but never run → **warn**. Nothing at all → **fail**. |

### Cluster state (EKS) is the special case

AWS APIs cannot see Velero backups. So:

- **Without `--kubeconfig`**, cluster-state coverage is reported as **not
  assessed**, with a note telling you to pass it. We have not looked inside the
  cluster, so we do not claim it is unbacked.
- **With `--kubeconfig`**, the tool uses the discovery client to check for the
  `velero.io` API group, then lists Velero `Backups`, `Schedules`, and `Restores`
  via the dynamic client. A completed Velero `Restore` is exactly the proof this
  tool looks for, and marks cluster state **verified**.
- Evidence is only credited to a cluster if the kubeconfig plausibly points at it
  (context name or server URL contains the EKS cluster name). Crediting one
  cluster with another's backups would be worse than declining to attribute.

> **This deliberately differs from the spec.** The sample table in
> `audit_cli_guide.md` §7 shows `etcd (prod-cluster)` as an outright coverage
> failure. Doing that without cluster access would risk a false accusation
> against a cluster that *is* backed up by Velero, and §5 makes score
> credibility non-negotiable. Honesty won.

---

## 4. "Not assessed" is never a pass

A check that produced no verdict is reported as one of two things, and the
distinction is deliberate:

- **Blocked** — we were not permitted to look. `12 check(s) could not be
  assessed`, followed by the denied operation. Fixable by granting a permission.
- **Not applicable** — there was nothing to look at. A volume with no backup has
  no backup age, no cross-region copy, and no restore history. No permission
  changes that.

Conflating these was a real bug caught by running against a live account: the
tool reported 16 checks as blocked "due to missing permissions" when in fact those
volumes simply had no backups. Telling someone to grant permissions they already
have is a false statement about their estate, which is precisely what the score's
credibility cannot survive.

---

## 5. The score

A coverage failure zeroes a resource outright — it is unrecoverable, and its
other checks have nothing left to assess. Otherwise a resource starts at 100
and loses a documented weight per remaining failing check; the estate score is
the criticality-weighted mean of those per-resource values.

`raw_deduction` (in the JSON output and below) is a different number: the
absolute sum of every deduction a resource would have taken with no zeroing
and no floor, which is why the coverage-critical `+10` bonus below still shows
up there even though it can never move a resource score that coverage already
zeroed. It is the schedule that number follows:

| Failing check (contributes to `raw_deduction`) | Deduction | Constant |
| --- | --- | --- |
| Coverage — no backup | −25 | `WeightCoverageFail` |
| …and it is cluster state or a production DB | −10 more | `WeightCoverageCriticalBonus` |
| Immutability | −10 | `WeightImmutabilityFail` |
| Freshness (past fail threshold) | −8 | `WeightFreshnessFail` |
| Freshness (past warn threshold) | −4 | `WeightFreshnessWarn` |
| Redundancy | −6 | `WeightRedundancyFail` |
| Never test-restored | −5 | `WeightRestoreUntested` |

All in `internal/score/score.go`, with the reasoning written beside them.

`--explain` prints the arithmetic so a skeptic can check it:

```
Per-resource recoverability:
    0/100  vol-01466b3d919b0c5c1
   79/100  seekinvest-postgres   (counts 2x: critical resource)
   92/100  finnhub-etl-volume

Deductions:
  -25  vol-01466b3d919b0c5c1 — no backup exists (coverage)
  -10  seekinvest-postgres — backups are deletable (no WORM/Object Lock) (immutability)
  -8   finnhub-etl-volume — most recent backup is beyond the failure threshold (freshness)
  -6   seekinvest-postgres — backups exist in only one region (redundancy)
  -5   seekinvest-postgres — never test-restored (restore-testing)

Recoverability Score: 63/100  (weighted mean of 3 resource(s))
Total raw deduction: 54
Checks assessed: 11 — 0 blocked by permissions, 4 not applicable
```

Two properties worth knowing:

- **Deterministic.** Same estate → same score, regardless of the order results
  arrive in. Regions are scanned concurrently, but results are sorted before
  scoring.
- **Nothing assessable scores 0, not 100.** An account we cannot read is not an
  account with perfect backups.

The score is a **criticality-weighted mean of per-resource scores**, not a sum of
deductions, so it does not saturate: an estate of 100 resources with 4
unprotected scores 91, and one with 50 unprotected scores 48. Before v2.0.0 the
deductions were absolute and the fourth unprotected resource zeroed any account
of any size — a 96%-protected estate reported the same 0 as an estate with
nothing backed up.

Per resource: a coverage failure scores it 0 (it is unrecoverable, and its other
checks have nothing to assess); otherwise it starts at 100 and loses its quality
penalties. Resources whose every check was skipped are excluded from the mean —
never scored 0, which would report a permission gap as a recoverability gap.
`raw_deduction` in the JSON output still preserves the absolute depth, which the
normalized value deliberately no longer expresses.

This means a v1 score and a v2 score for the same estate are not the same
number and must not be compared: because v2 no longer saturates, a `--fail-under`
gate calibrated against v1's behavior may now pass where it used to fail. Recheck
your gate's threshold after upgrading rather than assuming the old value still
means what it did.

---

## 5a. EFS

EFS filesystems ride the normal per-region fan-out (`internal/aws/filesystems.go`),
with states keyed by filesystem ARN. Discovery reads four EFS actions:
`DescribeFileSystems`, `DescribeBackupPolicy`, `DescribeReplicationConfigurations`,
and `ListTagsForResource`.

- **Coverage** accepts EFS's own automatic-backup feature (a separate AWS Backup
  default plan, enabled at filesystem creation) *or* a recovery point from a
  user-defined AWS Backup plan. Either one is real protection; treating only the
  plan as valid would fail filesystems that are correctly backed up.
- **Redundancy** accepts an AWS Backup cross-region copy *or* healthy cross-region
  EFS Replication — EFS's own replication feature, independent of AWS Backup.
  Same-region replication and unhealthy replication both **fail**, with wording
  that says which: "targets the same region as the filesystem" for the former,
  "configured but not healthy" for the latter. Unreadable replication health
  (`Unknown`) is never treated as healthy — it is reported as `blocked`, same as
  any other permission gap.
- **Freshness, immutability, and restore-testing have no EFS-specific branch.**
  The shared AWS Backup-based helpers already give the right answer for a
  filesystem's recovery points, so there was nothing to reinterpret — unlike
  coverage and redundancy, which needed EFS's own backup and replication
  features folded in alongside AWS Backup.
- **One Zone is context, not its own check.** A One Zone filesystem
  (`Resource.Attrs["storage_class"] == "one-zone"`) has no second copy of its
  own, so a One Zone filesystem with no backup at all is flagged as a
  compounding risk: it takes the coverage-critical `+10` bonus the same way a
  production database does (`criticalForCoverage` in `internal/score/score.go`).
  This deliberately does **not** change the resource's weight in the estate
  mean — `isCritical` is untouched by storage class — because a One Zone
  filesystem that *is* backed up is a legitimate cost decision, and penalising
  it for its storage class would be penalising the architecture, not the
  recoverability.

Two deliberate divergences from the spec, in addition to the EKS one above:

1. `elasticfilesystem:ListTagsForResource` is requested and called even though
   `DescribeFileSystems` also returns tags. The dedicated call keeps the
   production-tag heuristic identical across resource types, and
   `internal/iam`'s two-way drift test requires the interface and the policy to
   agree exactly — reading tags off `DescribeFileSystems` instead would leave a
   permission granted but never called, which that test rejects.
2. The One Zone signal rides on `Resource.Attrs["storage_class"]` rather than on
   `BackupState`. The scorer (`internal/score`) only ever sees findings, not
   discovery state, so the only place left to carry storage class forward is the
   resource itself.

---

## 6. Running it

### Common invocations

```sh
# Everything, auto-detected (slowest — 17 regions took ~50s on a small account)
drillproof audit scan --profile prod

# Realistic day-to-day
drillproof audit scan --profile prod --region us-east-1,eu-west-1 --explain

# Include cluster state
drillproof audit scan --profile prod --kubeconfig ~/.kube/config --context prod

# CI gate
drillproof audit score --profile ci --fail-under 80

# Artifacts
drillproof audit report --format html  > recoverability.html
drillproof audit report --format json  > recoverability.json
drillproof audit report --format sarif > recoverability.sarif

# The exact permissions needed
drillproof audit init                      # IAM policy JSON
drillproof audit init --format terraform   # role + trust policy + external ID
drillproof audit init --format rbac        # read-only ClusterRole for Velero checks
drillproof audit init --format all
```

Thresholds are tunable: `--warn-after 12h --fail-after 72h`.

Every flag has an env equivalent: `DRILLPROOF_PROFILE`, `DRILLPROOF_REGION`, …

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Error — bad flags, no credentials, fatal API failure |
| 2 | Score below `--fail-under` |
| 3 | `verify` — not implemented in v1 |

### CI example

```yaml
- name: Recoverability gate
  run: |
    drillproof audit score --region us-east-1 --fail-under 80
- name: Upload findings to code scanning
  if: always()
  run: drillproof audit report --format sarif > drillproof.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: drillproof.sarif
```

SARIF findings carry stable `partialFingerprints`, so an unresolved gap keeps the
same identity between runs rather than reappearing as new.

---

## 7. Why `drillproof audit` and not `audit`

The spec documents both `drillproof audit scan` (§3) and
`docker run drillproof/audit scan` (§8) — two different shapes. Both work: the
binary is `drillproof` with an `audit` command group, and the container's
entrypoint is `["/drillproof", "audit"]`, so the documented docker invocation
resolves to the same place.

---

## 8. How read-only is enforced

Not by review discipline. By construction:

1. The AWS interfaces in `internal/aws/api.go` expose **only** `Describe`,
   `List`, and `Get` operations. Everything downstream holds those interfaces
   rather than SDK clients, so a mutating call does not compile.
2. `TestInterfacesAreReadOnly` reflects over every interface and fails if a
   method appears that is not a read verb.
3. `TestPolicyCoversEverySDKCall` fails if the scanner calls something the
   emitted IAM policy does not grant — **or** grants something it never calls. So
   `init` cannot drift into over- or under-promising.
4. A CI job greps the source for mutating SDK calls that might bypass the
   interfaces.

The S3 quirk is worth knowing: the API operation is
`GetObjectLockConfiguration` but the IAM action is
`GetBucketObjectLockConfiguration`. The mapping is explicit in
`internal/iam/iam_test.go`; getting it wrong would hand users a policy that does
not authorise the tool.

---

## 9. Code layout

```
cli/
  main.go                 build info, exit code
  cmd/                    cobra commands: scan score report init verify version
  internal/
    model/                shared vocabulary, dependency-free
    aws/
      api.go              read-only interfaces + error classifiers
      inventory.go        EBS / RDS / EKS discovery
      backup.go           vault index, recovery points, native fallback
      scan.go             orchestration, concurrency, Velero merge
    k8s/velero.go         Velero detection (discovery + dynamic client)
    checks/checks.go      the six checks — pure
    score/score.go        weights + explanation
    report/               table.go json.go sarif.go html.go
    iam/iam.go            policy / Terraform / CFN / RBAC emitters
  .goreleaser.yaml        binaries, Homebrew tap, Docker manifests
  .github/workflows/      ci.yml, release.yml
```

### Adding a check

1. Add a `CheckID` to `internal/model` and `AllChecks`.
2. Add the evidence field to `model.BackupState`, populated in `internal/aws`.
3. Write the check as a pure function in `internal/checks`, using `blocked()`
   when access is missing and `moot()` when there is nothing to assess.
4. Add a weight in `internal/score` with the reasoning.
5. Add a SARIF rule description in `internal/report/sarif.go`.
6. If it needs a new AWS call, add it to the interface **and** to
   `actionGroups` in `internal/iam` — the drift test fails otherwise.

### Testing

```sh
go test ./...          # no AWS credentials needed; everything is faked
go test -race ./...
```

Fakes live in `internal/aws/fakes_test.go`; `estate()` in `scan_test.go` builds a
two-region account with a healthy volume, an unbacked production database, and a
cluster, which most scan tests reuse.

---

## 10. Known limitations

- **Binary size** is ~75–85 MB. `client-go` accounts for most of it; it is the
  cost of the Velero check the spec asks for.
- **Redundancy is only as good as the regions scanned.** `--region us-east-1`
  alone cannot see a copy in `eu-west-1`, so redundancy will read as failing.
  Scan all regions when you care about that check.
- **Production detection is a heuristic** (name and tag matching). It only ever
  *raises* scrutiny, never lowers it.
- **Immutability via S3 Object Lock** is not yet wired per-backup; the check
  relies on AWS Backup Vault Lock. The `s3:GetBucketObjectLockConfiguration`
  permission is in the policy for that work.
- **`verify` does nothing** by design — it exits 3 so no pipeline mistakes it for
  a passing check.
- **Full-region scans hit AWS rate limits** on large accounts. Retry with backoff
  is configured (8 attempts); narrow `--region` if a scan drags.

---

## 11. Privacy, restated

Runs locally. Read-only. No telemetry, no phone-home, no uploads. Reads
configuration and metadata only — never the contents of a backup, volume, or
database. Reports are written only where you redirect them.

Local report files are gitignored (`audit-report.*`, `*.sarif`): an
infrastructure posture report should never be committed by accident.
