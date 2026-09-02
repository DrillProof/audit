# drillproof audit

**Your backups run. But can you actually restore?**

A read-only CLI that inventories your AWS backups, checks them against five
recoverability criteria, and prints a **Recoverability Score (0–100)** with the
gaps that matter. It runs locally with your own credentials, changes nothing, and
sends nothing anywhere.

Most backups are never test-restored. This tool tells you which of yours.

```
$ drillproof audit scan --region ap-southeast-1

DrillProof Audit — account 1234-5678-9012 — ap-southeast-1
──────────────────────────────────────────────────────────
RESOURCE                TYPE       BACKUP   AGE   IMMUTABLE  X-REGION  RESTORE
payments-db (RDS)       database   ok       6h    no         no        untested
orders-pv (EKS/EBS)     volume     ok       3h    yes        yes       verified
etcd (prod-cluster)     k8s-state  none     -     -          -         failed
──────────────────────────────────────────────────────────
Recoverability Score: 61/100   (3 critical gaps)

Top findings:
  x etcd (prod-cluster) — no backup of cluster state — the cluster is unrecoverable
  ! payments-db (RDS) — backups can be deleted — no Vault Lock or Object Lock
  ! payments-db (RDS) — never test-restored — "backed up" is not "recoverable"

Fix these free: https://drillproof.com/audit   (or run `drillproof audit init`)
```

> The table above is illustrative. Your own output will differ.

---

## Privacy

This matters more than the features, so it comes first.

- **Runs locally**, with the credentials already on your machine.
- **Strictly read-only.** Only `Describe`, `List`, and `Get` APIs are called. The
  tool cannot create, modify, restore, or delete anything — the AWS client
  interfaces in `internal/aws` expose no mutating operation, so a write call
  would not compile. A test (`TestInterfacesAreReadOnly`) and a CI job enforce
  this on every commit.
- **Nothing leaves your machine.** No telemetry, no phone-home, no uploads. If
  opt-in telemetry is ever added it will be explicit and off by default.
- **Metadata only.** It reads backup configuration — resource ids, timestamps,
  retention and lock settings. It never reads the contents of a backup, a
  volume, or a database.

Reports are only written where you redirect them. Nothing is saved by default.

---

## Install

```sh
# Homebrew
brew install drillproof/tap/audit

# Shell installer
curl -sSL https://get.drillproof.com | sh

# Docker (mounts your AWS config read-only)
docker run --rm -v ~/.aws:/root/.aws:ro drillproof/audit scan

# From source
go install github.com/drillproof/audit@latest
```

## Usage

```sh
# Scan every enabled region — the provider and regions are auto-detected
drillproof audit scan

# Narrow it down
drillproof audit scan --profile prod --region us-east-1,eu-west-1

# Show the score arithmetic
drillproof audit scan --explain

# Gate a pipeline on the score
drillproof audit score --fail-under 80

# Machine-readable output
drillproof audit report --format json  > recoverability.json
drillproof audit report --format sarif > recoverability.sarif
drillproof audit report --format html  > recoverability.html

# Print the exact IAM policy this tool needs
drillproof audit init
drillproof audit init --format terraform
```

Also include cluster state, which AWS APIs cannot see:

```sh
drillproof audit scan --kubeconfig ~/.kube/config --context prod
```

### Commands

| Command   | What it does                                                    |
| --------- | --------------------------------------------------------------- |
| `scan`    | Inventory + all five checks + score (the default)               |
| `score`   | Just the score; `--fail-under N` gates CI                       |
| `report`  | Render as `html`, `json`, or `sarif`                             |
| `init`    | Emit the least-privilege IAM policy, Terraform, CFN, or K8s RBAC |
| `verify`  | **Coming soon** — a real isolated test-restore. Not in v1.       |
| `version` | Version and build info                                          |

### Global flags

| Flag           | Default                | Notes                                     |
| -------------- | ---------------------- | ----------------------------------------- |
| `--profile`    | standard AWS chain     | AWS profile                               |
| `--region`     | all enabled regions    | Repeatable/comma-separated; only narrows  |
| `--output, -o` | `table`                | `table` \| `json` \| `sarif`              |
| `--kubeconfig` | none                   | Enables the EKS/Velero cluster-state check |
| `--context`    | current context        | Kube context                              |
| `--explain`    | off                    | Show how the score was calculated         |
| `--warn-after` | `24h`                  | Freshness warning threshold               |
| `--fail-after` | `168h`                 | Freshness failure threshold               |
| `--no-color`   | off                    | Also respects `NO_COLOR`                  |
| `--quiet, -q`  | off                    | Score and failures only                   |
| `--verbose, -v`| off                    | Progress logging to stderr                |

Any flag can also be set by environment variable: `DRILLPROOF_REGION`,
`DRILLPROOF_PROFILE`, and so on.

### Exit codes

| Code | Meaning                                       |
| ---- | --------------------------------------------- |
| `0`  | Success                                       |
| `1`  | Error (bad flags, no credentials, API failure) |
| `2`  | Score below `--fail-under`                     |
| `3`  | `verify` — not implemented in v1               |

---

## What it checks

For every **EBS volume**, **RDS instance/cluster**, and **EKS cluster state**:

| Check               | Question                                            | Why it matters                                                             |
| ------------------- | --------------------------------------------------- | -------------------------------------------------------------------------- |
| **Coverage**        | Does a backup exist at all?                         | The only unrecoverable state. Dominates the score.                         |
| **Freshness**       | How old is the newest *successful* backup?          | Catches schedules that silently stopped succeeding.                        |
| **Immutability**    | Is it on WORM storage (Vault Lock / Object Lock)?   | A deletable backup may not be there during the incident that needs it.     |
| **Redundancy**      | Is a copy in another region?                        | A backup beside the resource does not survive a regional event.            |
| **Restore-testing** | Has a restore ever actually been performed?         | The gap this whole tool exists to surface. "Backed up" ≠ "recoverable".    |

Every finding carries the resource, region, status (`ok` / `warn` / `fail` /
`skipped`), a one-line explanation, and a remediation hint.

### "Not assessed" is never a pass

Two different things get reported separately, because conflating them would mean
lying to you:

- **Blocked** — we were not permitted to look. Fixable by granting the
  permission; run `drillproof audit init`.
- **Not applicable** — there was nothing to look at. A volume with no backup has
  no backup age and no cross-region copy; no permission changes that.

A resource whose lock state we could not read is never reported as immutable.

---

## The Recoverability Score

A single 0–100 integer plus a count of critical gaps. Each resource is scored on
its own — a coverage failure zeroes it outright (unrecoverable, and its other
checks have nothing left to assess); otherwise it starts at 100 and loses a
documented weight per remaining failing check. The estate score is the
criticality-weighted mean of those per-resource values, not a sum of
deductions, so it does not saturate the way an absolute-deduction score would.

| Failing check                       | Deduction |
| ----------------------------------- | --------- |
| Coverage (no backup)                | −25       |
| …and it is cluster state or prod DB | −10 more  |
| Immutability                        | −10       |
| Freshness (past fail threshold)     | −8        |
| Freshness (past warn threshold)     | −4        |
| Redundancy                          | −6        |
| Never test-restored                 | −5        |

Deterministic — the same estate always scores the same, regardless of the order
results arrive in. Every deduction is itemised by `--explain`, so you can check
the arithmetic:

```
$ drillproof audit scan --explain
...
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

The weights live in `internal/score/score.go` as named constants with the
reasoning written out. If you disagree with a weight, you can see exactly what to
change. **Untested-restore is weighted last on purpose** — not because it matters
least, but because it is nearly universal, and penalising it heavily would flatten
every score to zero and destroy the signal that makes the rest actionable.

See `docs/how_it_works.md` §5 for the full arithmetic, including how
`raw_deduction` (still an absolute sum) differs from the normalized score.

If nothing could be assessed at all, the score is **0**, not 100. An account we
cannot read is not an account with perfect backups.

---

## Permissions

`drillproof audit init` prints the exact policy — 17 actions, no wildcards:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "Identity", "Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*" },
    { "Sid": "RegionAndVolumeInventory", "Effect": "Allow", "Action": [
        "ec2:DescribeRegions", "ec2:DescribeSnapshots", "ec2:DescribeVolumes"
      ], "Resource": "*" },
    { "Sid": "DatabaseInventory", "Effect": "Allow", "Action": [
        "rds:DescribeDBClusterSnapshots", "rds:DescribeDBClusters",
        "rds:DescribeDBInstances", "rds:DescribeDBSnapshots"
      ], "Resource": "*" },
    { "Sid": "BackupPosture", "Effect": "Allow", "Action": [
        "backup:DescribeBackupVault", "backup:ListBackupVaults",
        "backup:ListRecoveryPointsByBackupVault", "backup:ListRecoveryPointsByResource",
        "backup:ListRestoreTestingPlans"
      ], "Resource": "*" },
    { "Sid": "ClusterInventory", "Effect": "Allow", "Action": [
        "eks:DescribeCluster", "eks:ListClusters"
      ], "Resource": "*" },
    { "Sid": "ObjectLockPosture", "Effect": "Allow", "Action": [
        "s3:GetBucketLocation", "s3:GetBucketObjectLockConfiguration"
      ], "Resource": "*" }
  ]
}
```

`Resource: "*"` is unavoidable for discovery: the tool cannot name ARNs it has
not found yet. Every action is a read.

For the optional cluster-state check, `drillproof audit init --format rbac`
emits a read-only `ClusterRole` (`get`/`list` only).

Missing a permission never crashes the scan — that check is reported as blocked,
naming the operation that was denied.

---

## Development

```sh
go test ./...              # unit tests, AWS fully faked — no credentials needed
go test -race ./...
go vet ./...
gofmt -l .

go build -o drillproof .
goreleaser release --snapshot --clean   # local release dry-run
```

Layout:

```
cmd/                cobra commands
internal/
  aws/              read-only clients behind narrow interfaces (+ fakes)
  k8s/              Velero detection via discovery + dynamic client
  checks/           the five checks — pure functions, no I/O
  score/            the scoring function and its documented weights
  report/           table / json / sarif / html renderers
  iam/              policy, Terraform, CloudFormation, RBAC emitters
  model/            shared vocabulary, dependency-free
```

The design rule worth knowing before changing anything: **the checks are pure**.
Discovery translates AWS and Kubernetes into `model.BackupState`, and the checks
read only that. It is why they are testable without credentials and why the score
is reproducible.

Two tests exist specifically to stop the product's promises rotting:

- `TestInterfacesAreReadOnly` reflects over every AWS interface and fails if a
  mutating operation appears.
- `TestPolicyCoversEverySDKCall` fails if the scanner calls something the emitted
  IAM policy does not grant — or grants something it never calls.

---

## Scope

**v1 covers** EBS, RDS, and EKS cluster state on AWS, read-only.

**v1 does not cover**, deliberately: actual test-restores (`verify`), S3/EFS/
DynamoDB resources, org-wide or cross-account scans, non-AWS clouds, and any
write operation whatsoever.

`verify` is absent for a reason. Performing a restore needs write permissions and
real isolation guarantees, and shipping that carelessly is how an audit tool
becomes an incident. Until then, `scan` can prove a restore point has *never*
been tested — and [a free Restore-Assurance Audit](https://drillproof.com/audit)
will run the real thing with you.

---

## License

Apache-2.0. See [LICENSE](LICENSE).
