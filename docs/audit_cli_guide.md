# `drillproof audit` CLI — Design & Build Spec

> **What this tool is:** the open-source, self-serve top-of-funnel for DrillProof. An engineer runs it against their own AWS account, it inventories backups and checks them against best practice, and prints a **Recoverability Score (0–100)** with the critical gaps. Genuinely useful standalone; the low score + "never test-restored" findings are what drive interest in DrillProof.
>
> **v1 golden rules:** (1) **read-only** — describe/list APIs only, never restore/modify/delete. (2) **AWS-only, EBS+RDS+EKS/etcd only** — resist scope creep. (3) Useful with zero signup. (4) `verify` (actual test-restore) is **NOT** in v1 — stub it as "coming soon".

---

## 1. Why Go (decided)
- The integration ecosystem is Go: Kubernetes `client-go`, Velero, AWS SDK for Go v2.
- Single static binary, no runtime — ideal for `brew install`, `curl | sh`, CI, and a scratch container image.
- Trivial cross-compilation (darwin/linux/windows × amd64/arm64).
Do not use TypeScript/Python for this.

---

## 2. Tech stack & libraries
- **Language:** Go (latest stable, 1.22+).
- **CLI framework:** `spf13/cobra` (commands/flags) + `spf13/viper` (config/env) — the standard, matches kubectl/velero UX engineers expect.
- **AWS:** AWS SDK for Go **v2** (`aws-sdk-go-v2`) — services: `ec2` (EBS volumes + snapshots), `rds`, `backup` (AWS Backup), `eks`, `sts` (identity/whoami), `s3` (Object Lock status on backup targets).
- **Kubernetes/EKS:** `client-go` + `sigs.k8s.io/controller-runtime`'s client for cluster checks; detect Velero via its CRDs (`velero.io`) using the dynamic/discovery client.
- **Output/UX:** a table writer (e.g. `jedib0t/go-pretty` or `olekukonko/tablewriter`), color via `fatih/color` (respect `NO_COLOR`), structured logging with `log/slog`.
- **JSON/SARIF:** stdlib `encoding/json`; SARIF as a typed struct for CI integrations.
- **Testing:** stdlib `testing` + `stretchr/testify`; mock AWS with interface-based fakes (define narrow interfaces per service, not the whole SDK).
- **Build/release:** `goreleaser` (binaries + Homebrew tap + Docker image), GitHub Actions CI.
- **License:** Apache-2.0. Module path `github.com/drillproof/audit`.

---

## 3. Command surface (v1)
```
drillproof audit <command> [flags]

Commands:
  scan          Inventory backup coverage + config across AWS (read-only)  [v1 core]
  score         Print just the Recoverability Score (for CI gating)        [v1]
  report        Render the last scan as html | json | sarif                [v1]
  init          Emit the exact least-privilege IAM policy / Terraform needed[v1]
  verify        (stub) "coming soon" — will do a safe isolated test-restore [NOT v1]
  version       Print version/build info                                   [v1]

Global flags:
  --profile string     AWS profile (default: standard AWS credential chain)
  --region strings     Region(s) to scan (default: all enabled regions, auto-discovered)
  --output string      table | json | sarif   (default: table)
  --kubeconfig string  Path to kubeconfig for EKS/Velero checks (optional)
  --context string     Kube context to use (optional)
  --no-color           Disable color (also respects NO_COLOR env)
  --quiet / --verbose
```

**Provider/region auto-detection (important UX):** the tool detects it's AWS from the ambient credential chain — the user does **not** type `--provider`. Regions default to **all enabled regions** via auto-discovery; `--region` only narrows. A `--provider` flag is reserved for the future but AWS is the only valid value in v1.

---

## 4. What `scan` audits (the five checks)
For **EBS volumes, RDS instances/clusters, and EKS clusters (incl. etcd)** across enabled regions:

1. **Coverage** — does each resource have a backup at all? (AWS Backup recovery points, EBS snapshots, RDS snapshots/automated backups, EKS: is there a Velero backup / is etcd captured?) → flag anything with **none**.
2. **Freshness** — age of the most recent *successful* backup vs a threshold (default warn > 24h, fail > 7d; configurable) → flag stale / silently-failed schedules.
3. **Immutability** — are backups on immutable/object-locked (WORM) storage? Check S3 Object Lock on backup vault targets / relevant config → flag deletable backups (the ransomware gap).
4. **Redundancy** — are backups copied **cross-region** (or otherwise isolated from the protected resource)? → flag single-location backups.
5. **Restore-testing** — has this backup ever been test-restored? (v1: metadata only — "backed up" vs "verified recoverable"; almost all will be **untested**) → flag as the DrillProof wedge.

Each finding has: resource id, type, region, check, status (`ok` / `warn` / `fail`), and a one-line explanation + remediation hint.

---

## 5. The Recoverability Score
- A single **0–100** integer, plus a count of **critical gaps**.
- Weighting (make it a documented, tunable function — don't hardcode opaque magic):
  - Coverage gaps (no backup at all) = heaviest penalty (esp. etcd / production RDS).
  - Then immutability, then freshness, then redundancy, then untested-restore.
- Deterministic and explainable: the report must show *why* the score is what it is (which findings cost how much). The score's credibility is what makes the funnel work — never fudge it.
- `score --fail-under N` exits non-zero if below N (for CI badges / pipeline gates).

---

## 6. Permissions model (v1 = read-only)
- `scan` needs only **describe/list** permissions: `ec2:Describe*` (volumes/snapshots), `rds:Describe*`, `backup:List*`/`backup:Describe*`, `eks:Describe*`/`eks:List*`, `s3:GetBucketObjectLockConfiguration` (+ `GetBucketLocation`), `sts:GetCallerIdentity`. Kubernetes: a **read-only ClusterRole** for EKS/Velero checks.
- `init` command **emits the exact least-privilege IAM policy JSON + a ready-to-apply Terraform/CloudFormation snippet** so the user can create the role in one step. The tool prints precisely which permissions it needs and refuses nothing silently.
- The tool must **fail gracefully on missing permissions** — skip that check, mark it "not assessed (missing permission X)", never crash, never hang.
- **Never** call any mutating API in v1. No create/restore/delete/modify. (Enforce this in code review: the AWS client interfaces should only expose read methods.)

---

## 7. Output examples

**Table (default):**
```
DrillProof Audit — account 1234-5678-9012 — ap-southeast-1
──────────────────────────────────────────────────────────
RESOURCE                TYPE       BACKUP   AGE   IMMUTABLE  X-REGION  RESTORE
payments-db (RDS)       database   ok       6h    no         no        untested
orders-pv (EKS/EBS)     volume     ok       3h    yes        yes       verified
etcd (prod-cluster)     k8s-state  none     -     -          -         failed
──────────────────────────────────────────────────────────
Recoverability Score: 61/100   (3 critical gaps)

Top findings:
  x etcd for prod-cluster has NO backup — cluster state is unrecoverable.
  ! payments-db backups are not immutable and not copied cross-region.
  ! 4 restore points never test-restored ("backed up" != "recoverable").

Fix these free: https://drillproof.com/audit   (or run `drillproof audit init`)
```

**`score` (CI):**
```
$ drillproof audit score --fail-under 80
Recoverability Score: 61/100  (below threshold 80)  -> exit 1
```

**JSON / SARIF:** same data, machine-readable; SARIF so findings can surface in CI/code-scanning UIs.

---

## 8. Distribution
- `goreleaser` → GitHub Releases (binaries for darwin/linux/windows, amd64+arm64), a **Homebrew tap** (`brew install drillproof/tap/audit`), a **`curl -sSL https://get.drillproof.com | sh`** installer, and a container image `drillproof/audit` on Docker Hub.
- `docker run --rm -v ~/.aws:/root/.aws drillproof/audit scan`.
- Open source on `github.com/drillproof/audit`, Apache-2.0, with a strong README (what it checks, install, sample output, the IAM policy, privacy note).

---

## 9. Privacy & trust (state this in README + `--help`)
- Runs **locally** with the user's own credentials; **read-only**.
- **No data leaves the machine** in v1 — it does not phone home, does not upload findings anywhere (any future opt-in telemetry must be explicit and off by default).
- It reads configuration/metadata, never the contents of backups or databases.
This matters: engineers won't run a tool that might exfiltrate their infra posture. Make the privacy promise loud.

---

## 10. Repo structure (suggested)
```
audit/
  cmd/                 # cobra commands: scan, score, report, init, verify(stub), version
  internal/
    aws/               # per-service read-only clients behind narrow interfaces (+ fakes)
      ec2.go rds.go backup.go eks.go s3.go sts.go
    k8s/               # client-go + velero detection
    checks/            # the 5 checks, each pure & testable
    score/             # scoring function (documented weights) + tests
    report/            # table / json / sarif renderers
    iam/               # policy + terraform emitter for `init`
  main.go
  .goreleaser.yaml
  README.md
```

## 11. Definition of done (v1)
- [ ] `scan` inventories EBS + RDS + EKS/etcd across enabled regions, runs the 5 checks, prints a table + Recoverability Score.
- [ ] Provider auto-detected (AWS); regions auto-discovered; flags only to narrow/override.
- [ ] `score --fail-under` gates CI (correct exit codes); `report` outputs json + sarif; `init` emits IAM policy + Terraform.
- [ ] Read-only enforced in code (no mutating AWS calls); graceful skips on missing permissions.
- [ ] Scoring is deterministic, documented, and explained in output.
- [ ] `verify` present as a clear "coming soon" stub.
- [ ] Cross-compiled binaries + Homebrew tap + Docker image via goreleaser; GitHub Actions CI green.
- [ ] README with checks, install, sample output, IAM policy, and the privacy promise.
- [ ] Unit tests for each check + the scorer using AWS fakes.

## 12. Explicitly OUT of scope for v1
- `verify` / any actual restore or test-restore (needs elevated perms + isolation safety — later, and security-critical).
- S3/EFS/DynamoDB resource coverage, cross-account/AWS-Organizations org-wide scan, non-AWS clouds, on-prem.
- Any write/mutating operation, any data upload/telemetry, any auth/account system.

## Notes for the builder
- Verify the exact AWS API calls for each check against current AWS SDK for Go v2 + AWS Backup/EBS/RDS/EKS docs — the five checks are settled, but confirm *how* each is detected (e.g. how to read "is this recovery point immutable", "last successful backup time") as you implement.
- Keep each check pure and independently testable; the scorer must be explainable.
- Fail soft, never hang, never crash on partial permissions or throttling (handle AWS rate limits with backoff).
- UX target: feels like `kubectl`/`velero` — fast, obvious flags, clean output.