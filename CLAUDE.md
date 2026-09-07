# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`drillproof audit` — a Go CLI that inventories AWS backups (EBS, RDS, EKS cluster state, S3 buckets, DynamoDB tables, EFS filesystems), runs five recoverability checks against them, and prints a 0–100 Recoverability Score. Module: `github.com/drillproof/audit`; `main` lives in `cmd/drillproof/` so `go install` names the binary `drillproof` rather than `audit`. Binary: `drillproof`, with an `audit` command group (`drillproof audit scan`); the Docker entrypoint is `["/drillproof", "audit"]` so `docker run drillproof/audit scan` resolves to the same place.

This directory is the CLI only. The sibling `../app/` is a separate pnpm/turbo web workspace with its own CLAUDE.md.

## Commands

```sh
go build -o drillproof ./cmd/drillproof
go test ./...                      # AWS is fully faked — no credentials needed
go test -race ./...
go test -run TestName ./internal/checks/   # single test
go vet ./...
gofmt -l .                         # CI fails on any output
go mod tidy                        # CI fails if this dirties go.mod/go.sum
goreleaser release --snapshot --clean
```

CI additionally runs `golangci-lint`, a cross-platform build matrix, `goreleaser check`, and a dedicated **read-only guarantee** job (see below).

## Architecture

The layering rule that governs everything: **discovery translates cloud APIs into `model.BackupState`; the checks read only that.** Checks are pure functions of `(model.Resource, *model.BackupState, checks.Config)` with no I/O and no clock read except `Config.Now`. That is why the suite runs without credentials and why the score is reproducible.


Flow: `cmd` → `aws.LoadProvider` → `aws.Scan` (region inventory in parallel, capped by `DefaultConcurrency = 4` because AWS throttles readily; a vault index is loaded first because cross-region redundancy can't be answered per-region) → `checks.Run` per resource → `score.Compute` → `report.Render*`.

EFS filesystems are regional and ride the same per-region fan-out as every
other resource type, with `internal/aws.FileSystems` states keyed by
filesystem ARN exactly as the S3/DynamoDB `Tables` states are keyed. Because a
region's `rr.states` can now be populated by more than one discovery call
(volumes/instances, tables, filesystems), `aws.Scan` merges each call's states
into `rr.states` rather than assigning it outright — an assignment would
silently drop whichever discovery ran first.

### Invariants worth knowing before changing anything

- **Read-only by construction.** No interface in `internal/aws` exposes a mutating operation, so a write call does not compile. Three gates enforce this: `TestInterfacesAreReadOnly` (reflects over every interface, rejects non-read verbs), a CI grep for mutating SDK method names outside `_test.go`, and `TestPolicyCoversEverySDKCall` in `internal/iam` (fails if the scanner calls something the emitted IAM policy does not grant, *or* grants something never called). Adding an SDK call means updating `internal/iam/iam.go` in the same change.
- **"Not assessed" is never a pass, and blocked ≠ not applicable.** `StatusSkipped` carries `SkipIsAccessGap`: true means a permission denied us (fixable via `drillproof audit init`), false means there was nothing to look at. Conflating them is a false statement about the user's estate. Similarly `model.Tristate` (`Unknown`/`Yes`/`No`) keeps "we know it's false" distinct from "we couldn't find out" — a lock state we couldn't read is never reported as immutable.
- **Failure degrades, never crashes.** A denied or failing API call marks that one check unassessed and appends a scan-level warning. A partial honest answer beats no answer.
- **The score is explainable.** Every deduction is a `model.Penalty` with its reason; `--explain` prints the arithmetic. Weights are named constants in `internal/score/score.go` with the reasoning written out in the package doc — changing one is a deliberate, reviewable act.
- **Nothing is written to disk and nothing is uploaded.** `report` re-scans across processes rather than caching results to disk; where output goes is the user's explicit choice via redirection. No telemetry.
- Strings in `model.ResourceType`, `model.CheckID`, and `model.Status` appear in JSON and SARIF output — treat them as public API.

### Exit codes

`0` success · `1` error · `2` score below `--fail-under` · `3` `verify` (not implemented in v1). Subcommands set these by returning `*cmd.ExitCodeError`.

## Scope boundaries (v1, deliberate)

No actual test-restores (`verify` is a stub), no org-wide or cross-account scans, no non-AWS clouds, and no write operation of any kind. `--provider` is hidden and rejects anything but `aws`.

EFS shipped after S3 and DynamoDB, and maps more cleanly than either: AWS
Backup supports EFS natively (automatic backups, recovery points, cross-region
copy), so all five checks apply with their ordinary meaning. That's the
opposite of S3 and DynamoDB, which needed each check reinterpreted because
neither has a volume-shaped backup story to grade directly.

## Conventions

- Flags are also settable as `DRILLPROOF_*` env vars via viper (`bindFlags` in `cmd/root.go`); validation of flag combinations belongs there.
- Comments in this codebase explain *why*, often at length in package docs. Match that — a new weight, threshold, or skipped check should come with its reasoning.
- Tests use `testify` and the fakes in `internal/aws/fakes_test.go`.
