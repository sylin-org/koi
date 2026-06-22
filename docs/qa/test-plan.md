# QA Follow-Up Test Plan

> **Status (2026-06-21): partly superseded.** Two references below are stale:
> - **`tests/integration.sh` was deleted** (CHANGELOG 0.3.0 — the weekly `qa.yml`
>   `.sh` scripts were replaced with cross-platform PowerShell Core `.ps1`
>   invocations). Only `tests/integration.ps1` and `tests/concurrency.ps1` remain;
>   read every `integration.sh`/`concurrency.sh` below as the `.ps1` equivalent under
>   `pwsh`.
> - **Certmesh cross-participant exchange coverage moved to per-PR Rust gates**
>   (**ADR-018**): `crates/koi/tests/two_daemon_certmesh.rs` (real two-binary daemons
>   over the DAT-gated HTTP) plus the `cross-host` job in `.github/workflows/ci.yml`
>   (`scripts/cross-host-certmesh.sh`, two containers). That coverage is **not** in the
>   scheduled `qa.yml` cron — it gates every PR. See ADR-018.
>
> The service-lifecycle, persistence, concurrency, and platform-unit sections below
> are still accurate (they run from the `.ps1` scripts / Rust unit tests). Verify the
> exact script names against the repo before relying on a path.

Date: 2026-02-12
Owner: QA
Scope: Follow-ups 1-4 (service lifecycle automation, persistence corruption, concurrency/soak, platform-specific unit tests)

## Goals
- Automate service lifecycle validation per OS.
- Validate persistence corruption handling and IO failures.
- Add a repeatable concurrency harness for key HTTP/IPC paths.
- Lock in platform-specific behavior with unit tests.

## Entry Criteria
- `cargo test` passes.
- `tests/integration.ps1` passes in Tier 1/2.
- Release binary can be built (`cargo build --release`).

## Exit Criteria
- Tier 3 automation runs without manual intervention (or self-skips with clear reason).
- Persistence corruption tests pass on all platforms.
- Concurrency harness completes without crashes or deadlocks.
- Platform-specific unit tests pass on their target OS.

---

## 1) Tier 3 Service Lifecycle Automation

### Windows (SCM)
- **Script**: `tests/integration.ps1 -Tier3`
- **Steps**:
  1) `koi install` (should auto-start the service)
  2) `sc.exe start koi` (idempotent if already started)
  3) Health check on `http://127.0.0.1:5641/healthz`
  4) `sc.exe stop koi`
  5) `koi uninstall`
- **Pass**: service starts, health endpoint OK, service stops, uninstall succeeds.

### Linux (systemd)
- **Script**: `tests/integration.ps1 -Tier3` under `pwsh` (the `.sh` variant was deleted; CHANGELOG 0.3.0)
- **Steps**:
  1) `sudo koi install`
  2) `systemctl is-active koi`
  3) Health check on `http://127.0.0.1:5641/healthz`
  4) `sudo systemctl stop koi`
  5) `sudo koi uninstall`
- **Skip Conditions**: systemd not available, runner not elevated.

### macOS (launchd)
- **Script**: `tests/integration.ps1 -Tier3` under `pwsh` (the `.sh` variant was deleted; CHANGELOG 0.3.0)
- **Steps**:
  1) `sudo koi install`
  2) `launchctl list | grep org.sylin.koi`
  3) Health check on `http://127.0.0.1:5641/healthz`
  4) `sudo launchctl bootout system/org.sylin.koi`
  5) `sudo launchctl bootstrap system /Library/LaunchDaemons/org.sylin.koi.plist`
  6) `sudo koi uninstall`
- **Skip Conditions**: launchctl unavailable, runner not elevated.

---

## 2) Persistence Corruption + IO Failures

### Unit Tests (Rust)
- **Module**: `koi-common::persist`
- **Cases**:
  - Invalid JSON returns `InvalidData`.
  - Missing file returns default (`read_json_or_default`).
  - `write_json_pretty` creates missing parent directories.
  - `write_json_pretty` fails when target is a directory.

### State Loaders (DNS/Health)
- **Modules**: `koi-config::state`, `koi-health::state`
- **Cases**:
  - Missing state file returns default state with empty entries.

---

## 3) Concurrency Harness

### Windows
- **Script**: `tests/concurrency.ps1`
- **Flow**:
  1) Start daemon in isolated data dir.
  2) Register N services concurrently.
  3) Heartbeat all services concurrently.
  4) Unregister all services concurrently.
- **Metrics**: total time, failures, unique ID count.

### Linux/macOS
- **Script**: `tests/concurrency.ps1` under `pwsh` (the `.sh` variant was deleted; CHANGELOG 0.3.0)
- **Flow**: same as Windows.
- **Notes**: cross-platform PowerShell Core; resolves `koi` vs `koi.exe` and the dynamic breadcrumb endpoint at runtime.

---

## 4) Platform-Specific Unit Tests

### Windows
- Validate that service paths use `KOI_DATA_DIR` override.
- Validate service log path ends with `logs/koi.log`.

### Linux
- Validate systemd unit file path and install path.
- Validate generated unit file contains `ExecStart` and `Type=notify`.

### macOS
- Validate launchd plist path and install path.
- Validate generated plist includes label and binary path.

---

## Automation (CI)

- **Scheduled QA workflow**: `.github/workflows/qa.yml` (cron + `workflow_dispatch`)
  - Integration + service-lifecycle + concurrency via the cross-platform `.ps1`
    scripts under PowerShell Core (`pwsh`). The old `.sh` integration scripts were
    removed (CHANGELOG 0.3.0).
- **Per-PR gates**: `.github/workflows/ci.yml` (the 3-OS build + test + clippy + fmt +
  MSRV + audit + the `surfaces` ledger lint). **Certmesh cross-participant coverage
  lives here, not in the cron** (ADR-018):
  - `crates/koi-embedded/tests/whole_story.rs` (Tier 1, in-process two-daemon) and
    `crates/koi/tests/two_daemon_certmesh.rs` (Tier 2, real two-binary daemons over
    DAT-gated HTTP) run under `cargo test --locked`.
  - The `cross-host` job (Tier 3) runs `scripts/cross-host-certmesh.sh` across two
    containers.
- **Schedule**: `qa.yml` is manual + scheduled; `ci.yml` gates every PR.
