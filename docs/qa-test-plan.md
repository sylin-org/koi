# QA Follow-Up Test Plan

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
- `tests/integration.ps1` and `tests/integration.sh` pass in Tier 1/2.
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
- **Script**: `tests/integration.sh --tier3`
- **Steps**:
  1) `sudo koi install`
  2) `systemctl is-active koi`
  3) Health check on `http://127.0.0.1:5641/healthz`
  4) `sudo systemctl stop koi`
  5) `sudo koi uninstall`
- **Skip Conditions**: systemd not available, runner not elevated.

### macOS (launchd)
- **Script**: `tests/integration.sh --tier3`
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
- **Script**: `tests/concurrency.sh`
- **Flow**: same as Windows.
- **Notes**: uses `curl` and `xargs -P` or falls back to sequential execution.

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

- **Workflow**: `.github/workflows/qa.yml`
- **Jobs**:
  - Integration tests on Windows/Linux/macOS.
  - Service lifecycle on Windows; Linux/macOS runs if systemd/launchctl available.
  - Concurrency harness on Linux and Windows.
- **Schedule**: manual trigger (workflow_dispatch) plus scheduled run.
