# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-06-13

### Changed
- Rebuilt the `koi-proxy` data plane as a TLS-terminating **TCP passthrough** (`tokio-rustls` + `copy_bidirectional`) replacing the HTTP reverse-forwarder. WebSockets and any bidirectional/upgraded protocol now pass through transparently. **Breaking:** the `/v1/proxy/status` shape replaces the hardcoded `running: true` with real `state` (`running`/`error`/…), inline `error` detail, and `cert_source` (`certmesh`/`self-signed`); the dashboard, embedded API, and `koi proxy status` table were updated to match. Listen port and `/v1/proxy/*` paths are unchanged.
- Reset project versioning to plain pre-1.0 SemVer (`0.3.0`) consistently across the workspace and all internal dependency definitions.
- Consolidated binary and libraries deployment process, replacing automated timestamp-patched versions with explicit SemVer releases.
- Suspended crates.io automated publishing; isolated deployment to a manual `workflow_dispatch` workflow with strict dependency ordering and post-publish index propagation verification checks.
- Updated installation instructions in README to point directly to prebuilt GitHub Releases archives.

### Fixed
- Fixed the broken `koi-proxy` data plane: the old listener registered an axum 0.8 `/*path` wildcard route that panicked at startup inside a `tokio::spawn` (silently, while `status()` reported `running: true`), and the cert watcher called `tokio::spawn` from notify's non-tokio thread (panicking on the first cert event). TLS termination — the crate's headline feature — could not have worked since the axum 0.8 upgrade. The rebuild fixes all three structurally and adds a self-signed certificate fallback so a proxy always starts.
- Fixed weekly scheduled QA workflow failures by cleaning up reference to deleted `.sh` integration test scripts and replacing them with cross-platform `.ps1` invocations running on PowerShell Core (`pwsh`).
- Repaired `tests/integration.ps1` and `tests/concurrency.ps1` to dynamically resolve operating system differences (handling `koi` vs `koi.exe` and resolving dynamic breadcrumb endpoint paths).
- Injected Daemon Access Token (DAT) headers (`x-koi-token`) into integration test requests to successfully authenticate mutations against HTTP endpoints.
- Resolved token isolation during client-mode CLI operations by allowing auto-discovery via local environment variables.
- Enabled crates.io verification script to use explicit pipefail settings via `shell: bash` on GitHub Actions to ensure failures are no longer silently ignored.
