# Validation suite

Select checks by the changed invariant and the [launch gate](../launch/README.md). This inventory describes existing guards and required observations; it is not a pre-filled pass ledger. Record current runs in [the launch ledger](../../fleet/launch/LEDGER.md), with exact source/artifact identity.

## Automated source checks

| Check | Invocation or source | Establishes |
| --- | --- | --- |
| Rust workspace | `cargo test --workspace --locked` | Compiled domain/client/integration assertions on the executing platform |
| Lint | `cargo clippy --workspace --all-targets --locked -- -D warnings` | Static diagnostics for built targets |
| Architecture | `cargo test -p koi-common --test architecture --locked` | Dependency/ownership guardrails |
| Binary Certmesh exchange | `cargo test -p koi-net --test two_daemon_certmesh --locked` | Two real process HTTP/auth/key-custody exchange |
| Embedded composition | `cargo test -p koi-embedded --locked` | Embedded lifecycle, UDP, HTTP and posture contracts |
| Runtime reconciliation | `cargo test -p koi-compose --locked` | Derived-resource state, replacement and cleanup against test backends |
| Crypto/issuance | `cargo test -p koi-certmesh --locked` | CA/CSR, grants, ACME, rejection and persistence contracts |
| TypeScript client | `node --test packages/ts/test/client.test.js` | Client framing/custody/error behavior |
| Native launcher | `node --test packages/npm/test/launcher.test.js` | Platform-carrier resolution and stable path handling |
| Browser transport | `node --test crates/koi-serve/assets/ui-transport.test.mjs` | Token/same-origin/display invalidation behavior |
| Python client | `python -m unittest discover -s packages/python/tests -v` with `PYTHONPATH=packages/python/src` | Python contract behavior |

Release/installer contracts are under `scripts/*.test.mjs`. POSIX bootstrap tests require a POSIX shell; a Windows host without `sh` cannot establish that result. Python cross-language CSR validation requires Node and `cryptography`; report its skip explicitly when absent.

The [CI workflow](../../.github/workflows/ci.yml) defines the actual OS/feature/MSRV/audit and cross-container checks. The [QA workflow](../../.github/workflows/qa.yml) schedules PowerShell integration/concurrency checks. Workflow configuration alone is not a passing run, and a pass on another source revision is not the current candidate's pass.

## Native facilities

Real Docker tests in `crates/koi-runtime/tests/docker_integration.rs` are ignored by ordinary Cargo test. They need a running runtime and isolated test resources; run serially under the documented prerequisites. Native Avahi, systemd-resolved, Windows DNS-SD/Bonjour and Windows Firewall tests similarly need their actual facilities. An ignored test or unavailable provider is not a certified scenario.

`tests/integration.ps1` and `tests/concurrency.ps1` are the current script entry points. The integration script's `-Tier3` native service checks are Windows SCM-specific; do not use that label as evidence of Linux/systemd, OpenRC or macOS/launchd installation. Separate installed-host evidence is required.

## Required journey observations

| Boundary | Positive assertion | Negative/recovery assertion |
| --- | --- | --- |
| Installation | Exact artifact, one healthy intended native service | Failed install/upgrade preserves recoverable baseline |
| Runtime observation | Labeled fixture yields the real host endpoint | Disconnect/reconnect reports truth and reconciles current inventory |
| Discovery | Independent peer finds the fixture | Stop withdraws; recreate replaces without duplicate/stale rows |
| Application | Independent peer reads expected fixture body | Closed/wrong/loopback-only endpoint is not presented as proved reachable |
| DNS when used | Peer resolves the intended name through configured resolver | Wrong/missing forwarding is diagnosed separately |
| Trust extension | Exact SAN and trusted issuer selected for actual client | Wrong SAN, untrusted root and expired/revoked Koi identity are distinct |
| Cleanup | Run-owned records/containers removed, baseline restored | Restoration failure blocks acceptance |

No whole-product claim follows from a passing slice. Certificate trust-store behavior, router/VLAN behavior, browser root selection and physical multicast require direct observations.

## Persistence and authority review

For a changed state boundary, verify rejection of corrupt/future-schema files, rollback of a partial multi-file commit, visibility versus confirmed durability, exact credential/root cleanup and stale-generation fencing. Auth changes require both allowed and denied requests, including protected GETs/streams and remote/unknown peers.

Do not repeat the entire matrix for a Markdown-only change. Validate links, executable examples against current source, removed false claims and preserved protocol semantics. Live installation/network proof remains a separate run under [the fleet contract](../../fleet/CONTRACT.md).
