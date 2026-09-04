# Verification note for the September 2026 assessment

Date: 2026-09-04. Koi source: `f625557c9fe81c9483eba80413efdc706d59f6dd` on `dev`, version `1.0.0-dev.0`. Adjacent desktop source: `3bf986e0f7daef451695e4993c4a050a8fd9fbb5`. Both trees were clean when inspected, before adding the assessment documents.

**Targeted checks executed in this session**

| Check | Result |
|---|---|
| `cargo test --locked --offline -p koi-common --test architecture` | 15 passed; no failures; compilation 10.78 seconds, test execution 0.21 seconds |
| `cargo fmt --all --check` | Exit 0 |
| `node --test packages/ts/test/client.test.js packages/npm/test/launcher.test.js scripts/release-version.test.mjs scripts/release-manifest.test.mjs` | 23 passed; no failures; approximately 10.18 seconds |
| `PYTHONPATH=packages/python/src python -m unittest discover -s packages/python/tests -v` (PowerShell environment assignment) | 8 passed; includes TS CSR verification through Python cryptography; approximately 3.98 seconds |
| `node --test ui/app.test.mjs` in the adjacent `koi-desktop` checkout | 38 passed; approximately 0.30 seconds |

Total: **84 targeted tests passed**, plus formatting. This total combines different packages and the adjacent desktop repository; it is not the Koi workspace test count or a coverage percentage.

**Live observations**

- Installed Windows daemon reported `1.0.0-dev.0`; binary SHA-256 was `d47138c58cb2117ca597ae6bb335079d160d42608816e63ea0785273768d7610`, matching the Windows OD-3 readiness record.
- CLI status reported working discovery, DNS, and local control; certmesh uninitialized; no managed roots, health checks, proxies, or UDP bindings; runtime connection unavailable; Pond disabled. Existing HTTP exposure was `0.0.0.0`, an observed configuration, not the product default.
- Dashboard loaded real state and events. It exposed the underlying runtime transport error, capability-oriented empty states, and a long inline API catalogue.
- Browser showed 26 live instances and 35 type entries at one observation. “Type” categories included full instance names and hostnames. A separate direct read of `/v1/mdns/snapshot` at discovery revision 373 contained 58 records and 35 service-type entries; 18 type strings did not match a simple `_service._tcp` / `_service._udp` shape. This heuristic is not a complete DNS-SD/subtype validator. The counts refer to different projections and should not be treated as a count-consistency defect.
- Searching for `no-such-koi-assessment-service` displayed “No services discovered yet” while the overall instance count remained populated.
- At a 390×844 viewport, the category list occupied the initial screen before service results. Measured page width was 375 pixels against a 390-pixel viewport; horizontal overflow was not established.
- Source inspection confirmed click-only type/histogram interactions and no matching keyboard semantics for those controls. This was not a complete accessibility audit.
- No warning/error console messages were captured in the final browser log check. Temporary viewport overrides were reset and assessment tabs closed.

No local CA, firewall, trust store, persistent daemon configuration, or service lifecycle was changed. Opening discovery presentation can create its normal temporary browse demand; this was not a passive packet capture. Raw household/device names and addresses are omitted from this note.

**Hosted and recorded evidence, not rerun here**

GitHub release API reported `v0.9.0` as the newest stable release (2026-06-25) and `v1.0.0-rc.2` as newest prerelease (2026-08-24). Repository default branch was `main`; reviewed local branch was `dev`.

[CI run 33878240432](https://github.com/sylin-org/koi/actions/runs/33878240432), created 2026-09-04, checked `main` commit `b09f0f3224c9f27aca28d2b9e6a15b391f1b271e`. Ubuntu and macOS test jobs, clippy, format, MSRV, audit, and surface checks succeeded. The lean closure job failed because it rejected `zbus`. Windows build succeeded, but the DNS test `runtime::tests::bind_failure_is_reported_stopped_and_can_be_retried` failed with socket error 10013 at the retry `unwrap`; that crate reported 28 passed and 1 failed. Cross-host CI was skipped due to its dependency gate.

Current reviewed source differs: the lean denylist excludes mandatory platform `zbus`; the DNS runtime and its contention/recovery tests have been replaced. Thus the failed run proves a **hosted validation gap**, not that these exact failures still reproduce on reviewed HEAD. The current CI workflow triggers on pushes/PRs to `main`, not direct `dev` pushes. No hosted run was dispatched in this assessment.

The [active fleet epic](../../fleet/epics/002-observable-domain-boundaries.md) records OD-2 acceptance and five ready OD-3 native candidates. OD-3 froze `b3eb47e08817045f9371703d780ada9aab00995d`; its coordinated six-hour soak targets 2026-09-04T23:30:00Z, with possible later collector completion and explicit final reconciliation. That completion was still future at assessment time. Historical surface results were read as dated records, not newly observed acceptance.

`git diff --name-only b3eb47e08817045f9371703d780ada9aab00995d HEAD -- crates Cargo.toml Cargo.lock packaging install.sh install.ps1` produced no differences.

**Repository inventory method**

Enumerated `git ls-files`, read tracked `.rs` files as UTF-8, and counted physical lines including blank lines, comments, inline tests, examples, and integration tests. No dependency, generated target, or untracked lab output was counted.

| Measure | Count |
|---|---:|
| Tracked files | 678 |
| Rust files | 302 |
| Physical Rust lines | 165,460 |
| Rust files over 800 lines | 60 |
| Workspace members | 19 |
| Markdown files under `docs/` | 181 |
| Certmesh Rust lines, including tests | 30,467 |
| Lab Rust lines, including tests | 20,938 |

**Limits**

No full workspace regression, native installer matrix, cross-host TLS lifecycle, destructive recovery scenario, security penetration test, independent cryptographic review, screen-reader study, or representative-user study was run. The active installed-service soak was left to its existing owners. Recommendations are product judgments grounded in the inspected source and observations, not claims of market demand or measured conversion.
