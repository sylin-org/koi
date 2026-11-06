# Validation surfaces

This index maps current interfaces to their guards. It does not carry campaign
history or certify the new preview. Exact results belong in
[proof receipts](launch/proof.md); candidate status belongs in
[readiness](launch/README.md) and [the ledger](../fleet/launch/LEDGER.md).

“Unknown since” means no current launch receipt is recorded here. A guard name
shows where validation exists, not that it was run in this documentation change.
Keep the five-column table parseable by scripts/lint-surfaces.sh.

| Surface | Exercised by | Last exercised | Guard | Notes |
| --- | --- | --- | --- | --- |
| Domain boundaries and dependency direction | Repository architecture tests | unknown since 2026-09-12 | crates/koi-common/tests/architecture.rs; CI | Preserve domain ownership and composition boundaries |
| mDNS publication, browse and provider routing | koi-mdns tests and native peer cases | unknown since 2026-09-12 | koi-mdns suite; native provider tests | Actual LAN peer required for platform capability claims |
| Runtime inventory and reconnect | koi-runtime tests and real Docker cases | unknown since 2026-09-12 | koi-runtime suite; runtime integration tests | Real runtime tests may require explicit environment execution |
| Container-derived lifecycle | Composition reconciliation tests and preview fixture | unknown since 2026-09-12 | crates/koi-compose/src/orchestrator.rs tests | Test existing containers, recreate, changed ports and removal |
| Service catalog and freshness | Catalog tests and client observations | unknown since 2026-09-12 | crates/koi-compose/src/catalog.rs tests | Found, responding, stale and ambiguous are different states; discovery availability comes from browse routes, not row counts |
| DNS resolution and delegation | koi-dns tests and ordinary second-client queries | unknown since 2026-09-12 | koi-dns suite | Koi's direct resolver query does not prove client DNS setup |
| HTTP authentication and route classes | Serving tests | unknown since 2026-09-12 | koi-serve suite; route/auth matrix | Classify aggregate reads, streams and unknown peers explicitly |
| Local operator IPC | Serving/local-control tests and installed clients | unknown since 2026-09-12 | koi-serve suite; native installed proof | Verify actual UID/SID authority and one intended daemon |
| CLI syntax and outcomes | CLI help/command tests and versioned quickstart | unknown since 2026-09-12 | koi-net suite | Examples must match the selected artifact |
| Health and reachability | Health tests and real application request | unknown since 2026-09-12 | koi-health suite | A published port or mDNS record does not prove app readiness |
| Proxy data plane | Proxy tests and independent client request | unknown since 2026-09-12 | crates/koi-proxy/src/data_plane_tests.rs | Verify real forwarding and listener lifecycle |
| Enrollment, renewal and identity persistence | Certmesh/crypto tests and trust cases | unknown since 2026-09-12 | koi-certmesh and koi-crypto suites | No independent security audit implied |
| Service-name grants and ACME | Certmesh grant/ACME tests and trusted-extension recipe | unknown since 2026-09-12 | koi-certmesh suite | Public workflow completion and account/SAN proof required |
| OS trust installation | Trust tests and actual intended clients | unknown since 2026-09-12 | koi-trust suite; native trust proof | OS-store presence does not establish every client trust source |
| MCP and client SDKs | Transport/client contracts | unknown since 2026-09-12 | koi-mcp suite; Node/Python contracts | Skips and missing optional test dependencies remain explicit |
| UDP bridge | UDP protocol/lifecycle tests | unknown since 2026-09-12 | koi-udp suite | Advanced integration; no transparent compatibility assumption |
| Prometheus export | Serving export tests | unknown since 2026-09-12 | crates/koi-serve/src/prometheus_sd.rs tests | Schema compatibility needs real consumer proof for recipe claims |
| Embedded lifecycle | Embedded crate tests and external examples | unknown since 2026-09-12 | koi-embedded suite; lean guard | Preserve readiness, cancellation and shutdown ownership |
| Shared UI and headless rendering | Renderer, serving and browser-transport tests | unknown since 2026-09-12 | crates/koi-ui/tests/render.rs, tests/home.rs, tests/devices.rs; crates/koi-serve/src/ui.rs; crates/koi-serve/assets/ui-transport.test.mjs | One shared HTTP(S) Open validator; discovery availability shown independently of rows; automatic refresh marks failures stale and disables Open; parked browser-access routes return 404; Home/Devices modules retained unrendered pending removal |
| mDNS inspector and bounded queries | Domain unresolved-observation/replay tests, authenticated adapter tests, shared renderer and real-DOM interaction probes | 2026-09-13 | koi-common/koi-mdns/koi-dashboard/koi-serve/koi-ui suites; browser smoke; native bridge tests | Source and isolated-browser checks only; [Restoration and review receipt](ux/mdns-inspector-proof.md); query outcomes, provider disagreements, cancellation, DAT and Pond redaction; native visual acceptance remains distinct |
| Shared renderer domain status imports | Exact dependency/type allowlist and negative source-guard fixtures | 2026-09-13 | crates/koi-common/tests/architecture.rs | [Receipt](ux/mdns-inspector-proof.md); source check only; Existing Certmesh/DNS status DTOs only; domain cores/commands/modules/wildcards/aliases rejected; guard is not a security sandbox |
| About documentation handoff | Shared source-owned URL set and desktop new-window handler | 2026-09-13 | koi-ui About/URL checks; desktop protocol checks | Source/build check only; [Visual receipt](ux/visual-signature-proof.md); exact docs links use the validated browser opener, remote native windows denied; physical native click-through remains unclaimed |
| Install, upgrade and release channels | Installer contracts, hosted dry run and native install | unknown since 2026-09-12 | release workflow; installer tests | Public endpoint and post-publication download are required |
| CI change-scope selection | Scope classifier contract tests | unknown since 2026-11-05 | scripts/ci-scope.test.mjs; CI Change scope job | Only known documentation paths skip product jobs; mixed, unknown or unavailable comparisons and workflow_dispatch run the full matrix |
| Current documentation | Link/example checks and bundle generation | 2026-09-12 | surface lint; scripts/AiDocDist.ps1 -Validate | [L01 evidence](launch/documentation-proof.md); documentation-only acceptance |

## Updating a row

Change the row when its guard or accepted result changes. A date requires a
linked receipt for the actual source/artifact and case. Failed or incomplete
native proof must remain explicit. Never copy a prior artifact's pass into a
new candidate's acceptance.
