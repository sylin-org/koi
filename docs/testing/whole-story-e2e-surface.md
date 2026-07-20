# Koi Whole-Story E2E Test Surface — Design Spec

**Status:** Partially implemented. The certmesh spine ships in CI as
[crates/koi-embedded/tests/whole_story.rs](../../crates/koi-embedded/tests/whole_story.rs)
(two embedded daemons exchange the certmesh lifecycle in one `cargo test`); the
real-binary two-daemon companion is
[crates/koi/tests/two_daemon_certmesh.rs](../../crates/koi/tests/two_daemon_certmesh.rs)
(ADR-018 Tier 2). These cover Acts 0–2 and the certmesh portion of Act 9. The physical
`koi-lab capability-story` driver now covers Acts 0, 3, 4, 5, 6, 7, 8, 10, and 11 in both
Linux role directions using real Docker events, derived DNS/mDNS/health/proxy state, exact
container teardown, health fixtures, UDP/SSE, MCP, IPC, native trust installation/removal,
certmesh-issued proxy certificate rotation, and ACME dns-01 through Koi's real DNS bridge.
The reusable Tier-1 breadth driver and the elevated Windows participant remain targets.
The design content below is the target contract, not a claim that every Act already has
one composed test.
**Date:** 2026-06-18
**Relates to:** ADR-015 (Certmesh Enrollment Hardening — its features are validated by this surface), ADR-018 (the integration-test-suite tiers that realize this), [docs/SURFACES.md](../SURFACES.md) (the surface ledger this feeds), ADR-008 (Embedded Facade — the harness substrate)

---

## Purpose

The target is one test surface that drives a realistic Koi deployment through the **complete lifecycle of certmesh and every other capability, plus the cross-capability interactions that are the actual point of the stack** — a labeled container becoming a discoverable, resolvable, health-checked, proxied, certificate-bearing service that shows up in the unified status, the dashboard feed, and the MCP inventory, then is revoked and torn down with everything unwound in reverse.

It is being delivered in **two tiers intended to share one scenario contract**:

- **Tier 1 — single-host multi-instance (CI-able):** N daemons on one machine via `KOI_DATA_DIR` + distinct ports; runs in the existing 3-OS CI matrix. Proves the logic.
- **Tier 2 — real multi-machine (Windows host + Linux servers):** the same acts against real hosts; proves the genuinely-distributed behaviors CI cannot (real multicast, cross-host mTLS, revocation propagation, real containers, proxy data plane). Manual/scheduled, not a PR gate.

This is a design spec; implementation follows the phasing at the end.

---

## Design principles

1. **Reuse, don't reinvent.** Build on the existing substrate: the `koi-embedded` `Builder` (every capability toggle — [lib.rs:62-253](../../crates/koi-embedded/src/lib.rs#L62)), the `embedded-integration.rs` harness patterns (HTTP + IPC + in-process drivers, `wait_for_event`, pass/fail tracking — [embedded-integration.rs](../../crates/koi-embedded/examples/embedded-integration.rs)), `temp_data_dir()` isolation ([tests/embedded.rs:9-26](../../crates/koi-embedded/tests/embedded.rs#L9)), and the blocking `koi-client` (ureq) as a black-box driver ([koi-client/src/lib.rs:62-90](../../crates/koi-client/src/lib.rs#L62)).
2. **Drive the public surfaces; assert observable outcomes + events.** HTTP API, CLI/IPC, and the `KoiEvent` broadcast — never reach into private state.
3. **One scenario, two tiers.** The same ordered Acts run in-process/multi-instance for CI and against real hosts for fidelity; differences are isolated to the driver and gating flags.
4. **Honesty over green.** What cannot truly run is gated and *labeled*, and every surface the run exercises updates its [SURFACES.md](../SURFACES.md) row per the rotation contract. The proxy data plane is independently guarded by `koi-proxy` tests; this scenario must not claim the composed certmesh-issued/native-trust path until it drives that path itself.

---

## The whole story (the canonical scenario)

Ordered **Acts**; each lists *drive → assert (+ events)*. Acts 1–2 and 9 also serve as the executable validation of ADR-015. Two instances are the minimum: **A** = cornerstone (CA + orchestrator + all caps), **B** = member.

| Act | Drive | Assert (+ events) | Cross-capability point |
|---|---|---|---|
| **0. Genesis & isolation** | Bring up A and B with distinct `KOI_DATA_DIR` + ports (`1564x` / `1664x`); `GET /healthz`; read breadcrumb. | 200 OK; breadcrumb carries endpoint + DAT; A and B cannot see each other's state. | per-daemon isolation |
| **1. CA genesis** | A `POST /v1/certmesh/create` (fixed entropy → reproducible CA), unlock, `GET /v1/certmesh/status`. | `ca_initialized`; issued CA cert profile correct (basicConstraints `pathlen:0`, KeyUsage) — **ADR-015 F10**. | — |
| **2. Enrollment** | A mints an invite for B (**ADR-015 F2**); B generates keypair+CSR locally and joins (**F1**); verify fingerprint from invite (**F3**). | Chain verifies to CA; **mechanically assert no `PRIVATE KEY` bytes in any response** (F1); roster has B; `member_joined` audited; idempotent retry returns same cert (**F8**); bad hostnames rejected (**F15**). `CertmeshMemberJoined`. | enrollment custody |
| **3. DNS** | A `POST /v1/dns/add` in-zone names; `GET /v1/dns/lookup`; start resolver on `15353`; query it. | entries resolve via stub and real resolver; member names in zone. `DnsEntryUpdated`. | dns ↔ certmesh (in-zone) |
| **4. mDNS** | A announce service; B discover (SSE) + resolve; heartbeat; unregister. | Resolved/Removed; lease renews. Non-meta `ServiceFound` is intentionally coalesced into the richer resolved record. `MdnsResolved/Removed`. | discovery |
| **5. Runtime + orchestrator (keystone)** | Start a labeled container (`koi.enable=true`, `koi.dns.name`, `koi.health.path`, `koi.proxy.port`) **or** inject a synthetic `RuntimeEvent::Started` (CI without Docker). | Appears in `/v1/runtime/instances` with `KoiMetadata`; orchestrator auto-creates an mDNS reg + DNS name + health check + proxy entry ([orchestrator.rs](../../crates/koi-compose/src/orchestrator.rs)). `RuntimeInstanceStarted` → derived `DnsEntryUpdated`/`ProxyEntryUpdated`/etc. | **the full auto-wiring story** |
| **6. Health** | Health check targets a real fixture listener (`127.0.0.1:0`); stop/start it. | status Up→Down→Up; `HealthChanged` on each transition. | health ← mdns/dns targets |
| **7. Proxy data plane** | A `POST /v1/proxy/add` sourcing cert from certmesh; connect a native TLS client through the listener to a real fixture backend. | entry reports honest `state`/`error` + `cert_source`; trusted TLS and body/full-duplex bytes round-trip; an untrusted client is rejected; a rotated cert is served without restarting the listener. `ProxyEntryUpdated`. | proxy ← certmesh cert + truststore |
| **8. UDP bridge** | A bind (`port:0`), B `GET /v1/udp/recv/{id}` (SSE); A `POST /v1/udp/send`; round-trip; heartbeat; unbind. | datagram arrives (base64 payload); lease renews. | datagram bridge |
| **9. Trust dynamics** | Fetch `GET /v1/certmesh/trust-bundle`; verify signature + sequence (**ADR-015 F4**); revoke B; re-fetch; B attempts mTLS + health. | bundle verifies; replayed lower-sequence bundle rejected (anti-rollback); after revoke the **sequence increments** and B is **rejected** at mTLS + health; renewal pull within grace succeeds, past grace refused (**F6**); `RenewResponse.ca_fingerprint` refreshes the pin (**F5**); promote validates the received key (**F14**). `CertmeshMemberRevoked`. | revocation propagation |
| **10. Aggregation** | `GET /v1/status`; subscribe `/v1/dashboard/events`; read MCP resources at `/v1/mcp` (`koi://lan/inventory`, `koi://health`, `koi://dns/zone`, `koi://mdns/services`); `GET /.well-known/mcp/server-card.json`; `GET /v1/host`. | status lists every enabled cap with `running` truth; the dashboard feed shows the cross-domain events emitted by Acts 2–9 (forwarder maps all 6 domain types — [forward.rs](../../crates/koi-dashboard/src/forward.rs)); MCP inventory reflects live runtime/health/dns/mdns; server-card unauthenticated, `/v1/mcp` token-gated. | **unified observability** |
| **11. Teardown & reverse cleanup** | Stop the container (or inject `RuntimeEvent::Stopped`); destroy the certmesh (`POST /v1/certmesh/destroy`). | orchestrator reverses every registration (mDNS unregister, DNS remove, health remove, proxy remove); `koi.enable=false` containers are skipped; B unaffected by A's destroy (isolation). | reverse auto-wiring |

A dedicated **ACME dns-01** mini-act (when DNS + certmesh are both up): place an in-zone order with a real `instant-acme` client, publish the proof through Koi's authenticated ephemeral-TXT API, observe it from the other host with `dig`, assert issuance through the real `AcmeDnsBridge → DnsCore` path, exact-clear only that proof, and verify the resulting chain and SAN.

---

## Harness architecture

A shared broad-scenario driver remains to be implemented. The certmesh spine currently
lives directly in these integration tests:

- **`crates/koi-embedded/tests/whole_story.rs`** — always-on, pure-Rust two-participant certmesh coverage over real HTTP and mTLS.
- **`crates/koi/tests/two_daemon_certmesh.rs`** — always-on two-real-binary coverage of production DAT middleware, enrollment adapters, and revocation boundaries.

The v1 epic will choose the final home for the reusable local/remote driver before Acts
3–8 and 10–11 are added. The types below describe that target architecture.

Core types:

- **`Story`** — owns `Vec<Instance>`, a step runner with pass/fail/skip tracking (mirror the existing `Harness` struct), per-instance event collectors, and explicit capability probes such as `docker_available()` and `multicast_available()`.
- **`Instance`** — either an in-process `koi-embedded` handle (Tier 1, fast in-process assertions via `handle.subscribe()`) or a remote endpoint driven by `koi-client` with `--endpoint/--token` (Tier 2). The Act bodies are written against an abstraction so the same code runs both tiers.
- **Drivers:** in-process handle (embedded) for speed; `koi-client` (ureq, blocking) for HTTP black-box; `reqwest` for SSE streams (dashboard/discover/recv). Tier 2 uses `koi-client` exclusively.
- **Isolation:** `temp_data_dir()` per instance; distinct `--port/--mtls-port/--acme-port/--dns-port`; `KOI_NO_CREDENTIAL_STORE=1` (as CI sets).

### Required test affordances (prerequisites to flag)

1. **An approving enrollment decider for tests.** The default is `deny_and_log_decider` ([koi-compose/src/certmesh.rs](../../crates/koi-compose/src/certmesh.rs)), so automated enrollment cannot complete. Add a `Builder` hook (test-only) to inject an auto-approving decider, or drive `open_enrollment` + `requires_approval=false`.
2. **Synthetic `RuntimeEvent` injection.** To exercise the orchestrator bridge (Act 5) without Docker in CI, expose a test path to feed a `RuntimeEvent::Started/Stopped` into `RuntimeCore`'s event channel. Real containers run only when `docker_available()` (Tier 2 / Docker-in-CI).
3. **Reproducible certmesh.** Fixed entropy seed so the CA/fingerprint are deterministic across runs.
4. **ADR-015 coupling.** The enrollment acts (2, 9) target the ADR-015 flow (invite + CSR + bundle). Until F1/F2/F4 land they drive the current TOTP/push path; each ADR-015 phase upgrades the corresponding act. This surface is the acceptance gate for ADR-015.

---

## Tier 1 — single-host multi-instance (CI-able)

Runs in the existing `test` job on ubuntu/windows/macos ([ci.yml](../../.github/workflows/ci.yml)). Coverage per capability:

| Capability | Tier 1 coverage | Gating / note |
|---|---|---|
| certmesh | **Full** lifecycle + enrollment + trust bundle + revoke + renew/grace | fixed entropy; test decider |
| dns | **Full** | resolver on `15353` (port 53 needs elevation) |
| health | **Full** | fixture listeners on `127.0.0.1:0` |
| udp | **Full** | `port:0` auto-assign; low lease for expiry tests |
| mdns | **Functional**, best-effort cross-instance | in-process `MdnsCore` asserts always; real multicast short-timeout + skip-with-log if unavailable |
| runtime + orchestrator | **Synthetic lifecycle + startup reconciliation implemented** | always-on `koi-compose` story starts the orchestrator after a normalized instance already exists, then proves inventory plus mDNS/DNS/health/live-proxy reconstruction and stop reversal through the same start/stop chokepoints; real containers stay Tier 2 |
| proxy | **Unit data plane complete; Tier-1 trust composition pending** | `koi-proxy` guards TLS round-trip, full duplex, bind error, and certificate hot reload; physical Act 7 is green, while portable native-trust composition is platform-limited |
| status / host / dashboard / MCP | **Full** | Two concurrent real daemons each prove the centralized seven-rung status/dashboard projection, host JSON, public server card, DAT refusal, all 11 MCP tools, all four resources, and a live read |
| ACME dns-01 | **Optional** real bridge act | when DNS + certmesh up |

CI wiring: the certmesh spine, synthetic runtime/orchestrator lifecycle, and two-real-daemon HTTP/dashboard/MCP breadth are always-on regression tripwires. The portable aggregation test is `cargo test -p koi-net --test two_daemon_certmesh --locked`; keep any future long-running multi-instance breadth profile explicit and document its command in the test module header (mirroring `acme.rs`).

---

## Tier 2 — real multi-machine (Windows host + Linux servers)

The target distributed superset runs across **W** (a Windows host), **L1**, **L2**. The
existing two-box certmesh scripts prove a valuable subset but are not yet this full
three-node, all-capability scenario:

- `koi install` on each (SCM / systemd); real ports 5641/5642/5643, DNS on 53 (elevated), real Docker on a Linux host for Act 5.
- A driver runbook (PowerShell + bash, or a `koi`-driven script using `koi-client --endpoint/--token`) executes the **same Acts** against real endpoints, collecting pass/fail. Reuses and extends the ADR-015 deployment runbook to all capabilities.
- Proves what Tier 1 structurally cannot: real multicast discovery across hosts, cross-host mTLS handshake, **revocation-propagation latency** (revoke on L1 → measure when W/L2 reject), real container → auto-wire → resolve/health/proxy, and the proxy **data plane** TLS round-trip with a certmesh-issued cert through native trust.
- Scheduling: manual, or a `schedule`d cloud/cron routine; never a PR gate. Results feed the SURFACES ledger.

---

## Coverage traceability

**Capabilities → Acts:** mdns (4,5,10), dns (3,5,10, ACME), health (5,6,10), proxy (5,7,11), udp (8), runtime/orchestrator (5,11), certmesh (1,2,9,11), dashboard (10), MCP (10), status/host (10), truststore (1, via CA install). Every capability on the contract surface (STACK-0001 D7: mdns/dns/certmesh/udp/truststore) is exercised end-to-end.

**ADR-015 features → Acts:** F1/F3/F8/F15 → Act 2; F2 → Act 2 (invite mint); F4/F5/F6/F14 → Act 9; F10 → Act 1; F7/F9/F11/F13/F16 → asserted inline (rate-limit fail-closed at Act 2 negatives; audit failures at Act 2; auto-unlock/machine-change at Act 0 Tier 2 clone; cert_path omission at Act 2 status; K2/FIDO2 by the `surfaces` CI job, not this harness). F12 (mDNS advertise) → Act 4.

---

## SURFACES.md ledger integration

On each green run, update only the rows that run actually exercised, per the **rotation contract** (binding, top of [SURFACES.md](../SURFACES.md)). The certmesh-only spine can advance certmesh evidence; it cannot advance mdns, dns, health, udp, truststore, or the broad whole-story claim. The physical `capability-story` may augment—rather than replace—the focused domain guards for every surface it actually composes. Note Tier 1 versus Tier 2 in the row.

---

## Constraints (the honest gaps)

- **Reusable composed proxy trust path** — physical Linux Act 7 is green in both role directions, including native trust, hostname verification, hot certificate rotation without daemon restart, exact trust removal, and fail-after-removal. The remaining gap is a reusable Tier-1 composition where the platform permits it.
- **Runtime without Docker** — implemented through `RuntimeCore::ingest_event`, the same inventory-and-fan-out chokepoint real backends use. The always-on `koi-compose` story proves startup reconciliation, derived mDNS/DNS/health/live-proxy state, and exact reversal. Physical Linux runs prove the same reconstruction after restarting Koi while a real container remains running. Real containers remain Tier 2 / Docker-available CI; Docker event-stream disconnect/reconnect is still V1-05 work.
- **mDNS in CI** — multicast works on GH runners but can fail in isolated networks; Tier 1 always asserts via in-process `MdnsCore` and treats cross-instance multicast as best-effort.
- **DNS port 53** — elevation required; Tier 1 uses `15353`. Tier 2 uses 53 (elevated) to validate the system resolver path.
- **Enrollment approval** — default decider denies; needs the test affordance above.
- **Credential store** — disabled in CI (`KOI_NO_CREDENTIAL_STORE=1`); keychain-specific behavior (auto-unlock sealing, ADR-015 F11) is a Tier 2 assertion (clone-without-keyring refuses).
- **IPC adapter** — requires mDNS enabled; the Windows named-pipe path is exercised only with mDNS on.

---

## Phasing

1. **Spine — complete for certmesh:** Acts 0–2 and the certmesh trust/revocation portion of Act 9 are guarded by the embedded and real-binary suites.
2. **Breadth — physical Linux complete; reusable Tier 1 pending:** `koi-lab capability-story` drives Acts 0, 3, 4, 5, 6, 7, 8, 10, and 11 plus the ACME dns-01 mini-act in both Linux directions. The same breadth still needs a CI-able in-process driver.
3. **Orchestrator — physical and synthetic complete:** a locally assembled run image drives real Docker start/stop, while the always-on Tier-1 test feeds normalized lifecycle events through the same runtime chokepoint. Both create and reverse mDNS, DNS, health, and a live self-signed TLS proxy.
4. **Proxy composition — physical complete:** retain the existing `koi-proxy` data-plane guards and augment them with the certmesh-issued/native-trust/DNS end-to-end Act 7, green in both Linux role directions.
5. **Remaining:** reusable Tier 1 breadth, scheduled hardware execution, and elevated Windows participation.

Each phase ships its tests green under `cargo test && cargo clippy -- -D warnings && cargo fmt --check`, runs on the 3-OS matrix, and updates the ledger.
