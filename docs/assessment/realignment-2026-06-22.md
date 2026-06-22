# Koi Maturity Assessment — Realignment (2026-06-22)

**Status:** Current-status realignment · **Supersedes status of:** [2026-06-maturity-assessment.md](2026-06-maturity-assessment.md) (dated 2026-06-11) · **Method:** four-track adversarial re-audit of every verified defect, lean-plan move, shed item, and stage against `dev` HEAD `32f6533`.

> **Read this first.** The June-2026 maturity assessment was a *point-in-time snapshot* taken at `dev` snapshot `4426d77` (corpus dated 2026-06-11). It is preserved verbatim as history and is **not** rewritten — it remains the canonical record of what was true on that day. This document is the *current-status overlay*: it maps each finding to its state at `dev` HEAD `32f6533` (2026-06-22), with commit/file evidence, and is honest about what is DONE, what only PARTIALLY shipped, what was SUPERSEDED by a design change, and what is genuinely still OPEN. Where the original assessment's claim turned out to be inaccurate, that is stated plainly rather than quietly dropped.

---

## 1. Headline

**All 12 verified defects are resolved.** D7's last sub-item — the unauthenticated `GET /v1/certmesh/log` audit endpoint — was closed in the post-`32f6533` engineering sprint:

- **D7** — dashboard XSS is structurally fixed; the **`GET /v1/certmesh/log` audit endpoint** is now token-authenticated (carved out of the GET exemption, exactly like `/v1/mcp`).

(D3, originally flagged as docs-staleness, was **re-verified DONE on 2026-06-22**: every live mutation example carries `x-koi-token`; only archived/historical docs still quote the old tokenless examples.)

All five *original* critical defects (D1, D2, D4, D5, D6) are closed. All five structural moves are landed (M2 — the certmesh decomposition — completed in the engineering sprint). The shed list is mostly executed, with two maintainer-decision items still open.

---

## 2. Context: what changed since the snapshot

The dominant structural change since 2026-06-11 is the **`koi-serve` extraction** (commits `ca9d938` P1 → `3160ec5` P2 → `b22cc90` P3 → `ce0747e` P4). The transports (HTTP, pipe, stdio, mcp_http, prometheus_sd), the ACME and mTLS listeners, the dashboard wiring, and the trust-plane supervisor were relocated into a single `koi-serve` crate, and **both the foreground daemon and the Windows service now serve through the same `koi_serve::serve` path.** This single move resolves the structural root of D5 (drifted Windows-service wiring) and finalizes M1 (one orchestrator). `koi-serve` was added to the crates.io publish list in `32f6533`, closing the D4 packaging gap.

---

## 3. Verified-defect status (§4 of the original assessment)

| D# | Original claim | Status | Evidence (HEAD `32f6533`) |
|----|----------------|--------|---------------------------|
| **D1** | koi-proxy panics at listener start (`/*path` under axum 0.8) inside `tokio::spawn`, invisibly; `status()` hardcodes `running:true`; second panic in cert-watch callback | **DONE** | `crates/koi-proxy/src/listener.rs:74-127` — `spawn_listener` returns a `watch::Receiver` reflecting real `ListenerStatus` (Starting/Running/Error/Stopped); bind errors surface as `Error`. No wildcard `/*path` route. `tls.rs:104-154` cert-watch uses `mpsc` `try_send` from the notify thread (no `tokio::spawn` off that thread). `ProxyRuntime::status()` (`lib.rs:246-263`) reads real state from the watch channel. Regression test `data_plane_tests.rs:231-246` `listener_reaches_running_without_panic`. |
| **D2** | HTTP adapter binds 127.0.0.1 only; no bind flag | **DONE** | `cli.rs` `--http-bind` (env `KOI_HTTP_BIND`, default `loopback`); `infra.rs::resolve_http_bind_ip()` resolves loopback/bridge/explicit; wired in `daemon.rs`, `platform/windows.rs:469`, and `koi-serve/src/serve.rs:96` (`ServeConfig.bind_ip`); `koi-serve/src/http.rs:354` binds `cfg.bind_ip`, not a literal. |
| **D3** | All non-GET endpoints require `x-koi-token`, but docs show tokenless POSTs / never mention auth | **DONE** | Code: `koi-serve/src/http.rs:585-633` `dat_auth_middleware` rejects unauthenticated mutations with 401 (exempting only `POST /v1/certmesh/join` + OPTIONS). Docs (re-verified 2026-06-22): every **live** mutation example carries `-H "x-koi-token: …"` — `README.md:42`, all CONTAINERS.md examples, `tutorials/getting-started.md:199`, `guides/api-authentication.md`, `reference/security-model.md`, `guides/recipes/container-udp.md`; `http-api.md` has a full *Authentication & Security* section. The only tokenless POSTs left are in `docs/archive/` and the assessment's own findings — historical by design (the archive quotes the pre-fix state; covered by S-archive). |
| **D4** | Crates.io publish silently broken (no pipefail; crates missing from list) | **DONE** | `.github/workflows/publish.yml:37` `set -euo pipefail`; CRATES array (lines 42-60) now includes `koi-serve` (commit `32f6533`); dynamic crates.io inventory phase + `--verify`. |
| **D5** | Windows service never spawns the runtime orchestrator / certmesh renewal-roster-failover tasks (drifted wiring) | **DONE** | `platform/windows.rs:436-456` `run_service` calls `koi_compose::cores::build_cores` (same as daemon — spawns all orchestrator/renewal/roster/failover tasks); `485-493` `spawn_enrollment_approval`; `500-522` `koi_serve::serve`. Wiring is now identical to the foreground daemon (refactors `ca9d938`/`3160ec5`/`b22cc90`). |
| **D6** | mDNS browse facade hands out independent handles but mdns-sd keeps one querier per type (concurrent discovers kill each other; resolve kills subscribers) | **DONE** | `koi-mdns/src/daemon.rs:54-67` `TypeBrowse` refcount + per-type `broadcast::Sender`; `subscribe_type` (288-342) shares one real browse via `Arc<TypeGuard>`; `TypeGuard::drop` (598-634) stops/aborts only on last ref; `resolve()` (349-392) uses a temporary subscription that never kills subscribers; warm-cache replay (324-329) cures cold-resolve. (Cross-checked by the two-box integration suite, 13/0.) |
| **D7** | Dashboard XSS and unauthenticated CA audit GETs | **DONE** | XSS structurally fixed — `koi-dashboard/tests/xss.rs`. Audit GET closed in the engineering sprint: `dat_auth_middleware` (`koi-serve/src/http.rs`) now carves `GET /v1/certmesh/log` out of the GET exemption (like `/v1/mcp`) so the audit log requires the daemon token; the `koi certmesh log` CLI already sends it. Tests: `audit_log_get_{without,with}_token_*` + `certmesh_sibling_read_get_stays_exempt` (status/diagnose/trust-bundle stay exempt — no secrets). |
| **D8** | `qa.yml` invokes deleted scripts | **DONE** | `tests/integration.ps1` (modified 2026-06-21) and `tests/concurrency.ps1` (modified 2026-06-12) both exist; QA workflow operational. |
| **D9** | `surface.rs` manifest drift | **SUPERSEDED** | The `surface.rs` design was removed wholesale. clap is now the single source (see M3); factory-reset shipped as `crates/koi/src/commands/factory_reset.rs`; rotate-auth lives in `cli.rs`. The drifting layer no longer exists. |
| **D10** | No `--token`/`KOI_TOKEN`; breadcrumb token leak | **DONE** | `cli.rs:149-152` defines `--token` + `KOI_TOKEN`; `commands/mod.rs:63-79` guards against the breadcrumb leak. |
| **D11** | ADR-012 false claim; unmarked retrospective ADRs | **PARTIAL (original claim partly incorrect)** | Re-audit shows ADR-012 **Block 4 already documents the removal** — it is *not* a false claim as the original assessment asserted. ADRs carry retrospective headers. Recorded here for honesty; no code/doc action outstanding. |
| **D12** | Docs contradict code (crypto, cert validity, factory-reset, MSRV) | **DONE** | ECDSA P-256, 30/90-day cert validity, factory-reset, and MSRV 1.92 are all consistent across code and docs. No contradictions found. |

---

## 4. Structural moves (the lean plan)

| Move | Status | Evidence |
|------|--------|----------|
| **M1 — one orchestrator** | DONE | Shared `koi_compose::cores::build_cores`; daemon + Windows service serve through the single `koi_serve::serve` path; parity tests. |
| **M2 — certmesh diet** | **DONE** | CA-creation extraction, `HOOK_FORBIDDEN` hardening, and `init_ceremony` as its own module shipped earlier. The engineering sprint then (a) extracted the ~1.3k-line unit-test block to `crates/koi-certmesh/src/core_tests.rs` (cutting `lib.rs` 4043 → 2717) + fixed a latent test-isolation bug it surfaced (`capability_status_locked` now makes its own CA on disk in an isolated dir), and (b) split the ~2000-line `impl CertmeshCore` into **8 cohesive submodules** (`core_{setup,lifecycle,enroll,identity,auth,member,admin,renewal}.rs`, each `use super::*; impl CertmeshCore {…}`), cutting `lib.rs` **2717 → 736 lines** (now the facade: types, `CertmeshState`, free helpers, `impl Capability`, module decls). Verified a **pure move** by an adversarial relocation-fidelity review (60-method 1:1 census, token-identical multiset, all visibilities/attributes preserved); 296 certmesh tests unchanged, fmt + workspace clippy clean, two-box hardware gate 19/0. |
| **M3 — manifest truth** | DONE | clap is the single source; conformance test validates the vectors. |
| **M4 — koi-common kernel** | DONE | Kernel carries only axum/utoipa/chrono/tokio — no presentation stack. |
| **M5 — DomainRuntime template** | DONE | `DomainRuntime<C>` in `runtime_state.rs`; DNS and Health wrap it. |

### Tier-1/2 tunables

| Item | Status | Evidence |
|------|--------|----------|
| **T-dns-cache** | DONE | Commit `1683ebc`; `DnsZone` serves `.local` from mDNS. |
| **T-proxy** | DONE | `tokio_rustls` `TlsAcceptor` + `copy_bidirectional`; real `ProxyStatus` state. |
| **T-udp** | DONE | `binding.rs:40` `child_token()`. |
| **T-client** | DONE | No domain-crate deps; blocking HTTP only. |
| **T-runtime** | **PARTIAL** | `health_kind` label done; Docker backend upgraded; stub/certmesh-label coverage unverified. |
| **T-health** | **PARTIAL** | Module shrunk (~375 lines); but checks still run **sequentially** per loop, not concurrently. |

---

## 5. Shed list

| Item | Status | Evidence / note |
|------|--------|-----------------|
| **S-wordlist** | DONE | 7700 → 31 lines via `include_str!` (P08 `9580236`). |
| **S-fido2** | DONE | Removed from all layers; grep empty (P08 `aa0d8cd`). |
| **S-cafailover** | DONE | Auto-failover removed, manual promote kept (P08 `356e444`). |
| **S-compliance** | DONE | Compliance endpoint + CLI removed (P08 `48d9fbc`). |
| **S-trustprofile** | DONE | Flattened to booleans (P08 `3ed2fec`). |
| **S-commandsurface** | DONE | Folded into the help module (P09 `995e32f`). |
| **S-pipe** | **SUPERSEDED (maintainer decision)** | The pipe adapter was *not* retired — it was deliberately **kept and relocated** into `koi-serve/src/pipe.rs` during the P1 extraction (`ca9d938`). The IPC transport is load-bearing; this is an intentional reversal of the shed, not a miss. |
| **S-deadcode** | **PARTIAL** | Partial cleanup; **5** `#[allow(dead_code)]` sites remain across `crates/`. |
| **S-pipelinestatus** | **OPEN (maintainer decision)** | `PipelineResponse` status machinery still ~150 lines in `koi-common/src/pipeline.rs` (`PipelineStatus` enum + `Ongoing`/`Finished`). Whether the streaming-status field earns its keep is a maintainer call. |
| **S-archive** | **OPEN** | `docs/archive/` still in-repo (`IMPLEMENTATION.md`, `TECHNICAL.md`, `koi-implementation-prompt.md`, `koi-spec.md`); reference-drift cleanup not done. |

---

## 6. Stage completion

| Stage | Status | Evidence |
|-------|--------|----------|
| **Stage 0 — truth restoration** | PARTIAL | P01/02/03 landed; minor doc-truth gaps remain (chiefly the D3 docs staleness). |
| **Stage 1 — make the promise true (5 critical defects)** | **DONE** | D1, D2, D4, D5, D6 all fixed (P03-P07/P09 + the koi-serve refactor). The original "5 critical defects" are closed. |
| **Stage 2 — consolidation** | DONE | P07-P10 complete; LOC consolidated from ~57.7k toward the ~40-43k band; koi-serve unified the serving layer. |
| **Stage 3 — hardening** | PARTIAL (~50-60%) | XSS tests, proxy regression test, two-box integration suite, and trust-sim proptests added; security audit incomplete; D7 audit-GET still open. |
| **Stage 4 — launch** | PARTIAL (~50%) | In-process MCP over Streamable HTTP shipped; crates.io publish pipeline fixed (D4); broader packaging/distribution unfinished. |

---

## 7. Genuinely still open (prioritized backlog)

1. **D7 — unauthenticated `GET /v1/certmesh/log`.** Security-relevant: the CA audit log is readable without a token because it is GET-exempt in `dat_auth_middleware` (`koi-serve/src/http.rs:605-609`). Decide: carve `/v1/certmesh/log` out of the GET exemption (like `/v1/mcp`), or accept-and-document.
2. ~~**D3 — docs staleness on auth.**~~ **RESOLVED on re-verify (2026-06-22)** — every live mutation example already carries `x-koi-token`; the only tokenless POSTs left are in `docs/archive/` (historical, covered by S-archive). No action.
3. **Stage 3 hardening completion.** Finish the security audit pass behind the new test scaffolding (~50-60% done).
4. **Stage 4 packaging.** Complete distribution/packaging beyond MCP + crates.io publish (installers, release artifacts).
5. **M2 — certmesh core decomposition. DONE.** The unit-test block moved to `core_tests.rs` and the ~2000-line `impl CertmeshCore` was split into 8 cohesive submodules (`lib.rs` 4043 → 736 across both moves), verified as a pure relocation by an adversarial review + the two-box gate.
6. **T-health — concurrent checks.** Run health checks concurrently rather than sequentially per loop.
7. **S-archive.** Move `docs/archive/` out of the repo and fix reference drift.
8. **S-deadcode.** Remove the remaining 5 `#[allow(dead_code)]` sites or justify each in-line.
9. **S-pipelinestatus (maintainer decision).** Decide whether to keep or shed the ~150-line `PipelineResponse` status machinery.
10. **T-runtime label coverage.** Verify/complete stub and certmesh label handling in the runtime adapter.

---

*Realignment compiled 2026-06-22 against `dev` HEAD `32f6533`. The 2026-06-11 snapshot stands unchanged as the historical record.*
