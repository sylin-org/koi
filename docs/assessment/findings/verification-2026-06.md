# Claim Verification Record — June 2026

Fourteen load-bearing claims from the deep-read reports (`reader-*.md`) were adversarially
re-verified against the actual code, git history, dependency sources, and external state
before being admitted into the [maturity assessment](../2026-06-maturity-assessment.md).
**All fourteen were confirmed.** Nuances and corrections are noted per claim.

| # | Claim | Verdict | Severity |
|---|-------|---------|----------|
| 1 | koi-proxy data plane is broken (axum 0.8 route panic, silent) | **Confirmed** | Critical |
| 2 | Headline container use case broken as documented (loopback-only bind) | **Confirmed** | Critical |
| 3 | All documented mutation examples return 401 (undocumented DAT auth) | **Confirmed** | High |
| 4 | crates.io publishing silently broken since February | **Confirmed** | High |
| 5 | Scheduled QA workflow can never pass (deleted scripts) | **Confirmed** | Medium |
| 6 | Windows service mode lacks orchestrator + certmesh background tasks | **Confirmed** | High |
| 7 | surface.rs command manifest drifted from real CLI, zero tests | **Confirmed** | Medium |
| 8 | ADR-012 contains false history; ADRs 001–010 backdated | **Confirmed** | Medium |
| 9 | mDNS browser page has LAN-sourced XSS vectors | **Confirmed** | High |
| 10 | `--endpoint` auth token trap | **Confirmed** | Medium |
| 11 | PipelineResponse status machinery + Confirmation gates are dead code | **Confirmed** | Low |
| 12 | Size facts (wordlist, eval_init, main.rs business logic) | **Confirmed** | Info |
| 13 | Reference docs contradict code (crypto algorithm, cert lifetime, factory-reset) | **Confirmed** | Medium |
| 14 | mdns-sd single-querier-per-type unmodeled; boundary rule violated in-crate | **Confirmed** | High |

---

## 1. koi-proxy data plane is broken — CONFIRMED (Critical)

- `crates/koi-proxy/src/listener.rs:46` registers `.route("/*path", any(proxy_handler))`.
- Resolved axum is **0.8.8** (Cargo.lock). axum 0.8 removed `/*wildcard` syntax in favor of
  `/{*wildcard}` and **panics** at route registration with "Path segments must not start
  with `*`". No `without_v07_checks` call exists anywhere in the repo.
- The router is built inside `tokio::spawn` (`koi-proxy/src/lib.rs:~207`), so the panic kills
  the spawned task silently — the daemon keeps running.
- `ProxyRuntime::status()` (`lib.rs:238–250`) hardcodes `running: true` for every entry, so
  the failure is unobservable through the API, CLI, and dashboard.
- Second latent panic: `watch_certs` (`listener.rs:66–90`) calls `tokio::spawn` inside the
  `notify::recommended_watcher` callback, which runs on notify's own (non-tokio) thread —
  the first cert-change event panics the watcher thread, silently killing hot reload.
- No test anywhere starts a TLS listener; the only proxy integration test exercises config
  events. **Conclusion: TLS termination — the crate's headline feature — cannot have worked
  since the axum 0.8 upgrade, and the system reports it as running.**

## 2. Container use case broken as documented — CONFIRMED (Critical)

- `crates/koi/src/adapters/http.rs:238`: `TcpListener::bind(("127.0.0.1", port))` with the
  explicit comment "Bind to loopback only."
- `CONTAINERS.md:31` claims: "Koi binds to `0.0.0.0:5641` — every network interface,
  including the Docker bridge gateway. Containers can reach it without any extra
  configuration." This is false against the current binary.
- No CLI flag or env var exists to change the HTTP bind address (verified across cli.rs —
  the only "bind" surface is `koi udp bind`).
- Platform nuance: on **Docker Desktop** (Windows/macOS), `host.docker.internal` proxies to
  the host's loopback, so parts of the flow may still work there. On **native Linux Docker**
  — the dominant homelab platform (selfh.st 2025: Linux 81%) — the documented
  `172.17.0.1` / `host-gateway` paths cannot reach a loopback-bound daemon. The 914-line
  CONTAINERS.md guide fails at its first curl on the primary target platform.

## 3. Documented mutation examples return 401 — CONFIRMED (High)

- `dat_auth_middleware` (`http.rs:455–495`) exempts only GET/HEAD/OPTIONS; every other
  method requires `x-koi-token` (constant-time compared), else 401.
- The token is regenerated per daemon start and distributed only via the breadcrumb file.
- `README.md:34` (`curl -X POST .../v1/mdns/announce`), the CONTAINERS.md POST examples,
  and `docs/reference/http-api.md` all show unauthenticated POSTs. http-api.md — the
  self-described authoritative reference — never mentions the token at all (its only "auth"
  hits refer to certmesh enrollment auth).

## 4. crates.io publishing silently broken — CONFIRMED (High)

- The publish step (`release.yml`, `publish` job) declares no `shell:` key, so it runs under
  GitHub Actions' default `bash -e {0}` — **without pipefail**. (`shell: bash`, which would
  enable pipefail, appears only in the build jobs at lines 28/92/101/129/161.)
- Therefore `cargo publish -p $crate --locked 2>&1 | tee ...` always exits 0 (tee's status),
  the `|| { ... exit 1 }` error handler is dead code, and the job reports green regardless.
- The `CRATES` list (release.yml:218–231) contains 12 crates and **omits koi-udp,
  koi-runtime, and command-surface** — which koi-net and koi-embedded depend on. cargo
  refuses to publish a crate whose dependencies are not on the registry, so koi-net and
  koi-embedded can never publish until the list is fixed.
- Live state (crates.io API, June 11 2026): `koi-net` max_version **0.2.202602121703**,
  updated **2026-02-12** — four months stale, predating the ADR-011 security overhaul.
  `koi-udp` → "crate does not exist." Lib crates (koi-common etc.) are current at
  0.2.202603241449.
- Consequence: `cargo install koi-net` — the documented install path (README.md:125,
  release template) — resolves the Feb-12 binary source against Mar-26 lib crates via loose
  `"0.2"` requirements spanning a breaking security overhaul. Likely compile failure;
  behavioral mismatch at best.

## 5. Scheduled QA workflow can never pass — CONFIRMED (Medium)

- `qa.yml` lines 21, 43, 65, 76, 87 invoke `tests/integration.sh` / `tests/concurrency.sh`.
- `tests/` contains only `integration.ps1` and `concurrency.ps1`; the `.sh` twins were
  deleted in commit `fe8151c` (2026-02-12).
- 5 of 8 QA jobs reference nonexistent files; the weekly cron has failed every run since
  (reader observed 10+ consecutive failures through 2026-06-01). Nobody noticed — the
  feedback loop is not being watched.

## 6. Windows service mode is a weaker daemon — CONFIRMED (High)

- `orchestrator::spawn_orchestrator` has exactly one call site: `main.rs:642`.
- `spawn_certmesh_background_tasks` (main.rs:917) and `spawn_enrollment_approval_prompt`
  (main.rs:1294) are called only at `main.rs:801–802`.
- `platform/windows.rs run_service` duplicates ~400 lines of `daemon_mode()` wiring but
  calls none of the above. **A Windows service install silently lacks container
  orchestration, certificate auto-renewal, roster sync, and failover** — the platform Koi
  uniquely claims to serve well.

## 7. surface.rs manifest drift — CONFIRMED (Medium)

- `surface.rs:1245` registers `name: "certmesh rotate-totp"` while its own example at line
  1255 says `koi certmesh rotate-auth` and clap parses `rotate-auth` (cli.rs). Manifest
  lookup is exact-match, so `koi certmesh rotate-auth?` fails.
- `surface.rs` contains **zero** `#[test]` (verified). Additional drift instances
  documented in [reader-binary-cli-dx.md](reader-binary-cli-dx.md): nonexistent flags
  `--totp`, `--exec`, `--cidr`, `--process`, `--include-logs`; dns lookup claiming
  CNAME/TXT/SRV vs parser accepting A/AAAA/ANY; factory-reset claiming logs are preserved
  while `remove_dir_all` wipes the whole data dir.

## 8. ADR-012 false history; ADRs 001–010 backdated — CONFIRMED (Medium)

Verified independently by a workflow verifier with full git forensics:

- `git show 588b616:crates/koi-health/Cargo.toml` (ADR-011's own commit, 2026-03-18 06:09)
  shows dependencies on koi-certmesh, koi-dns, koi-mdns, koi-proxy. ADR-011's Root Cause 4
  describes this in present tense — it was a real finding.
- Commit `aa979d4` (2026-03-18 08:01, ~2h later): "refactor(architecture): cross-domain
  trait injection, remove 8 Cargo deps" — removed 7 cross-domain deps + hickory-proto.
- ADR-012 (committed 2026-03-25) nonetheless records: "The domain boundary model was
  implemented correctly from the start. ADR-011's description of cross-domain imports was
  prospective…" — refuted by the repo's own history. (Mitigating: ADR-012:133 preserves the
  original finding as struck-through text, so the erasure is incomplete.)
- ADRs 001–010 were all created in a single commit `8a63730` (2026-02-15) with Date headers
  spanning 2025-01-15 → 2025-12-15 — **all predating the repository's first commit
  (e4fa582, 2026-02-07)**. Nothing marks them as retrospective reconstructions.
- This is the signature failure mode of AI-maintained documentation: high fidelity to
  current code, low fidelity to causal history.

## 9. mDNS browser XSS — CONFIRMED (High)

- `esc()` (`mdns-browser.html:370`) uses `textContent → innerHTML`, which escapes `& < >`
  but **not double quotes**.
- Escaped values are interpolated into double-quoted HTML attributes at lines 477, 500,
  559, 563 (`data-type`, `title`, `data-key`). A LAN device announcing a service named
  `" onmouseover="…` achieves attribute breakout → inline-handler XSS on the dashboard
  origin.
- `inferEndpoint` (line 422) validates TXT `url=` values with bare `new URL()` — which
  accepts `javascript:` — and renders the result as a clickable launch link.
- Impact: the dashboard origin can reach all unauthenticated GET endpoints (certmesh
  status, audit log, roster), making this an exfiltration path on a tool hosting a private
  CA, triggerable by any device on the LAN.

## 10. `--endpoint` token trap — CONFIRMED (Medium)

- `detect_mode` (`commands/mod.rs:51–55`): explicit `--endpoint` → `token: String::new()`
  → every mutation against that endpoint 401s.
- `require_daemon` (`commands/certmesh.rs:~89`): explicit endpoint → "use breadcrumb token
  if available" — i.e., sends the **local** daemon's token to a possibly **remote** host:
  wrong credential, wrong host, and a mild credential-disclosure smell.
- No `--token` flag or `KOI_TOKEN` env var exists (verified in cli.rs).

## 11. Dead framework machinery — CONFIRMED (Low)

- `PipelineResponse::ongoing/finished/with_warning`: all call sites outside
  `koi-common/src/pipeline.rs` are inside `#[cfg(test)]` modules (dispatch.rs test module
  starts at line 130, hit at 241; protocol.rs test module at 253, hits at 400–417).
  Zero production callers; `.agentic/reference/api-endpoints.md` still documents the
  streaming `status` contract.
- command-surface `Confirmation::gate()/requires_confirmation()/prompt_stdio()`,
  `write_summary_catalog`, `by_tag`, `by_scope`: no callers (workspace grep); actual
  confirmation prompts hand-rolled in factory_reset.rs and certmesh.rs.
- `koi-proxy load_entries_with_certmesh`: no callers.

## 12. Size facts — CONFIRMED (Info)

- `koi-certmesh/src/wordlist.rs` = **7,784 lines** exactly (EFF wordlist as a Rust const) —
  41.8% of the crate's 18,610 LOC.
- `pond_ceremony.rs::eval_init` spans lines **79–835** (next fn at 835) ≈ 756 lines, one
  function.
- `main.rs` = 1,545 lines; `spawn_certmesh_background_tasks` at 917 and
  `spawn_enrollment_approval_prompt` at 1294 bound the certmesh background-task machinery
  living in the binary entry file.

## 13. Reference docs contradict code — CONFIRMED (Medium)

- `docs/reference/envelope-encryption.md:83` claims "Ed25519 (CA)"; `:85` claims "90 days"
  member validity. Code: ECDSA P-256 (`koi-crypto/src/keys.rs:1,96,134`),
  `CERT_LIFETIME_DAYS: i64 = 30` (`koi-certmesh/src/ca.rs:16`).
- `docs/guides/system.md:100`: "`koi factory-reset` is planned but not yet implemented" —
  while `commands/factory_reset.rs` ships fully implemented (114 lines), and the same
  guide's line 187 assumes it exists.
- Further instances (verified by the docs reader): architecture.md understating crate sizes
  4×, README "Rust 1.75+" vs `rust-version = "1.92"`, three contradicting trust-profile
  tables.

## 14. mdns-sd single-querier reality; boundary rule violated — CONFIRMED (High)

- `browse.rs:4,16,37` import `mdns_sd` types; `daemon.rs:82` returns
  `mdns_sd::Receiver<MdnsEvent>` — while `daemon.rs:38` itself claims "This is the ONLY
  file that imports mdns_sd types" and `.agentic/rules/mdns-boundary.md` enshrines the
  rule. (Contained within the crate; nothing leaks past the crate boundary.)
- mdns-sd 0.17 source (`service_daemon.rs:873`):
  `service_queriers: HashMap<String, Sender<ServiceEvent>>` — exactly one querier channel
  per service type. A second browse of the same type replaces the first's sender;
  `stop_browse` removes the type's querier and clears its cache.
- Consequence (as alleged): concurrent SSE discovers of one type silently kill each other;
  `resolve()` (browse-then-stop_browse) and `BrowseHandle::drop` terminate concurrent
  subscribers of that type; the dashboard's meta-browse cache never re-spawns a killed
  type. The facade's promise of independent browse handles is structurally false.

---

*Verification performed 2026-06-11. Claims 1–7, 9–14 verified inline by the assessing
agent; claim 8 verified by an independent adversarial workflow agent. Method: re-derive
every file:line citation from source; check dependency ground truth in the cargo registry
cache; git forensics for history claims; live API queries for external state.*
