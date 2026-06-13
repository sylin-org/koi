# Koi Prompt Stash — Progress Ledger

Tracks execution of the work orders in this directory (`P01`–`P13`). Agents:
update your row when you **start** (status `in-progress`) and when you **finish**
(`done`, `blocked`, or `obsolete`, with a one- or two-line note). Link commits by
short SHA. Uncommitted working-tree work is noted as `(wt)`.

See [README.md](README.md) for the prompt catalog and sequencing, and
[CHARTER.md](CHARTER.md) for the session protocol (research → plan → implement →
verify). Every prompt must leave a plan file at `plans/<id>-plan.md`.

| ID | Status | Date | Agent/model | Commits | Notes |
|---|---|---|---|---|---|
| P01 | done | 2026-06-11 | prior session + opus-4-8 | 221d077, 83867e4, (wt) | Docs deep-sweep: security-model.md linked from 6 docs, ADR hygiene (011→Accepted, 012 Block-4 hashes, 001–010 retro headers, dup §7.7), envelope-encryption/system/architecture/MSRV/profile tables matched to code, MSRV drift-guard test (cli.rs:1465). Gap-patch (wt): 2 tokenless CONTAINERS.md `announce` examples now carry `x-koi-token`. |
| P02 | done | 2026-06-11 | prior session + opus-4-8 | a0e6a99, 53ff67c, cf5376d, 221d077, (wt) | Version reset to 0.3.0 (=0.3.0 internal pins), version.json deleted, build.ps1 stops mutating; qa.yml `.ps1`-only; release.yml tag-only; publish.yml repaired (pipefail, 15-crate ordered list, crates.io verify) + `workflow_dispatch`-only; CI gains MSRV/cargo-audit/Dependabot; CHANGELOG seeded; README install → GitHub Releases. Gap-patch (wt): release.yml no longer reads deleted version.json (CHANGELOG extraction); build.ps1 docstring corrected. |
| P03 | done | 2026-06-13 | opus-4-8 | (wt) | `--http-bind` (loopback/bridge/`<ip>`/0.0.0.0 + `KOI_HTTP_BIND`) with startup warning UX, `koi status` `Bind:`/`http_bind`, and breadcrumb surfacing; `koi token show\|write` (tty-guarded show, 0600 write) reading the breadcrumb; Windows firewall opens the HTTP port only when exposed; both main.rs and the Windows service path wired. Tests: 7 bind/breadcrumb unit + 4 DAT-auth router (GET exempt, POST 401/200). Docs: CONTAINERS.md (banner→exposure + token/compose-secrets recipe), README, security-model.md, http-api.md, cli.md, agentic refs. Verify green: check/clippy -D/157 tests/fmt. **Live-validated** on Debian 13 with a real `docker0` bridge (cross-built musl binary): 23/23 checks incl. bridge resolution → 172.17.0.1, `koi status`/breadcrumb surfacing, token tty-refusal + 0600, and the headline **container→daemon over 172.17.0.1** (GET unauth ok, tokened POST 201, tokenless POST 401). Plan at [plans/P03-plan.md](plans/P03-plan.md). Prior broken attempt reverted (divergence log). |
| P04 | done | 2026-06-13 | opus-4-8 | 7bb0d24 | TLS-terminating passthrough replaces the broken HTTP forwarder. Fixes all 3 defects in claim 1 (axum-0.8 route panic, notify-thread cert-watch panic, no-WebSocket) structurally: `copy_bidirectional` passthrough, `ResolvesServerCert` hot-reload via notify→tokio bridge, real `watch`-channel listener state (`running`/`error`+detail), self-signed fallback. Breaking `ProxyStatus` shape propagated to dashboard/CLI/OpenAPI; `/v1/proxy/*` paths + facade unchanged. 5 in-crate integration tests (no Docker). Verify green: check/clippy -D/fmt; koi-proxy 17, workspace + certmesh 264 (single-threaded). **Caveat:** acceptance criterion 7 (smaller crate / <954 src excl tests) **not met** — prod grew ~871→~1117 because correct cert-resolution+hot-reload+self-signed+state cost more than the broken forwarder; kept charter-non-negotiable DX (zero-config self-signed) + correctness over the size target and surfaced it (see divergence). Plan at [plans/P04-plan.md](plans/P04-plan.md). |
| P05 | pending | | | | mDNS browse multiplexing — fix single-querier interference. |
| P06 | pending | | | | Presentation-layer rebuild — koi-dashboard crate; XSS hardening; koi-common back to kernel. |
| P07 | pending | | | | One orchestrator — single composition layer (prereq P03–P06 ideally). |
| P08 | pending | | | | Certmesh diet — 18.6k → ~9k LOC. |
| P09 | pending | | | | CLI surface unification — fold command-surface. |
| P10 | pending | | | | Domain template extraction (prereq P07). |
| P11 | pending | | | | koi-mcp server (prereq P03). |
| P12 | pending | | | | ACME facade (prereq P08). |
| P13 | pending | | | | Ecosystem doors — Prometheus SD, Traefik labels, DNS recipes, `koi trust` (prereq P03). |

## Divergence log

When a pre-flight check fails or repo reality contradicts a prompt, record it
here: date, prompt ID, what was found, what was done instead.

| Date | ID | Finding | Action |
|---|---|---|---|
| 2026-06-13 | P03 | Prior-session attempt left 4 uncommitted files that did not compile: `Command::Token` enum variant added with no dispatch arm (E0004); `init_logging` else-branch lost its `Ok(vec![stderr_guard])` return (E0308) — an unrelated regression; two `platform/windows.rs` call sites not updated for the new `startup_diagnostics`/`http::start` signatures (E0061×2); plus a clippy-failing unused-import warning. Token command, Windows firewall rule, tests, and all docs were absent (~40% done). | Reverted the 4 files via `git restore` (full diff captured in session history); workspace compiles again. Rebuilding P03 cleanly from a written plan. |
| 2026-06-13 | P01/P02 | Validation found two committed prompts substantively done but with minor gaps: P01 left 2 tokenless `curl -s -X POST` examples in CONTAINERS.md (escaped the acceptance grep, which only matched `curl -X POST`); P02's release.yml still `jq`-read the deleted `version.json`, which under `shell: bash` (`-eo pipefail`) would hard-fail every release; build.ps1 docstring described removed timestamp machinery. | Patched all three in the working tree (uncommitted): added `x-koi-token` headers, switched release description to a CHANGELOG.md awk extraction, rewrote the build.ps1 docstring. |
| 2026-06-13 | P04 | Prompt's "Keep: `allow_remote` (loopback vs 0.0.0.0 listen — preserve its security semantics)" describes a **listen-side** semantic that contradicts the code: `allow_remote`/CLI `--backend-remote` actually gates whether the **backend** may be non-loopback (`safety.rs`), and the listener always binds `0.0.0.0`. | Preserved the existing **backend-loopback-gate** semantic and the `0.0.0.0` listen (a TLS reverse proxy is meant to be LAN-reachable; TLS is its security boundary — distinct from P03's loopback-default control-plane HTTP). Honors "preserve its security semantics" + charter's no-silent-behavior-change rule. |
| 2026-06-13 | P04 | certmesh writes member certs to `certs/<hostname>/` (`koi-certmesh/certfiles.rs`) but the proxy read `certs/<entry.name>/` (`listener.rs`), so certmesh certs were never found unless entry name == hostname; and `load_tls_config` had **no self-signed fallback** despite `proxy.md` claiming one (so a proxy on a fresh machine failed to start at all). | Rebuild resolves certs in order: `certs/<entry.name>/` → `certs/<hostname>/` → generated self-signed (rcgen). Makes the common single-host certmesh case work and gives true zero-config TLS. Full certmesh↔proxy cert-naming reconciliation deferred to a certmesh prompt. |
| 2026-06-13 | P04 | **Acceptance criterion 7 (crate smaller / well under 954 src lines excl tests) not met:** production src grew ~871 → ~1117. The forwarding path collapsed (`copy_bidirectional` replaced the 85-line `forwarder.rs`; reqwest/hyper/http-body-util/futures-util deps dropped), but the rebuild added what the broken original lacked — working cert resolution, self-signed fallback, hot-reload via `ResolvesServerCert`, real listener-state plumbing (~34 broken cert lines → ~470 working listener+tls lines). | Kept correctness (criteria 2/3) + the charter's non-negotiable DX (#2 zero-config first success ⇒ self-signed fallback) over the size target. Removing self-signed changes user-facing behaviour, regresses DX, and still would not reach <871 — so per the charter it was **surfaced**, not silently applied. **Resolution (2026-06-13): user accepted the honest size as the correct behaviour** — keep DX + correctness, no further trimming or feature removal. |
| 2026-06-13 | P04 | Pre-existing `clippy::too_many_arguments` on `crates/koi/src/adapters/http.rs::start` (8 args, P03 code, untouched by P04) failed `cargo clippy -- -D warnings` under the machine's clippy **0.1.95** (repo MSRV is 1.92); P03 was verified under an older clippy. | Added a one-line behaviour-neutral `#[allow(clippy::too_many_arguments)]` on the wiring entrypoint to keep the shared hard gate green. No other pre-existing lints surfaced behind it. |
| 2026-06-13 | P04 | At branch creation `dev` carried 4 pre-existing **uncommitted** files unrelated to P04 (`.agentic/CONTEXT.md`, `.github/workflows/ci.yml`, untracked `docs/SURFACES.md`, `scripts/lint-surfaces.sh`). | They were cleaned from the working tree externally mid-session; the final P04 tree contains only proxy-rebuild changes. The `.agentic/CONTEXT.md` edit in this branch is P04's own (koi-proxy dependency line), not the earlier surfaces work. |

## Process notes

- **Plan files:** none of P01–P03's first passes left the CHARTER-mandated
  `plans/<id>-plan.md`. Enforced from P03 onward.
- **Binary crate package name** is `koi-net` (not `koi`); `cargo` invocations that
  target the binary use `-p koi-net`.
- **Verify** with `cargo check --workspace`, `cargo test`,
  `cargo clippy -- -D warnings`, `cargo fmt --check` before marking a row `done`.
