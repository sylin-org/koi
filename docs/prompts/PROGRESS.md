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
| P04 | pending | | | | Proxy rebuild — TLS passthrough replacing the broken HTTP forwarder. |
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

## Process notes

- **Plan files:** none of P01–P03's first passes left the CHARTER-mandated
  `plans/<id>-plan.md`. Enforced from P03 onward.
- **Binary crate package name** is `koi-net` (not `koi`); `cargo` invocations that
  target the binary use `-p koi-net`.
- **Verify** with `cargo check --workspace`, `cargo test`,
  `cargo clippy -- -D warnings`, `cargo fmt --check` before marking a row `done`.
