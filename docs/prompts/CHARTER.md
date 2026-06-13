# Koi DX Charter — read before any session in this stash

You are working on **Koi**, an open-source Rust local-network toolkit: one cross-platform
binary that makes LAN services *discoverable* (mDNS), *named* (local DNS), *trusted*
(private certificate mesh + OS truststore install), and *reachable* (TLS endpoint),
exposed to any language via HTTP + CLI, label-driven for containers. Audience: homelabs,
developers, small networks. It is a toolset, not a commercial product. The repo's
architectural ground truth is `.agentic/CONTEXT.md`; the strategic ground truth is
`docs/assessment/2026-06-maturity-assessment.md`.

The project is **pre-1.0 greenfield**: breaking changes are welcome, migration paths are
not required, and compatibility shims are unwanted. Prefer rebuilding a part properly
over patching it. What is *not* negotiable is the DX below — it is the product.

---

## The Koi feel — DX principles every change must preserve

1. **Domain monikers, verb-first.** CLI is `koi <domain> <verb> [args]`
   (`koi mdns discover`, `koi dns add grafana 10.0.0.42`). New surface follows the
   pattern; no top-level verb sprawl.
2. **Zero-config first success.** Every capability must have a command that does
   something useful with no setup (`koi mdns discover` works in 30 seconds on a fresh
   machine). Configuration is for the second session, never the first.
3. **Discoverability is built in.** Bare `koi` prints live status + a command catalog;
   bare `koi <domain>` prints curated examples; `koi <command>?` opens a detail page.
   Anything you add must appear in all three, accurately.
4. **Human output and `--json` are peers.** Every command has a clean human rendering
   (columns, color with graceful NO_COLOR/dumb-terminal/non-TTY degradation) and a
   stable `--json` shape. Scripts and humans are both first-class.
5. **The secure path is the easy path.** Security must not require ceremony: loopback +
   token by default, opt-in exposure with loud warnings, secrets never echoed or in
   argv, destructive ops gated by typed confirmation (`Type RESET to confirm`).
6. **Verb-oriented JSON wire shapes.** Happy paths are externally tagged
   (`{"found": {...}}`, `{"registered": {...}}`); errors are flat
   (`{"error": "not_found", "message": "..."}`); no envelope noise on the happy path.
7. **Leases over liveness guesses.** Anything registered has a lifecycle:
   session/heartbeat/permanent, ALIVE → DRAINING → expired, with goodbye semantics.
   "No stale services" is a product promise.
8. **Runtime tunables, not feature flags.** One binary; capabilities toggle with
   `--no-<cap>` / `KOI_NO_<CAP>=1` and disabled capabilities answer 503 with a helpful
   message naming the flag. Never `#[cfg(feature)]` for domain capabilities.
9. **API-first.** Every capability is reachable over HTTP with utoipa-annotated
   handlers; `/docs` (Scalar) and `/openapi.json` must stay complete and truthful.
10. **Collaboration doctrine.** Koi is the substrate under tools users already run:
    export in *their* formats (ACME, http_sd, RFC 2136, split-DNS), consume what users
    already wrote (existing labels, existing roots), and give every capability an exit
    (easy to stop using ⇒ easy to start using). Never require rip-and-replace.

## Architecture rules (enforced)

- **Workspace of domain crates.** Each domain exposes commands/state/events behind an
  opaque facade (`XxxCore`); internal state is never `pub`; HTTP handlers delegate to
  domain methods. Domain crates depend on `koi-common` only — **never on each other**;
  cross-domain wiring lives in the composition layer via the integration traits in
  `koi-common::integration`.
- **`koi-common` is a types-only kernel** (types, errors, pipeline, id, paths). If you
  are adding axum/HTML/IO machinery to it, you are in the wrong crate.
- **mdns-sd is isolated** behind `MdnsDaemon` in `crates/koi-mdns/src/daemon.rs` — no
  mdns-sd types may cross the crate boundary.
- **Errors:** `thiserror` enums per domain → `koi_common::error::ErrorCode` → HTTP
  status. Every new variant gets a mapping and a test. No `unwrap`/`expect`/
  `unreachable!` in production paths; no silent error swallowing.
- **Constants:** SCREAMING_SNAKE_CASE, co-located with their module, defined exactly
  once. Check `.agentic/reference/utilities.md` before creating one.
- **Files ≤ ~800 lines, functions ≤ ~50 lines** for *new* code. If a rebuild leaves a
  file larger, split it.

## How to work (session protocol)

1. **Research first.** Read the files this prompt names, plus whatever they reference.
   Verify every claim you rely on against current code — the repo has known doc drift;
   code is ground truth. Use web search where the prompt says external facts matter.
2. **Write a plan before coding** to `docs/prompts/plans/<prompt-id>-plan.md`: goal,
   file-by-file change list, target shapes, test list, risks. Re-read the prompt's
   acceptance criteria and check your plan covers each. Then implement.
3. **Verify continuously.** After each coherent unit: `cargo check`. Before claiming
   done: `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`. New behavior
   needs tests that fail without your change. Test what is *risky*, not what is easy.
4. **Keep docs true.** Any user-visible change updates: the relevant `docs/guides/*`,
   `docs/reference/*`, the command catalog (`surface`), and `.agentic/` if boundaries
   moved. A change that makes docs false is incomplete.
5. **Commits:** conventional format (`feat:`, `fix:`, `refactor:`, `docs:`), one
   logical change per commit. Do not push or tag unless the prompt says so.
6. **If blocked** (missing context, contradictory ground truth, scope explosion): stop,
   write what you found and the decision needed into the plan file, and surface it —
   do not guess through ambiguity that changes user-facing behavior.

## Definition of done

A prompt's work is done when: all acceptance criteria check; the verification commands
pass on your machine; new risk-bearing behavior has a test; docs and the command catalog
tell the truth; and `git status` shows only intended changes.
