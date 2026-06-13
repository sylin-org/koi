# P06 — Presentation Layer Rebuild (koi-dashboard crate, XSS hardening, kernel restoration)

> Paste this entire file as the task for a fresh agent session in the Koi repo.
> Size: M · Prereqs: none · Read `docs/prompts/CHARTER.md` first.

## Mission

Three entangled problems, one move. (1) The dashboard and mDNS browser — 60KB of HTML
plus a 563-line browse cache — were moved into **koi-common**, turning the "shared
kernel" into a presentation host and dragging axum/async-stream/chrono/hostname into
every domain crate's transitive closure. (2) The mDNS browser page has **verified XSS
vectors from LAN-attacker-controlled data**: its `esc()` helper does not escape quotes
yet values are interpolated into double-quoted HTML attributes, and TXT `url=` values
are rendered as launch links with no scheme allowlist (`javascript:` passes). (3) The
always-on meta-browse worker browses every service type on the LAN whenever mDNS is
enabled — chatty multicast nobody opted into. Extract a `koi-dashboard` crate, fix the
injection class properly, and make the network-wide browsing lazy.

## Load context first

1. `docs/prompts/CHARTER.md` (architecture rule: koi-common is types-only)
2. `docs/assessment/findings/verification-2026-06.md` claim 9 (re-verify the exact
   lines), and `findings/reader-adapters-ux.md`
3. `crates/koi-common/src/dashboard.rs`, `browser.rs`, `assets/*.html`,
   `koi-common/Cargo.toml` (the dependency damage)
4. Consumers: `crates/koi/src/adapters/dashboard.rs`, `mdns_browser.rs`, `main.rs`
   wiring (~680–692 for the unconditional meta-browse), `koi-embedded/src/lib.rs` +
   `mdns_browse_adapter.rs` (the duplicated copies)

## Research phase

- Map exactly what koi-common exports for dashboard/browser and who imports it.
- Confirm which koi-common deps exist *only* for presentation (candidate removals:
  axum? async-stream? chrono? hostname? tokio-stream?) — check what the kernel types
  still need.
- For the XSS fix, decide between: (a) attribute-safe `esc()` that also escapes `"` and
  `'`, or (b) the structurally-safer rewrite — build rows via `document.createElement`
  + `textContent`/`dataset` and stop concatenating HTML for dynamic values. Prefer (b)
  for the tables/detail panes; it eliminates the bug *class*. Launch links get an
  explicit `http:`/`https:` scheme allowlist regardless.
- Find the duplicated event-forwarder and browse-adapter copies in koi-embedded that
  the new crate should absorb (they have already diverged — the embedded copy forwards
  runtime events, the daemon copy doesn't; unify on the superset).

## Target architecture (north star)

```
crates/koi-dashboard/          # new presentation crate
  src/lib.rs                   # routes(state) -> Router for / and /mdns-browser + /v1/dashboard/* + /v1/mdns/browser/*
  src/snapshot.rs              # SnapshotFn injection (keep the existing inversion — it's good)
  src/browser_cache.rs         # moved from koi-common, lazy-start
  src/event_forward.rs         # THE single forwarder (superset: includes runtime+udp arms)
  assets/dashboard.html
  assets/mdns-browser.html     # rebuilt rendering: DOM construction, scheme allowlist

deps: koi-dashboard → koi-common (types only), axum, tokio
consumers: koi (binary), koi-embedded         # both delete their local copies
koi-common: loses assets/, dashboard.rs, browser.rs and the presentation-only deps
```

Lazy meta-browse: the LAN-wide browse worker starts on the **first request** to a
browser/dashboard endpoint that needs it (or via an explicit opt-in flag), idles out
after N minutes without clients, and `koi status` shows whether it is active.
Zero-build-step single-file HTML stays — it fits the single-binary philosophy; do not
introduce a JS toolchain.

## Plan, then implement

Per charter. Sequence: create crate + move server modules → move assets → rebuild the
browser page's dynamic rendering (XSS fix) → unify the forwarder/adapters (delete both
divergent copies) → lazy meta-browse → strip koi-common deps → update
`.agentic/CONTEXT.md` + `docs/reference/architecture.md` (they currently misstate where
this code lives).

## Acceptance criteria

- [ ] `koi-common/Cargo.toml` no longer depends on presentation-only crates (list the
      removals in the commit message); no domain crate's `cargo tree` pulls them via
      koi-common.
- [ ] XSS closed: no dynamic value is string-concatenated into an HTML attribute; a
      service named `"><img src=x onerror=alert(1)>` and one named
      `" onmouseover="alert(1)` render inert (add a small JS-free integration test:
      serve the snapshot endpoint with a hostile name and assert the HTML response
      contains the escaped/inert form — or DOM-construction makes the assertion
      structural).
- [ ] Launch links: `javascript:`/`data:` TXT urls are dropped; only http/https render.
- [ ] One event forwarder exists, covering all domains incl. runtime/udp; koi-embedded's
      duplicates (`mdns_browse_adapter.rs`, inline forwarder) are deleted.
- [ ] Meta-browse is lazy/opt-in with idle stop; default daemon startup performs no
      LAN-wide browsing until a presentation surface asks.
- [ ] Dashboard and browser pages function as before (manual check) and
      `.agentic`/architecture docs state the new crate truthfully.
- [ ] Workspace builds: `cargo test && cargo clippy -- -D warnings` green.

## Verification

Workspace commands per charter; `cargo tree -p koi-dns | grep -E "axum|chrono"` shows
no presentation leakage; manual: `koi launch`, browse the two pages, register a
hostile-named service via the API and inspect the rendered row.

## Do NOT

- Add dashboard features (mutation controls, new panels) — KOI-0002's deferred phases
  stay frozen.
- Introduce a frontend build pipeline, framework, or bundler.
- Change dashboard/browser URL paths or the snapshot/SSE endpoint contracts.
