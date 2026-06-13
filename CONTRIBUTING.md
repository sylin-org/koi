# Contributing to Koi

Contributions welcome. Please open an issue to discuss before submitting large
changes.

Koi is consolidating toward *less but more meaningful parts* — see the
[assessment & roadmap](docs/assessment/README.md). Contributions that delete,
simplify, or make documentation true are as valued as features; check the
[work-order prompts](docs/prompts/README.md) for the current plan before starting
something big.

---

## Setup

```bash
git clone https://github.com/sylin-org/koi.git
cd koi
cargo build
cargo test
```

## Verify before submitting

```bash
cargo check
cargo test
cargo clippy -- -D warnings
cargo fmt --check
```

All four must pass; CI enforces them.

---

## The one meta-rule: docs tell the truth

A change that makes any document false is incomplete. If you change behavior,
update the relevant guide, reference page, and the command catalog in the same PR.
If you find a doc that already lies about the code, fixing it is a welcome PR on
its own. The [security model](docs/reference/security-model.md) is the canonical
source for bind/auth/CORS claims — never restate those facts elsewhere, link them.

---

## Code style

**Clarity over cleverness.** A 5-line `match` beats a chained
`.map().and_then().unwrap_or_else()`.

### Naming

- Name things for what they **are**, not what they do: `Registry`, not
  `RegistrationManager`.
- Test names are descriptive sentences:
  `browse_response_omits_status_when_fully_resolved`, not `test_browse`.
- Constants: `SCREAMING_SNAKE_CASE`, co-located with the module that uses them,
  defined exactly once. No centralized constants file.

### Size limits (for code you write or touch)

- **Files ≤ ~800 lines, functions ≤ ~50 lines.** Several legacy files exceed this —
  they are being shrunk per the roadmap, not imitated. New code complies; when you
  touch an oversized file, leave it smaller than you found it.

### Visibility

- Use `pub(crate)` to enforce layer boundaries; domain internals are never `pub`.
- No `impl From<X> for Y` unless the conversion is lossless, obvious, and used in
  more than one place.

### Avoid

- `unwrap()` / `expect()` in production code — use `?`, `unwrap_or_else`, or
  graceful fallbacks. (`unreachable!()` in evolution-reachable match arms too.)
- Silent error swallowing — errors propagate or are logged with context.
- `eprintln!` for diagnostics — use `tracing::*`.
- Stringly-typed interfaces in core — validate at the boundary, carry newtypes.
- Traits with one implementor; `Builder` for a three-field struct; generics with
  one consumer. Concrete code first — abstraction when the second consumer arrives.
- `async-trait` where `impl Future`/RPITIT works; it is acceptable only where
  object safety genuinely requires it (e.g. pluggable backends).

### Dependencies

Be miserly — every dependency is audit surface and compile cost.

- **No `anyhow` in library/domain crates** — `thiserror` with typed enums;
  `anyhow` only in the binary crate.
- **No `tower` middleware stacks, ORMs, or gRPC.** Open an issue first if you
  think you need one.
- All versions pinned in the root `Cargo.toml` `[workspace.dependencies]`.
- Prefer a maintained crate over hand-rolling protocol/encoding/crypto plumbing
  (base32, durations, JWS, …) — and prefer `std` over a crate for trivia.

---

## Testing strategy

**Test what is risky, not what is easy.** A broadcast channel does not need your
test; the lease state machine, the wire contract, and the TLS path do.

- **Core tests** (most tests live here): domain logic directly — no HTTP, no
  sockets. Deterministic time injection over sleeps.
- **Protocol tests**: serde contracts. Absent optional fields produce clean JSON
  (no `null`); flattened structs stay flat; round-trips round-trip.
- **Adapter tests**: thin — transport reaches core and returns a response; don't
  re-test domain logic through adapters.
- **Behavioral minimum**: every event a domain emits has at least one test that
  fails if the emission breaks; every error variant has its ErrorCode mapping
  tested.

Dev REPL for quick manual checks:

```bash
echo '{"browse": "_http._tcp"}' | cargo run
```

---

## Architecture rules

Enforced in review. Full picture: [Architecture](docs/reference/architecture.md)
and `.agentic/CONTEXT.md`.

1. **Domain crates never import each other.** Cross-domain access goes through the
   integration traits in `koi-common`; wiring lives in the composition layer.
2. **`koi-common` is a types-only kernel** — no transport, no presentation, no IO
   machinery.
3. **Adapters contain zero domain logic.** Deserialize → call core → serialize.
4. **One canonical model per concept.** No per-adapter DTOs.
5. **`mdns-sd` is imported in exactly one file** (`crates/koi-mdns/src/daemon.rs`).
6. **No `#[cfg(feature = "...")]` for capabilities** — runtime tunables only.
7. **The DX is the product.** CLI changes preserve the moniker shape, the
   discoverability triad (catalog / domain examples / `command?`), `--json`
   parity, and terminal-degradation behavior — see
   [docs/prompts/CHARTER.md](docs/prompts/CHARTER.md) for the full DX charter.

---

## AI-assisted contributions

This project is developed agentic-first and keeps a tool-agnostic AI context in
`.agentic/` (Claude, Cursor, Copilot, etc. bootstrap from it). If you work with an
AI agent:

- Have it read [docs/prompts/CHARTER.md](docs/prompts/CHARTER.md) — the DX charter
  and session protocol (research → written plan → implement → verify).
- For roadmap work, start from a [work-order prompt](docs/prompts/README.md)
  rather than improvising scope.
- Treat code as ground truth over docs; agents must re-verify any doc claim they
  rely on, and fix the doc when it lies.
- The same review bar applies: plans before diffs, tests for risky paths, truthful
  docs in the same PR.

---

## Logging levels

| Level | Use for |
| ----- | ------- |
| `error` | Unrecoverable failures |
| `warn` | Worked around, but operator should know |
| `info` | Lifecycle events only (start, stop, capability ready) |
| `debug` | Request flow, normalization, mode detection |
| `trace` | Packet-level detail |

**Default `info` should be silent during normal operation.** If it's noisy, levels
are wrong.

---

## Documentation voices

| Location | Voice | Purpose |
| -------- | ----- | ------- |
| `docs/guides/` | Wise mentor | Walk beside the reader, anticipate confusion |
| `docs/reference/` | Precise technician | Exact shapes, validated against code |
| `docs/adr/` | Honest historian | Context, decision, consequences — including reversals |

When changing behavior, update the relevant guide and reference doc. New
capability or significant design change → new ADR. ADRs written after the fact
must say so.

---

## License

By contributing, you agree that your contributions will be dual-licensed under
Apache-2.0 and MIT, consistent with the project license.
