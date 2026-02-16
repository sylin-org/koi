# Contributing to Koi

Contributions welcome. Please open an issue to discuss before submitting large changes.

---

## Setup

```bash
git clone https://github.com/sylin-org/koi.git
cd koi
cargo build
cargo test
```

Build scripts are also available: `build.bat` (Windows) and `build.ps1` (PowerShell).

## Verify before submitting

```bash
cargo check
cargo test
cargo clippy -- -D warnings
```

All three must pass. CI enforces clippy with `-D warnings`.

---

## Code style

**Clarity over cleverness.** A 5-line `match` beats a chained `.map().and_then().unwrap_or_else()`.

### Naming

- Name things for what they **are**, not what they do: `Registry`, not `RegistrationManager`.
- Test names are descriptive sentences: `browse_response_omits_status_when_fully_resolved`, not `test_browse`.
- Constants: `SCREAMING_SNAKE_CASE`, co-located with the module that uses them. No centralized constants file.

### Size limits

- **No file over 300 lines.** Split into focused modules.
- **No function over 30 lines.** Extract helpers.

### Visibility

- Use `pub(crate)` to enforce layer boundaries.
- Internal types visible to sibling modules, not to adapters.
- No `impl From<X> for Y` unless the conversion is lossless, obvious, and used in more than one place.

### Avoid

- `unwrap()` and `expect()` in production code - use `?`, `unwrap_or_else`, or graceful fallbacks.
- `unreachable!()` in match arms reachable through API evolution - use `anyhow::bail!`.
- `async-trait` - use `impl Future` or RPITIT (Rust 1.75+).
- Stringly-typed interfaces in core - validate at the boundary, carry newtypes internally.
- Traits with one implementor. `Builder` for a three-field struct.
- `eprintln!` for diagnostics - use `tracing::*`.

### Dependencies

Be miserly. Every dependency is audit surface and compile cost.

- **No `anyhow` in library/domain crates** - `thiserror` with typed error enums. `anyhow` only in the binary crate's `main.rs`.
- **No `tower` middleware, ORMs, or gRPC.** If you think you need one, open an issue first.
- All dependency versions are pinned in the root `Cargo.toml` under `[workspace.dependencies]`. Crates reference them with `.workspace = true`.

---

## Testing strategy

### Core tests (most tests live here)

Test domain logic directly - no HTTP, no sockets, no serialization.

```rust
#[test]
fn registry_removes_expired_leases_on_tick() { ... }
```

### Protocol tests

Verify serde contracts. Absent optional fields must produce clean JSON (no `null`). `#[serde(flatten)]` must produce flat output. Top-level verb keys must round-trip.

### Adapter tests

Thin integration only. Verify transport plumbing reaches core and returns a response. Don't re-test domain logic through adapters.

### Manual testing

The CLI adapter doubles as a dev REPL - pipe JSON through `cargo run` for rapid manual testing:

```bash
echo '{"browse": "_http._tcp"}' | cargo run
```

---

## Architecture rules

These are enforced in review. See [Architecture](docs/reference/architecture.md) for the full picture.

1. **Domain crates never import each other.** Cross-domain wiring happens in the binary crate only.
2. **Adapters contain zero domain logic.** Deserialize → call core → serialize. That's it.
3. **Core never imports transport types.** No `axum::` in domain crates.
4. **One canonical model per concept** (`ServiceRecord`, `Request`, `Response`). No per-adapter DTOs.
5. **`mdns-sd` imported in exactly one file** (`crates/koi-mdns/src/daemon.rs`).
6. **No `#[cfg(feature = "...")]` for capabilities.** Capabilities are runtime-toggled, not compile-time.

---

## Logging levels

| Level   | Use for                                               |
| ------- | ----------------------------------------------------- |
| `error` | Unrecoverable failures                                |
| `warn`  | Worked around, but operator should know               |
| `info`  | Lifecycle events only (start, stop, capability ready) |
| `debug` | Request flow, normalization, mode detection           |
| `trace` | Packet-level detail                                   |

**Default `info` should be silent during normal operation.** If it's noisy, levels are wrong.

---

## Documentation

Documentation lives in three places with three voices:

| Location          | Voice              | Purpose                                      |
| ----------------- | ------------------ | -------------------------------------------- |
| `docs/guides/`    | Wise mentor        | Walk beside the reader, anticipate confusion |
| `docs/reference/` | Precise technician | Exact shapes, validated against code         |
| `docs/adr/`       | Honest historian   | Context, decision, consequences              |

When changing behavior, update the relevant guide and reference doc. If adding a new capability, add an ADR explaining the design decision.

---

## License

By contributing, you agree that your contributions will be dual-licensed under Apache-2.0 and MIT, consistent with the project license.
