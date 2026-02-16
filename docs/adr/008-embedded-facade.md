# ADR-008: Embedded Facade (`koi-embedded`)

**Status:** Accepted  
**Date:** 2025-12-01  

## Context

Integrating Koi capabilities into a Rust application required running the daemon out-of-process and communicating over HTTP or IPC, adding operational complexity for use cases where in-process embedding is natural. Integration testing relied on external PowerShell/Shell scripts that started the daemon, poked its API, and asserted responses — these were slow, platform-fragile, and couldn't test domain behaviors with deterministic event assertions. Domain logic was already properly separated into bounded-context crates, making an orchestration facade viable.

## Decision

A new `koi-embedded` crate provides a `Builder → KoiConfig → KoiHandle` API that orchestrates domain crates in-process. The facade contains zero domain logic — it composes existing crates and exposes async capability sub-handles (`handle.mdns()`, `handle.dns()`, etc.). An event bus delivers typed `KoiEvent` variants by subscribing to each domain's broadcast channel — zero-latency, no file-polling.

```rust
let handle = Koi::builder()
    .with_mdns(true)
    .with_dns_zone("lab")
    .build()
    .await?;
```

Feature flags allow disabling individual capabilities. `Builder::new().build()` works with sane defaults.

## Consequences

- Most integration script coverage was replaced by in-process embedded tests with deterministic event-driven assertions, running in CI on all platforms.
- External scripts were retained solely for OS-level service lifecycle validation (install/uninstall/SCM/systemd).
- Domain crates required small public hooks for event broadcast channels, lightly expanding their public API surface.
- Rust applications can embed full Koi capabilities without spawning a separate process or managing IPC.
