---
type: REF
domain: embedded
title: "Embed Koi in a Rust app — capability card"
audience: [operators, developers, ai-agents]
status: current
last_updated: 2026-09-04
koi_version: v1.0.0-dev.0
validation:
  date_last_tested: 2026-09-04
  status: verified
  scope: "integration (koi-embedded whole_story.rs two-daemon join/renew/revoke over real HTTP+mTLS; http_ephemeral.rs http_port(0)→bound_http_port + announce_http-without-token fails closed) + unit (testkit open/secured posture gate; adaptive serve occupied/ephemeral/cancel/rollback + live posture transition; seal/open round trip)"
---

# Embed Koi in a Rust app — capability card

> One-screen map of running Koi **in-process as a library** — no daemon, no IPC, no binary dependency. Full flow: [embedded.md](../../guides/embedded.md) · trust primitives: [trust-protocol.md](../trust-protocol.md) · API surface: [http-api.md](../http-api.md).

**What it does** — `koi-embedded` runs every Koi capability inside your Rust process through the **same composition root** (`koi_compose::build_cores`) the daemon and the Windows service use, so the in-process graph is identical — no separate embedded server, no `/v1/status` drift. You configure with a fluent `Builder`, call `KoiEmbedded::start().await`, and get a `KoiHandle` that hands out **typed per-domain handles** (`mdns()`, `dns()`, `certmesh()`, …) plus a broadcast `KoiEvent` stream. Capabilities are **opt-in by selection** (unlike the daemon's enabled-by-default model): you turn on exactly what the host app needs.

## The one canonical pattern

Build, start, take handles, subscribe to events, shut down. The handle is the single object you keep.

```rust
use koi_embedded::{Builder, ServiceMode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let koi = Builder::new()
        .service_mode(ServiceMode::EmbeddedOnly) // run in-process (vs Auto/ClientOnly)
        .mdns(true)
        .dns_enabled(true)
        .certmesh(true)
        .build()?;                  // validates config (fails closed — see escape hatch)
    let handle = koi.start().await?; // builds cores + bridges + background tasks

    // Typed per-domain handles — each Result errs if its capability is disabled:
    handle.mdns()?.register(payload)?;
    handle.dns()?.add_entry(entry)?;
    let posture = handle.certmesh()?.posture().await?;

    // One broadcast stream of everything that happens:
    let mut events = handle.subscribe()?; // broadcast::Receiver<KoiEvent>
    // ... while let Ok(ev) = events.recv().await { ... }

    handle.shutdown().await?; // ordered cancel → drain → join → withdraw-announce
    Ok(())
}
```

## Commands & flags you'll use

| Builder / handle call | What it does |
|---|---|
| `Builder::new().<cap>(true)…build()?` | Select capabilities: `mdns`, `dns_enabled`, `health`, `certmesh`, `proxy`, `udp`, `runtime_auto`. |
| `.http(true).http_port(0)` → `handle.bound_http_port()` | Mount the embedded HTTP adapter; `0` = OS-assigned free port, read the real one back (no probe race). |
| `.announce_http(true).http_token("…")` | Expose the adapter on `0.0.0.0` for LAN peers. **Token required** (see escape hatch). |
| `handle.mdns()/dns()/health()/certmesh()/proxy()/udp()/runtime()` | Typed handle; `Err(DisabledCapability)` if the capability was not selected. |
| `handle.vault()` | Open the encrypted KV vault (needs `.data_dir(..)`). |
| `handle.subscribe()` / `handle.events()` | `Result` containing a broadcast `KoiEvent` receiver / `BroadcastStream` (incl. coalescing `CertmeshStatusChanged`). Remote mode returns `RemoteUnsupported` because no daemon-wide event transport exists. |
| `handle.participate(router, addr, "_svc._tcp", cancel).await` | One-call trusted service: best-effort identity, real listener bind, acknowledged posture-stamped publication on the actual port, then one owned generation. Returns the bound address. |
| `handle.serve(router, addr, cancel).await` | Readiness-fenced same-port dial without discovery. Returns the real address (including an OS-selected port); bind failure is the call's error. |

## The escape hatch

`build()` and `start()` **fail closed, never silently**. `announce_http(true)` without `http_token(..)` returns `KoiError::InsecureConfig` at `start()` — *before any socket binds* — rather than serving unauthenticated mutations to the whole LAN; loopback-only (the default) needs no token. Each typed handle returns `KoiError::DisabledCapability("…")` for a capability you didn't select and `KoiError::RemoteUnsupported` for an embedded-only operation under `ServiceMode::ClientOnly`/`Auto`. Remote operations backed by daemon endpoints return their typed transport/API/decode error; they never substitute `None`, an empty collection, `false`, a default status, or a no-op success. For tests, **`koi_embedded::testkit`** spins a real node in a known posture with **no Docker**: `testkit::open()` (no identity) and `testkit::secured()` (a CA is created → real leaf), each with an auto-wiped data dir — the "same code, both postures" acceptance gate (ADR-020 §2).

## The proof it works

Integration: `crates/koi-embedded/tests/whole_story.rs` stands up **two embedded daemons** (CA + member) and drives create → invite → join over real HTTP → key-rotating mTLS renewal → revoke → 403 boundary — proving the Builder→start→typed-handle path on real sockets. `crates/koi-embedded/tests/http_ephemeral.rs` guards `http_port(0)`→`bound_http_port()` (distinct ports, no guard) and that `announce_http` without a token **fails closed** at `start()`. Unit tests additionally exercise a real occupied TCP port, port-0 listener plus exact advertised port, caller cancellation, initial-publication rollback, and posture-adaptive traffic. All run under a plain `cargo test --locked` (pure Rust, no child processes) on the ubuntu/windows/macos CI matrix.
