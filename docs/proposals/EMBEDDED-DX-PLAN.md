# Embedded DX Plan

Date: 2026-02-12
Owner: Maintainers
Status: Proposed

## Summary
Introduce an embedded facade crate that provides a premium DX for in-process use
without sacrificing SoC/DDD/SOLID boundaries. Keep external integration scripts
for service lifecycle validation (systemd/SCM/launchd). Add an embedded test
project that replaces most integration script coverage.

## Goals
- Premium DX: simple to use, easy to embed, event-driven by default.
- Clear SoC/DDD/SOLID boundaries: facade composes domain crates, no domain logic
  in the facade.
- Sane defaults with explicit overrides (paths, ports, capability toggles).
- Embedded tests replace most integration scripts; external scripts remain for
  installed service lifecycle coverage.

## Non-Goals
- Removing the existing HTTP/IPC adapters.
- Rewriting domain crates.
- Replacing OS-level service lifecycle tests.

## Architecture (SoC/DDD/SOLID)
- Bounded contexts remain: mdns, dns, health, certmesh, proxy.
- Domain logic stays in existing crates.
- New facade crate only orchestrates and exposes a clean API.
- Adapters (HTTP/IPC/CLI) stay in the binary crate.

## Deliverables
1) New crate: `koi-embedded`
   - `Builder`, `KoiConfig`, `KoiHandle`
   - Event bus with typed `KoiEvent`
   - Capability sub-handles (mdns/dns/health/certmesh/proxy)
   - Feature flags to disable capabilities

2) Embedded test project
   - In-process integration tests driven by the facade
   - Event-driven assertions (streams or channels)
   - Replaces most integration script coverage

3) Keep external scripts
   - `tests/integration.ps1` and `tests/integration.sh` remain for service
     lifecycle and external daemon validation

4) Documentation
   - `docs/embedded-quickstart.md`
   - Examples in `examples/`

## API Sketch

```rust
let koi = koi_embedded::Builder::new().build()?;
let handle = koi.start().await?;

let koi = koi_embedded::Builder::new()
    .data_dir(custom_path)
    .http(false)
    .mdns(true)
    .dns(|cfg| cfg.zone("lan").port(5353))
    .health(|cfg| cfg.interval_secs(30))
    .certmesh(|cfg| cfg.profile("just-me"))
    .events(|event| println!("koi event: {event:?}"))
    .build()?;

let handle = koi.start().await?;
handle.mdns().browse("_http._tcp").await?;
```

## Event Model
- `KoiEvent::MdnsFound(ServiceRecord)`
- `KoiEvent::MdnsRemoved(ServiceRecord)`
- `KoiEvent::MdnsResolved(ServiceRecord)`
- `KoiEvent::DnsUpdated { name, ips, source }`
- `KoiEvent::HealthChanged { name, status }`
- `KoiEvent::CertmeshMemberJoined { hostname, fingerprint }`
- `KoiEvent::ProxyUpdated { entry }`

The facade exposes:
- `handle.events()` -> `impl Stream<Item = KoiEvent>`
- `handle.subscribe()` -> `Receiver<KoiEvent>`
- `builder.events(handler)` -> push-style hook

## Configuration
- `Builder::new().build()` must be valid with sane defaults.
- Explicit config struct with defaults and overrides
- No hidden env var dependencies unless explicitly requested
- Paths are configurable: data, certs, state, logs
- Ports are configurable: http, dns

## Test Strategy
### Embedded test project (new)
- Runs in-process with `koi-embedded`
- Covers domain behaviors (mdns/dns/health/certmesh/proxy)
- Uses events for deterministic assertions
- Runs in CI on all platforms

### External service scripts (existing)
- Keep `tests/integration.ps1` and `tests/integration.sh`
- Focus on service lifecycle and external daemon behavior

## Phases and Milestones

### Phase 1: Facade skeleton (1-2 weeks)
- Create `koi-embedded` crate
- Add `Builder`, `KoiConfig`, `KoiHandle`
- Wire mdns + dns minimal handles
- Add event bus skeleton

### Phase 2: Event bus + capability handles (1-2 weeks)
- Full `KoiEvent` model
- mdns/dns/health/certmesh/proxy handles
- Event fan-out from domain signals

### Phase 3: Embedded tests (1 week)
- New in-process test project
- Replace most integration script coverage

### Phase 4: Docs + examples (2-4 days)
- Quickstart guide
- Example binaries

## Acceptance Criteria
- Embedded facade provides single-line Builder usage
- Event bus delivers domain events with typed payloads
- Capability handles expose consistent async API
- Embedded tests cover mdns/dns/health/certmesh/proxy flows
- External scripts remain for service lifecycle testing

## Risks
- Event fan-out mapping may need additional domain signals
- Some domain crates may require small public hooks for events
- Certmesh in-process tests may need isolated data directories

## Open Questions
- Should embedded facade expose HTTP/IPC adapters by default? (default: no)
- Should facade provide sync wrappers for common actions? (default: async only)
- Minimum Rust version for the embedded crate? (default: workspace MSRV)
