# KOI-0002: Koi Dashboard & mDNS Browser

> **Status:** Proposal  
> **Authors:** —  
> **Date:** 2026-02-25

---

## 1. Motivation

Koi exposes a rich HTTP API across six domain capabilities (mDNS, Certmesh, DNS, Health, Proxy, UDP), but the only visibility into system state is via CLI commands or direct API calls. There is no unified, at-a-glance view of what's running, what's healthy, and what's on the network.

Meanwhile, mDNS is the cornerstone service — it handles service discovery across the LAN — but users have no way to *browse* the network interactively. The `koi mdns discover` CLI command streams JSON and closes on idle; there's no persistent, visual network map.

These are **two distinct concerns:**

1. **Dashboard** — system-level operational overview: identity, capability status, health, DNS, certmesh, proxy/UDP summaries, activity feed
2. **mDNS Browser** — a domain-specific deep-dive tool: live network map with filtering, sorting, TXT record inspection, service type analysis

They share a visual language but have different data lifecycles, different audiences, different update cadences, and different reasons to change. Splitting them respects SoC and lets each evolve independently.

---

## 2. Design Philosophy

### 2.1 Visual Language: "Lantern/Vellum"

Shared design system borrowed from Zen Garden's Ollama orchestrator. Both pages use identical tokens:

| Token | Value | Purpose |
|-------|-------|---------|
| `--bg-base` | `#f4f2ee` / `#1a1a1a` (dark) | Warm parchment/ink |
| `--accent-sage` | `#84a59d` | Healthy / enabled / active |
| `--accent-clay` | `#d4a373` | Warning / draining / degraded |
| `--accent-hopeful` | `#c4b060` | In-progress / pending |
| `--accent-red` | `#c45050` | Error / down / expired |
| `--vellum-white` | `rgba(255,255,255,0.45)` | Glassmorphic card backgrounds |
| `--glass-blur` | `blur(14px)` | Backdrop filter for cards |

Typography: system sans-serif for prose, monospace (IBM Plex Mono/Cascadia Code) for data. Section titles are tiny, uppercase, wide-spaced monospace labels. Subtle SVG grain texture overlay for tactile warmth.

Full `prefers-color-scheme: dark` support via CSS custom property overrides.

The CSS tokens are **duplicated in each HTML file** (not extracted into a shared stylesheet). Each SPA is fully self-contained. This matches the Ollama precedent and removes any inter-file coupling.

### 2.2 Interaction Model

Both pages follow the **"poll-for-truth, SSE-for-feedback"** architecture proven in the Ollama orchestrator. Each page has its own poll and SSE endpoints.

| Concern | Poll Endpoint | SSE Endpoint | Poll Interval |
|---------|---------------|--------------|---------------|
| Dashboard | `GET /v1/dashboard/snapshot` | `GET /v1/dashboard/events` | 3s |
| mDNS Browser | `GET /v1/mdns/browser/snapshot` | `GET /v1/mdns/browser/events` | 5s |

The poll cycle is the single source of truth for rendering. SSE provides instant feedback for the activity log (dashboard) and real-time service discovery (browser). Actions go through existing domain API endpoints.

---

## 3. Architecture

### 3.1 Two Adapters, One Boundary Model

Neither the dashboard nor the browser gets its own domain crate. Both are **presentation adapters** — they consume read-only snapshots from existing domain facades and own zero domain logic.

```
┌────────────────────────────────────────────────────────────────────────────┐
│                       crates/koi/src/adapters/                            │
│                                                                           │
│  http.rs          dashboard.rs (NEW)       mdns_browser.rs (NEW)         │
│  (existing)       System overview          mDNS network explorer          │
│     │                  │                        │                         │
│     │     ┌────────────┤           ┌────────────┤                         │
│     │     │            │           │            │                         │
│     │     ▼            ▼           ▼            ▼                         │
│     │   GET /        GET /v1/    GET /mdns-    GET /v1/mdns/              │
│     │   (HTML)       dashboard/* browser(HTML) browser/*                  │
│     │                                                                     │
│     │            pipe.rs     cli.rs     dispatch.rs                       │
│     │                                                                     │
│     └──────────── All use AppState (Arc<DomainCore>) ────────────────────│
└────────────────────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────────┐
│              Domain Cores (read-only access)                  │
│                                                               │
│  MdnsCore    CertmeshCore   DnsRuntime                       │
│  HealthCore  ProxyRuntime   UdpRuntime                       │
└──────────────────────────────────────────────────────────────┘
```

**Boundary rules preserved:**

- Both modules live in the binary crate (`crates/koi/src/adapters/`) — they're adapters
- All data comes from existing `Capability::status()`, domain query methods, and broadcast channels
- Domain crates remain unmodified — no dashboard or browser awareness inside them
- Cross-domain aggregation (dashboard snapshot) lives in the binary crate
- mDNS-specific aggregation (browser cache + SSE) is isolated in its own adapter module

### 3.2 Why Two Modules, Not One

| Factor | Dashboard | mDNS Browser |
|--------|-----------|-------------|
| **Data scope** | All 6 capabilities, cross-domain | mDNS-only, single-domain deep-dive |
| **Update cadence** | 3s poll, domain events feed activity log | 5s poll, mDNS events are primary content |
| **Background worker** | None (reads snapshots on-demand) | Meta-browse worker + service cache |
| **State** | Stateless — assembles snapshot per request | Stateful — maintains `BrowserCache` in memory |
| **Reason to change** | New capability added, status shape changes | mDNS protocol evolves, new filter/sort features |
| **HTML size** | ~800–1000 lines | ~1000–1200 lines |
| **Audience** | Ops: "is my system healthy?" | Dev/Net: "what's on my network?" |

Splitting means the browser's background worker, cache, and SSE stream don't pollute the dashboard module. The dashboard stays a thin, stateless snapshot assembler. Each HTML file stays under 1200 lines — manageable without a build toolchain.

### 3.3 File Layout

```
crates/koi/
├── src/
│   └── adapters/
│       ├── mod.rs               # Existing — re-exports new modules
│       ├── http.rs              # Existing — gains route mounting for both
│       ├── dashboard.rs         # NEW — system overview: snapshot, SSE, HTML
│       ├── mdns_browser.rs      # NEW — mDNS browser: cache, snapshot, SSE, HTML
│       └── ...
├── assets/
│   ├── dashboard.html           # NEW — system overview SPA
│   └── mdns-browser.html        # NEW — mDNS browser SPA
```

For **embedded mode**:

```
crates/koi-embedded/
├── src/
│   ├── http.rs                  # Gains optional dashboard + browser mounting
│   └── ...
```

### 3.4 Cross-Navigation

The two pages link to each other via a lightweight nav header present in both SPAs:

```
┌─────────────────────────────────────────────────────────────┐
│  KOI   Dashboard ·  Browser  ·  API Docs                    │
└─────────────────────────────────────────────────────────────┘
```

Three links: `GET /` (dashboard), `GET /mdns-browser` (mDNS browser), `GET /docs` (Scalar API docs). The current page's link is highlighted. The nav is a 4-line HTML bar — duplicated in each SPA (self-contained files, no shared templates).

**Conditional Browser link:** On the dashboard, the "Browser" nav link is only rendered when the snapshot reports mDNS as enabled. When mDNS is disabled, the link is omitted — the route doesn't exist, so there's nothing to link to. On the browser page itself, the link is always present (you can only reach that page if mDNS is enabled).

---

## 4. Dashboard Adapter (`dashboard.rs`)

### 4.1 Snapshot Builder

Assembles a unified JSON snapshot by querying each enabled core. Stateless — built fresh per request from cheap, lock-free reads:

```rust
// crates/koi/src/adapters/dashboard.rs

#[derive(Serialize)]
pub(crate) struct DashboardSnapshot {
    // ── Identity ──
    version: String,
    platform: String,
    hostname: String,
    uptime_secs: u64,
    mode: DashboardMode,            // "daemon" | "embedded" | "client"

    // ── Capabilities ──
    capabilities: Vec<CapabilityCard>,

    // ── Domain Details ──
    health: Option<HealthDetail>,
    dns: Option<DnsDetail>,
    certmesh: Option<CertmeshDetail>,
    proxy: Option<ProxyDetail>,
    udp: Option<UdpDetail>,
}

#[derive(Serialize)]
struct CapabilityCard {
    name: String,               // "mdns", "certmesh", etc.
    enabled: bool,
    healthy: bool,
    summary: String,            // From Capability::status()
}

#[derive(Serialize)]
struct HealthDetail {
    machines: Vec<MachineHealth>,
    services: Vec<ServiceHealth>,
}

// ... DnsDetail, CertmeshDetail, ProxyDetail, UdpDetail follow same pattern
```

**No mDNS browser data here.** The dashboard snapshot is purely system-level. The mDNS capability card shows registration count and health — the same `Capability::status()` summary as every other card.

### 4.2 SSE Event Stream

```rust
// GET /v1/dashboard/events
```

Merges all domain broadcast channels — the same pattern proven in `koi-embedded/src/events.rs`. Event types:

| SSE `event:` | Payload | Source |
|--------------|---------|--------|
| `health.changed` | `{ name, status }` | `HealthCore::subscribe()` |
| `dns.updated` | `{ name, ip }` | `DnsCore::subscribe()` |
| `dns.removed` | `{ name }` | `DnsCore::subscribe()` |
| `certmesh.joined` | `{ hostname }` | `CertmeshCore::subscribe()` |
| `certmesh.revoked` | `{ hostname }` | `CertmeshCore::subscribe()` |
| `proxy.updated` | `ProxyEntry` JSON | `ProxyRuntime::subscribe()` |
| `proxy.removed` | `{ name }` | `ProxyRuntime::subscribe()` |
| `mdns.registered` | `{ id, name }` | `MdnsCore::subscribe()` |
| `mdns.expired` | `{ id }` | `MdnsCore::subscribe()` |
| `heartbeat` | `{ uptime_secs }` | Timer (every 15s) |

Note: _registration lifecycle_ events (`registered`, `expired`) go to the dashboard. _Network discovery_ events (`found`, `resolved`, `removed`) go to the browser. Clean separation.

### 4.3 Routes

| Method | Path | Response | Notes |
|--------|------|----------|-------|
| `GET` | `/` | `text/html` | Dashboard SPA (`include_str!`) |
| `GET` | `/v1/dashboard/snapshot` | `application/json` | System-level state |
| `GET` | `/v1/dashboard/events` | `text/event-stream` | Unified capability events |

### 4.4 HTML Sections

```
┌─────────────────────────────────────────────────────────────┐
│  KOI   Dashboard ·  Browser  ·  API Docs          NAV BAR  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ▎ Koi                                     ● healthy        │
│  ▎ NETWORK SERVICES DAEMON                          HERO    │
│  ▎ localhost:5641                                            │
│  hostname-fqdn · windows · 1h 23m · 6 capabilities          │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐  CAPABILITY CARDS  │
│  │  MDNS    │ │ CERTMESH │ │   DNS    │  (auto-grid)       │
│  │  ● 3 reg │ │ ● CA init│ │ ● running│                    │
│  └──────────┘ └──────────┘ └──────────┘                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                    │
│  │  HEALTH  │ │  PROXY   │ │   UDP    │                    │
│  │  ● 5 up  │ │ ● 2 fwd  │ │ ● 1 bind │                    │
│  └──────────┘ └──────────┘ └──────────┘                    │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  HEALTH                                     DETAIL PANELS   │
│  ●●●○  3 up / 1 unknown                                    │
│  SERVICE       KIND   TARGET          STATUS   LAST OK      │
│  api         ● http   https://...      up      12s ago      │
│  database    ● tcp    localhost:5432   up      12s ago      │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  DNS RESOLVER · CERTMESH · PROXY · UDP                      │
│  (condensed detail panels per capability)                   │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ACTIVITY                                    EVENT LOG      │
│  14:32:05  health.changed  api: up → down                   │
│  14:31:50  dns.updated     grafana.lan → 192.168.1.42      │
│  ...                                                         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Side navigation** (sticky, hidden <1200px):

```
  OVERVIEW
  CAPABILITIES
  HEALTH
  DNS
  CERTMESH
  PROXY / UDP
  ACTIVITY
```

#### 4.4.1 Hero / Identity Bar

- Sage left-border accent
- Mode badge: `DAEMON`, `EMBEDDED`, or `CLIENT` (monospace, uppercase)
- Pulsing health dot (sage=healthy, clay=degraded, red=unhealthy)
- At-a-glance: hostname, platform, uptime, enabled capability count

#### 4.4.2 Capability Cards

Auto-grid of vellum-glass cards, one per capability:

| Capability | Card Contents |
|-----------|---------------|
| **mDNS** | Registration count (alive/draining/expired), uptime. Links to → Browser page |
| **Certmesh** | CA initialized, locked status, auth method, member count, enrollment state |
| **DNS** | Running status, zone name, record count, port |
| **Health** | Machines tracked, services monitored, status breakdown |
| **Proxy** | Active listeners, entry count |
| **UDP** | Active bindings count |

Disabled capabilities render at 45% opacity with "disabled" badge — dormant stone treatment.

The mDNS card includes a "Browse network →" link to `/mdns-browser`, creating a clear affordance to the dedicated browser. No inline network table.

#### 4.4.3 Health Panel

```
Machines  ●●●○    3 up / 1 unknown
Services  ●●●●●   5 up / 0 down

SERVICE          KIND    TARGET                STATUS   LAST OK
api           ●  http    https://localhost:3k    up     12s ago
database      ●  tcp     localhost:5432          up     12s ago
external-api  ◌  http    https://api.example     down   5m ago
└─ Response: 503 Service Unavailable
```

Dot-row summary, expandable failure messages, sage/red/muted coloring.

#### 4.4.4 DNS, Certmesh, Proxy, UDP Panels

Condensed domain detail panels. See §4.5–4.7 in the original spec for wireframes — unchanged, just no longer mixed with the browser.

#### 4.4.5 Activity Log

Ring buffer of 50 entries, reverse-chronological, color-coded by domain. Fed from `/v1/dashboard/events` SSE.

---

## 5. mDNS Browser Adapter (`mdns_browser.rs`)

### 5.1 Background Worker & Cache

The browser adapter is **stateful**. On daemon startup (if mDNS is enabled), it spawns a meta-browse worker and maintains an in-memory service cache:

```rust
// crates/koi/src/adapters/mdns_browser.rs

/// In-memory cache of mDNS services discovered on the network.
/// Adapter-level read model — NOT a domain concept.
pub(crate) struct BrowserCache {
    services: Arc<RwLock<HashMap<String, BrowserService>>>,
}

#[derive(Serialize, Clone)]
struct BrowserService {
    name: String,
    instance_name: String,        // Full instance name (key)
    service_type: String,
    host: String,
    ip: String,
    port: u16,
    txt: HashMap<String, String>,
    first_seen: String,           // ISO 8601
    last_seen: String,            // ISO 8601
    resolved: bool,
    removed_at: Option<String>,   // ISO 8601, for fade-out
}
```

#### 5.1.1 Worker Lifecycle

```
daemon_mode() / koi_embedded::start()
  └─ if mdns enabled:
       let cache = BrowserCache::new();
       spawn(mdns_browser::worker(mdns_core.clone(), cache.clone(), cancel.clone()));
       // Inject cache into AppState / embedded state
```

The worker:
1. Calls `MdnsCore::browse("_services._dns-sd._udp.local.")` to enumerate all service types on the network
2. For each discovered type, spawns a sub-task subscribing to lifecycle events via `MdnsCore::subscribe(type)`
3. Maps `MdnsEvent::Found`, `Resolved`, `Removed` into `BrowserCache` writes
4. Every 30s, purges services where `removed_at` is >60s old
5. Shuts down cleanly via `CancellationToken`

Uses only the existing `MdnsCore` public interface — no new domain methods needed.

### 5.2 Snapshot

```rust
#[derive(Serialize)]
pub(crate) struct BrowserSnapshot {
    // ── Summary ──
    total_services: usize,
    service_types: Vec<TypeSummary>,

    // ── Services ──
    services: Vec<BrowserService>,

    // ── Meta ──
    cache_age_secs: u64,          // Time since worker started
    mdns_enabled: bool,
}

#[derive(Serialize)]
struct TypeSummary {
    service_type: String,
    count: usize,
}
```

Reads from `BrowserCache`. The `service_types` array is sorted by count descending — ready for the histogram bars.

### 5.3 SSE Event Stream

```rust
// GET /v1/mdns/browser/events
```

Subscribes **only** to `MdnsCore::subscribe()` — no other domain channels. Lean and focused. Event types:

| SSE `event:` | Payload | Source |
|--------------|---------|--------|
| `found` | `ServiceRecord` JSON | `MdnsCore::subscribe()` |
| `resolved` | `ServiceRecord` JSON | `MdnsCore::subscribe()` |
| `removed` | `{ name, service_type }` | `MdnsCore::subscribe()` |
| `heartbeat` | `{ total_services }` | Timer (every 15s) |

Each SSE event includes a UUIDv7 `id:` field for deduplication — matching the existing mDNS SSE pattern.

### 5.4 Routes

| Method | Path | Response | Notes |
|--------|------|----------|-------|
| `GET` | `/mdns-browser` | `text/html` | Browser SPA (`include_str!`) |
| `GET` | `/v1/mdns/browser/snapshot` | `application/json` | Full browser cache |
| `GET` | `/v1/mdns/browser/events` | `text/event-stream` | mDNS-only SSE stream |

The API endpoints nest under `/v1/mdns/browser/` — scoped to the mDNS domain, consistent with existing `/v1/mdns/*` routes. These routes are mounted by `mdns_browser.rs` but nested under the mDNS prefix in `http.rs`. **The browser routes are only available when mDNS is enabled** — when disabled, the `/v1/mdns/browser/*` prefix returns 503 via the existing `disabled_fallback_router` pattern, and the `/mdns-browser` HTML page is not served.

### 5.5 HTML Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  KOI   Dashboard ·  Browser  ·  API Docs                  NAV BAR │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ▎ mDNS Browser                                    42 services     │
│  ▎ NETWORK SERVICE DISCOVERY                      HERO             │
│  ▎ via koi daemon on localhost:5641                                │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐  ┌──────────────────────────────────┐             │
│  │ Filter       │  │ _http._tcp       17  ████████████│  TYPE      │
│  │ ____________ │  │ _https._tcp      12  ████████    │  HISTOGRAM │
│  │              │  │ _smb._tcp         5  ████        │             │
│  │ Types:       │  │ _printer._tcp     4  ███         │             │
│  │ ☑ _http._tcp │  │ _ssh._tcp         3  ██          │             │
│  │ ☑ all others │  │ _ipp._tcp         1  █           │             │
│  └─────────────┘  └──────────────────────────────────┘             │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                    SERVICE TABLE    │
│  NAME              TYPE           HOST           IP            PORT │
│  ─────────────────────────────────────────────────────────────────  │
│  My NAS        ▸   _http._tcp    nas.local.     192.168.1.50  8080 │
│  Grafana       ▸   _http._tcp    grafana.lan.   192.168.1.42  3000 │
│  HP Printer    ▸   _ipp._tcp     hp.local.      192.168.1.60   631 │
│  Dev Server    ▸   _http._tcp    dev.local.     192.168.1.10  3000 │
│  └─ TXT Records ─────────────────────────────────────────────────  │
│     version=2.1  path=/api  server=nginx                           │
│     ────────────────────────────────────────                       │
│     first seen: 14:30:02 · last seen: 14:32:05 · resolved ●       │
│  Pi-hole       ▸   _dns._udp    pi.local.      192.168.1.1     53 │
│  ...                                                               │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                    DISCOVERY LOG   │
│  14:32:05  found      My NAS._http._tcp on 192.168.1.50           │
│  14:31:58  resolved   Grafana._http._tcp → grafana.lan.           │
│  14:31:52  removed    Old-Service._smb._tcp                        │
│  ...                                                               │
└─────────────────────────────────────────────────────────────────────┘
```

#### 5.5.1 Filter & Controls Bar

- **Free-text filter** — searches across name, type, host, IP, TXT keys/values
- **Type filter checkboxes** — dynamically generated from discovered types
- **Service type histogram** — horizontal micro-bars showing distribution, doubles as clickable type filter
- **Export** — "Copy as JSON" button for the current filtered view

#### 5.5.2 Service Table

- **Sortable columns** — click column headers (Name, Type, Host, IP, Port) with ▲/▼ indicators
- **Expandable rows** — click `▸` to reveal:
  - Full TXT record key-value pairs (URLs rendered as links, long values truncated with expand)
  - First/last seen timestamps
  - Resolved status with dot indicator
- **Status dot per service** — sage=resolved, hopeful/gold=found (unresolved), muted+fade=recently removed
- **Auto-scroll toggle** — pin to newest (default) or freeze

#### 5.5.3 Service Type Categorization

Purely a JS-side visual concern:

| Service Type | Category | Color |
|-------------|----------|-------|
| `_http._tcp`, `_https._tcp` | Web | sage |
| `_ssh._tcp` | Remote Access | clay |
| `_smb._tcp`, `_nfs._tcp`, `_afpovertcp._tcp` | File Sharing | hopeful |
| `_ipp._tcp`, `_printer._tcp` | Printing | muted |
| `_dns._udp`, `_dns-sd._udp` | DNS | sage |
| Everything else | Other | stone-400 |

#### 5.5.4 Discovery Log

Bottom section — mDNS-only activity feed from `/v1/mdns/browser/events` SSE. Ring buffer of 30 entries, color-coded by event type (found=sage, resolved=hopeful, removed=clay).

### 5.6 Cache Eviction

Removed services (mDNS goodbye packets) are marked with `removed_at` and kept for 60 seconds with a visual fade-out in the UI. After 60s, the background worker purges them. Prevents flickering during network transitions.

Maximum cache size: 500 services. If the network has more, oldest-unseen services are evicted. Defensive bound.

---

## 6. Integration Details

### 6.1 AppState Extension

`AppState` in `http.rs` gains one new field:

```rust
#[derive(Clone)]
struct AppState {
    // ... existing fields ...
    browser_cache: Option<Arc<BrowserCache>>,  // NEW — None if mDNS disabled
}
```

### 6.2 Route Mounting (Daemon Mode)

In `crates/koi/src/adapters/http.rs`:

```rust
// Dashboard — always mounted (disabled capabilities show as disabled cards)
app = app.route("/", get(dashboard::get_dashboard));
app = app.route("/v1/dashboard/snapshot", get(dashboard::get_snapshot));
app = app.route("/v1/dashboard/events", get(dashboard::get_events));

// mDNS Browser — only mounted if mDNS is enabled (follows domain route pattern)
if let Some(ref browser_cache) = state.browser_cache {
    app = app.route("/mdns-browser", get(mdns_browser::get_page));
    app = app.nest("/v1/mdns/browser", mdns_browser::routes(browser_cache.clone()));
} else {
    app = app.nest("/v1/mdns/browser", disabled_fallback_router("mdns-browser"));
}
```

### 6.3 Route Mounting (Embedded Mode)

In `crates/koi-embedded/src/http.rs`:

```rust
// Only if http_enabled (default true)
app = app.route("/", get(dashboard_html));
app = app.route("/v1/dashboard/snapshot", get(dashboard_snapshot));
app = app.route("/v1/dashboard/events", get(dashboard_events));

if let Some(ref cache) = browser_cache {
    app = app.route("/mdns-browser", get(mdns_browser_html));
    app = app.nest("/v1/mdns/browser", mdns_browser_routes(cache.clone()));
}
```

### 6.4 mDNS Browser Worker Wiring

```
daemon_mode() in main.rs
  └─ if mdns enabled:
       let browser_cache = Arc::new(BrowserCache::new());
       spawn(mdns_browser::worker(mdns_core.clone(), browser_cache.clone(), cancel.clone()));
       // Pass browser_cache into AppState
```

For embedded mode, same pattern in `KoiEmbedded::start()`.

The worker uses the existing `MdnsCore::browse()` and `MdnsCore::subscribe()` APIs — it's just another consumer of the core's public interface. No new domain methods needed.

### 6.5 Snapshot Builder Sharing (Daemon vs Embedded)

**Decision: Duplicate.** Both the daemon and embedded snapshot builders are ~80–100 lines of read-only queries against `Capability::status()` plus domain-specific methods. The browser snapshot builder is ~40 lines reading from `BrowserCache`. Duplicating preserves the rule that domain crates never import each other and avoids a new dependency. If shared logic grows past ~150 lines, extract into a utility at that point.

### 6.6 Capability Detection

The existing `Capability` trait suffices for dashboard cards:

```rust
pub trait Capability: Send + Sync {
    fn name(&self) -> &str;
    fn status(&self) -> CapabilityStatus;
}
```

For deep-dive detail panels (health, DNS, certmesh), the dashboard accesses domain-specific methods through `AppState`'s `Option<Arc<DomainCore>>` fields — same pattern as existing HTTP handlers.

### 6.7 HTML Asset Strategy

Two self-contained HTML files with inline CSS and JS:

```rust
// dashboard.rs
const DASHBOARD_HTML: &str = include_str!("../../assets/dashboard.html");

// mdns_browser.rs
const BROWSER_HTML: &str = include_str!("../../assets/mdns-browser.html");
```

**Why two files instead of one?**

- Each page is self-contained: no shared JS state, no shared CSS imports, no coupling
- Either can be modified without risk to the other
- Compile-time embedded: zero filesystem dependencies
- Combined they're ~2000 lines — the Ollama orchestrator is 1850 in **one** file, so two ~1000-line files are well within proven territory

### 6.8 Mode-Aware Behavior

| Aspect | Daemon | Embedded | Client-Only (embedded) |
|--------|--------|----------|----------------------|
| Dashboard served | Yes, at `GET /` | Yes, if `http_enabled` | No (remote daemon serves it) |
| Browser served | Yes, at `GET /mdns-browser` | Yes, if `http_enabled` | No (remote daemon serves it) |
| Dashboard snapshot | Local domain cores | Local domain cores | Proxied to remote |
| Browser snapshot | Local `BrowserCache` | Local `BrowserCache` | Proxied to remote |
| Browser worker | Spawned if mDNS enabled | Spawned if mDNS enabled | Not spawned |
| Hero badge | `DAEMON` | `EMBEDDED` | N/A |
| Admin actions | Available (shutdown, drain) | Subset (no shutdown) | Available (remote) |

---

## 7. Expandability & Future Work

### 7.1 Dashboard Plugin Card System

Each capability card follows a uniform structure (name, enabled, healthy, summary). New capabilities added to Koi automatically get a card — the snapshot builder iterates over all capabilities in `AppState`.

### 7.2 Browser Actions (Future)

Action buttons per service: "Register similar", "Monitor this service" (add health check), "Add DNS alias". These `POST` to existing API endpoints — no new backend.

### 7.3 Additional Browsers (Future)

The same adapter pattern can spawn dedicated browsers for other domains:
- **Certificate Browser** (`GET /certmesh-browser`, `/v1/certmesh/browser/*`) — roster visualization, expiry timeline
- **DNS Browser** (`GET /dns-browser`, `/v1/dns/browser/*`) — zone visualization with record sources

Each would be its own adapter module + HTML file. The pattern is established.

### 7.4 WebSocket Upgrade (Future)

If SSE proves limiting, either stream can upgrade to WebSocket independently. The poll-for-truth pattern means SSE→WS migration is non-breaking for either page.

### 7.5 Embedded Mode Opt-Outs

Builder methods for granular control:

```rust
Builder::new()
    .http(true)
    .dashboard(true)     // system overview at GET /
    .mdns_browser(true)  // mDNS browser at GET /mdns-browser
```

---

## 8. Implementation Plan

### Phase 1 — Dashboard Backend

1. **`crates/koi/src/adapters/dashboard.rs`** — Snapshot builder, SSE stream, HTML serving
2. **Mount dashboard routes in `http.rs`** — `GET /`, `/v1/dashboard/snapshot`, `/v1/dashboard/events`
3. **Smoke test** — `curl /v1/dashboard/snapshot` returns valid JSON with all capability cards

### Phase 2 — Browser Backend

4. **`crates/koi/src/adapters/mdns_browser.rs`** — `BrowserCache`, meta-browse worker, snapshot, SSE, HTML serving
5. **Mount browser routes in `http.rs`** — `GET /mdns-browser`, nest `/v1/mdns/browser/*`
6. **Wire worker in `main.rs`** — spawn browser worker, inject cache into `AppState`
7. **Smoke test** — `curl /v1/mdns/browser/snapshot` returns discovered services

### Phase 3 — Dashboard Frontend

8. **`crates/koi/assets/dashboard.html`** — Design tokens, hero, capability cards, health panel, DNS/certmesh/proxy/UDP panels, activity log, side nav, dark mode
9. **SSE integration** — Connect to `/v1/dashboard/events`, update activity log in real-time

### Phase 4 — Browser Frontend

10. **`crates/koi/assets/mdns-browser.html`** — Design tokens, hero, filter bar, type histogram, service table with sort/expand, discovery log, dark mode
11. **SSE integration** — Connect to `/v1/mdns/browser/events`, real-time service additions/removals
12. **Service type categorization** — Color mapping for well-known types

### Phase 5 — Embedded Mode

13. **Mount both in `koi-embedded/src/http.rs`** — duplicate snapshot builders, wire browser cache
14. **Builder toggles** — `dashboard(bool)`, `mdns_browser(bool)`

### Phase 6 — Polish

15. **Connection resilience** — Disconnection banner, SSE auto-reconnect (both pages)
16. **Copy-as-JSON export** — Browser filtered view export
17. **mDNS card → Browser link** — "Browse network →" affordance on dashboard mDNS card linking to `/mdns-browser` (only rendered when mDNS is enabled)
18. **ADR** — Document architecture decision

---

## 9. API Surface Summary (New Endpoints)

| Method | Path | Response | Module |
|--------|------|----------|--------|
| `GET` | `/` | `text/html` | `dashboard.rs` |
| `GET` | `/v1/dashboard/snapshot` | `application/json` | `dashboard.rs` |
| `GET` | `/v1/dashboard/events` | `text/event-stream` | `dashboard.rs` |
| `GET` | `/mdns-browser` | `text/html` | `mdns_browser.rs` |
| `GET` | `/v1/mdns/browser/snapshot` | `application/json` | `mdns_browser.rs` |
| `GET` | `/v1/mdns/browser/events` | `text/event-stream` | `mdns_browser.rs` |

No new write endpoints. All mutations go through existing domain APIs (`/v1/mdns/*`, `/v1/health/*`, etc.).

---

## 10. What This Does NOT Do

- **No authentication** — both pages are read-only views. Auth is a separate concern (ADR-009).
- **No persistent storage** — browser cache is in-memory, rebuilt on restart via meta-browse (takes seconds).
- **No new domain crate** — both modules are adapters in the binary crate.
- **No build toolchain** — no npm, no webpack, no TypeScript. Two self-contained HTML files.
- **No modifications to domain crates** — all data consumed through existing public APIs and broadcast channels.
- **No shared HTML/CSS/JS** between the two pages — each is fully self-contained. Design token duplication is intentional.

---

## 11. Open Questions

1. **Should `GET /` replace the existing `/docs` (Scalar) page, or coexist?** Recommendation: coexist. `/docs` is API docs for developers; `/` is the operational dashboard; `/mdns-browser` is the network explorer. Three audiences = three pages.

2. **Should the mDNS browser cache survive daemon restarts?** Recommendation: No. Rebuilds in seconds via meta-browse. No persistence.

3. **Should embedded mode get SSE event streams?** Recommendation: Yes, if `http_enabled`. Same broadcast channels exist. Cost is near-zero.

4. **Should the browser be available when mDNS is disabled?** Answer: **No.** The browser is an mDNS feature — it follows the same conditional mounting pattern as all domain routes. When mDNS is disabled, `/v1/mdns/browser/*` returns 503 via `disabled_fallback_router`, and `/mdns-browser` is not served. The dashboard still shows mDNS as a disabled card, which is sufficient visibility.
