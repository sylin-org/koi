# Koi 0.6 Wishlist — Aggregated & Prioritized

> **Status (2026-06-24): 0.5.2 scope SHIPPED on `dev`** (not yet pushed/tagged).
> - Instant batch I1–I5 — `35f4ec3`
> - T1-A `CertmeshCore::renew_member` (ADR-021) — `cff618a` — **two-box hardware gate PASSED 20/0**
> - T1-B mDNS browser type annotations — `fa9e0ca`
> - T1-C first-run getting-started hint — `e0c8d47`
>
> All gated (fmt, clippy -D, `test --workspace --locked`, doc-leaks). Remaining
> for 0.6.0: T2 items (scoped tokens, `koi tls setup`, NRPT, `--cert-lifetime`).
> Follow-up noted in review: extend `csr::requested_sans` to also surface IP SANs
> so an unauthorized IP in a renewal CSR fails loudly (today structurally backstopped
> by `sign_csr`, so safe but silent).

> Synthesized 2026-06-24 from three sources:
> - **V** — Product wishlist v2 (Gemini strategic analysis, realigned after Tailscale comparison)
> - **S** — Surface analysis harvest (Gemini pros/cons/scenarios; net-new opportunities)
> - **Z** — Embedded consumer wishlist against koi 0.5.1 (code-precise; see docs/notes/ in the consumer repo)
>
> Source **Z** carries the highest weight: concrete, verified against a path-dep build,
> filed with exact file/line references. Sources V and S are strategic and positioning.
>
> **K2 gate**: all implementation must use generic, consumer-neutral vocabulary.
> Never name the Z-wishlist's consumer in koi code or docs.
> Run `scripts/check-doc-leaks.sh` after any doc changes.

---

## Architecture Decision

**ADR-021** (`docs/adr/021-embedded-completion.md`) covers the main architectural
decision for this cycle: `CertmeshCore::renew_member`, `KoiHandle::verify`, and
`member_cert_expiry`. Read it before starting the certmesh work.

---

## Instant Batch — Ship Together

Five items with zero or trivial engineering. One commit, no design decisions, no
two-box gate.

| # | Item | Source | Effort |
|---|------|--------|--------|
| **I1** | `KoiHandle::verify` — 5-line delegate to `certmesh()?.core()?.verify()` | Z | 5 lines |
| **I2** | `member_cert_expiry() -> Option<DateTime<Utc>>` — change `pub(crate)` to `pub` on `CertmeshCore` in `core_renewal.rs:74` or rename/expose | Z | visibility change |
| **I3** | OrbStack comparison in README — "OrbStack only does this on macOS and is proprietary; Koi is the open-source cross-platform answer" (under Scenario 2 / Developer Inner Loop) | S | 1 sentence |
| **I4** | "Port-scan localhost" in `docs/guides/mcp.md` — local MCP discovery is unsolved; projects currently port-scan; Koi can both BE discoverable (`_mcp._tcp`) and make other MCP servers discoverable | S | 1 paragraph |
| **I5** | Short-lived certs = explicit CRL/OCSP answer in `docs/guides/certmesh.md` — "Koi does not implement CRL/OCSP. For security-sensitive deployments, use `--cert-lifetime 24h` — a rotated 24-hour cert is functionally equivalent to instantaneous revocation without distribution infrastructure." | S | prose update |

**Verify**: `cargo clippy -- -D warnings`, `cargo test --workspace --locked`,
`scripts/check-doc-leaks.sh`.

---

## Tier 1 — High-Value, Individually Scoped

### T1-A: `CertmeshCore::renew_member` (Z, ADR-021)

Extract CA-side renewal invariants from `renew_handler` (`koi-certmesh/src/http.rs:902`)
into `CertmeshCore::renew_member(authenticated_cn: &str, csr_pem: &str)`.

The handler becomes a two-line wrapper. The method enforces every invariant:
active + non-revoked, SANs pinned to enrollment record (a renewal CSR cannot expand
them — the most critical invariant), policy lifetime, sign CSR, roster update, audit,
`CertRenewed` event.

**Tests required** (must cover the extracted method directly, not just the HTTP path):
- Member not found → `NotFound`
- Member draining → rejected
- Member revoked → `Revoked`
- SAN expansion attempt → `InvalidPayload`
- Expired cert → still allowed (renewal is the fix)
- Happy path: valid rotate-key CSR → cert issued, roster updated, event emitted

**Two-box gate applies** (certmesh change on the renewal hot path).
Size: medium. Security-critical.

### T1-B: mDNS browser type annotations (S)

Add a well-known service type lookup table to the mDNS browser. Raw `_hap._tcp`
becomes "HomeKit Accessory Protocol"; `_matterc._udp` becomes "Matter commissioning";
`_esphomelib._tcp` becomes "ESPHome device"; `_googlecast._tcp` becomes "Google Cast";
etc.

Location: `crates/koi-dashboard/src/` — a static `HashMap<&str, (&str, &str)>`
(type → (label, description)) rendered in `mdns-browser.html`.

**Why this matters**: This is the best zero-engineering path to community adoption.
The Home Assistant + Matter + HomeKit + ESPHome communities actively debug mDNS
commissioning issues. A "browse and debug your smart-home devices on any platform,
including Windows" post is a credible r/homeassistant launch.

No new API, no gate concerns. Size: very small.

**Starter list of types to annotate** (add more from IANA and community sources):

| Type | Label | Description |
|------|-------|-------------|
| `_http._tcp` | HTTP | Web service |
| `_https._tcp` | HTTPS | Secure web service |
| `_ssh._tcp` | SSH | Secure Shell |
| `_ftp._tcp` | FTP | File Transfer |
| `_smb._tcp` | SMB/Samba | Windows file sharing |
| `_afpovertcp._tcp` | AFP | Apple file sharing |
| `_hap._tcp` | HomeKit | HomeKit accessory |
| `_matterc._udp` | Matter | Matter commissioning |
| `_matter._tcp` | Matter | Matter operational |
| `_esphomelib._tcp` | ESPHome | ESPHome device |
| `_googlecast._tcp` | Google Cast | Chromecast / Google Home |
| `_spotify-connect._tcp` | Spotify | Spotify Connect |
| `_airplay._tcp` | AirPlay | Apple AirPlay |
| `_raop._tcp` | AirPlay Audio | AirPlay audio |
| `_ipp._tcp` | Printer (IPP) | Internet printing |
| `_printer._tcp` | Printer | Generic printer |
| `_pdl-datastream._tcp` | Printer (PDL) | PDL printer |
| `_scanner._tcp` | Scanner | Network scanner |
| `_homeassistant._tcp` | Home Assistant | Home Assistant instance |
| `_mqtt._tcp` | MQTT | Message broker |
| `_mqtts._tcp` | MQTT (TLS) | Secure message broker |
| `_nfs._tcp` | NFS | Network file system |
| `_daap._tcp` | DAAP | iTunes music sharing |
| `_dop._tcp` | DMAP | Apple media sharing |
| `_rtsp._tcp` | RTSP | Media streaming |
| `_koi._tcp` | Koi | Koi daemon |
| `_mcp._tcp` | MCP | Model Context Protocol server |
| `_certmesh._tcp` | Certmesh | Koi certificate mesh CA |
| `_services._dns-sd._udp` | DNS-SD | Service discovery meta-query |

### T1-C: First-run experience (V)

Verify what the installer already does (780de5f added `koi status` + next steps at
install completion). The remaining gap is **bare `koi` when the daemon has never been
configured** — not the install path, but the "cloned and ran it" or "downloaded the
binary" path.

If `koi` with no subcommand and no running daemon currently prints a confusing or
empty status, add a first-run branch that prints three clear next steps:
1. `koi mdns discover` — works instantly, no config
2. `koi --daemon` — start the full toolbox
3. `koi certmesh create` — mint a private CA

Size: small. Verify the current behavior before implementing.

---

## Tier 2 — Product Engineering (Design Decisions Required)

### T2-A: `koi tls setup` — one-command simple mode (V)

```bash
koi tls setup   # creates private CA, installs trust, enables DNS
```

Privacy-first framing: "private HTTPS in one command — no account, no cloud, your
names stay on your network." Not speed-vs-mkcert.

Needs scoping: "enable auto-cert" may imply cert-on-demand that doesn't yet exist.
Define the exact sequencing before implementing.

### T2-B: Scoped tokens (V)

```bash
koi token create --scope discover   # read the LAN, nothing else
koi token create --scope announce   # containers: announce only
koi token create --scope dns        # manage DNS records only
```

The DAT is the admin key; scoped tokens are the API-key model for MCP agents and
containers. Requires auth middleware extension in `koi-serve`. Prerequisite for the
MCP flagship guide having a copy-paste scoped-read-only example.

### T2-C: DNS without port 53 — Windows NRPT in service installer (V)

macOS (`/etc/resolver/internal`) and Linux (`systemd-resolved` drop-in for the
`.internal` zone) are docs-only. Windows NRPT rule automation in the service
installer (`koi install`) is the one engineering item — it's where port-53 friction
is worst, and the installer already runs elevated.

**First**: verify whether `.internal` is already the default zone (per ADR-016 §quirk,
it was `.lan` at the realignment; check `koi-config` defaults). If not yet changed,
the default zone change is the prerequisite.

### T2-D: Short-lived certs `--cert-lifetime` (V)

`koi certmesh create --cert-lifetime 24h`

The engineering counterpart to the I5 docs change. Renewal automation must work at
24h — the self-renewal loop's timer and the `CertExpiringSoon` threshold both need
adjustment. Do **after** T1-A (`renew_member`) is stable.

---

## Tier 3 — Depth / Architecture

### T3-A: `.internal` positioning docs (V/S)

Verify the default DNS zone. If already `.internal`: write the positioning guide
("why `.internal`, why public CAs are forbidden from issuing for it, why a private CA
is the only path"). If still `.lan`: change the default and write the guide together.

ICANN reserved `.internal` in 2024. This is a cheap, defensible positioning move that
requires mostly documentation.

### T3-B: Dashboard copy-token + DNS add (V)

Copy-token: unambiguous, safe, high value.
DNS add: opens the read-only dashboard principle. Auth model question: DAT in a
cookie? Requires explicit design decision before implementing.

### T3-C: Integration recipe docs — Caddy, Traefik, Pi-hole (V/S)

All mostly documentation:
- Caddy: point `ca = http://localhost:5643` at the ACME server (already ships)
- Traefik: equivalent ACME configuration
- Pi-hole / AdGuard: conditional forwarding to Koi's DNS resolver (recipes exist in
  dns-coexistence.md; make them more prominent)

Prometheus SD: already done. Home Assistant webhook: niche, deprioritize.

---

## Deferred

| Item | Source | Why deferred |
|------|--------|--------------|
| Injected member-side renewal transport | Z | After `renew_member` ships; CA-side is the immediate unlock |
| `koi tailscale setup` | V | Tailscale CLI doesn't expose split-DNS zone config; one-command promise can't be kept. Revisit if Tailscale exposes an API. Interim: `koi tailscale guide` (detect + print steps + open URL). |
| MCP flagship guide rewrite | V/S | After scoped tokens land — the guide's value prop needs the scoped read-only token example |
| Event hooks / webhooks | V | SSE already covers push-to-client; outbound webhooks add retry/registry complexity |
| `koi.toml` persistent config | V | Large architecture change to koi-config; pull forward when pain from flag-only config is concrete |
| Standalone crate stabilization | V | Post-1.0 — requires semver stability commitment the project isn't making yet |

---

## Release Shape Notes

The instant batch (I1–I5) + T1-A + T1-B is a natural **0.5.2** scope: embedded
ergonomics + docs/community. No breaking changes if `member_cert_expiry()` is purely
additive.

T2-A/B/C are the natural **0.6.0** scope: product features that may have breaking
changes (`--cert-lifetime` adds a required invariant to renewal; scoped tokens change
the auth model).

---

## Verification Checklist

Before any commit:
- `cargo check --workspace`
- `cargo test --workspace --locked`
- `cargo clippy -- -D warnings`
- `cargo fmt --check`
- `scripts/check-doc-leaks.sh` (after any doc change)
- `git show HEAD:docs/SURFACES.md | bash scripts/lint-surfaces.sh /dev/stdin`

Two-box gate applies for: T1-A (certmesh renewal hot path), T2-B (auth middleware),
T2-D (cert lifecycle).
