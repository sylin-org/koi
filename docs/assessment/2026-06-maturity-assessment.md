# Koi Project Assessment — June 2026

> **⚠️ Point-in-time snapshot (2026-06-11) — much has since been resolved.** For the current
> status of every verified defect, lean-plan move, shed item, and stage — re-audited against
> `dev` HEAD with commit/file evidence — see
> **[realignment-2026-06-22.md](realignment-2026-06-22.md)** (headline: **10 of 12 verified
> defects fixed**; the two remaining are docs-staleness + one unauthenticated audit GET). This
> document is preserved unchanged as the historical record of what was true on 2026-06-11.

**Status:** Complete · **Date:** 2026-06-11 · **Method:** staged multi-agent assessment
(10 parallel subsystem deep-reads → adversarial verification of 14 load-bearing claims →
2 external research tracks → synthesis). All quantitative claims in this document were
verified against source, git history, dependency code, or live external state — see
[findings/verification-2026-06.md](findings/verification-2026-06.md).

**Corpus:** detailed per-lens reports in [findings/](findings/), strategy research in
[research/](research/).

---

## 1. Executive summary

Koi set out to test a usage philosophy — *one cross-platform binary that makes the local
network discoverable, named, trusted, and reachable, exposed to any language over
HTTP/IPC/CLI* — and the feasibility test **succeeded**. The capability composition loop
(container starts → mDNS announces → DNS names it → certmesh certifies it → proxy serves
it → health watches it) is architecturally real, the domain-crate boundary model held up
under 15 crates, and the landscape research confirms the position is genuinely
differentiated: nothing else offers a cross-platform mDNS daemon with an HTTP API, and
nobody offers the integrated pipeline ("open-source OrbStack domains for any host").

But the project is currently a **late-stage feasibility prototype wearing beta-shaped
clothing**, and the costume is starting to mislead. ~57.7k lines of Rust, ~820 tests,
3-OS CI, 6-target releases, 13 ADRs, and 24k lines of documentation coexist with: a TLS
proxy that has plausibly **never worked** (it panics silently at startup and reports
`running: true`), a headline container use case that is **broken as documented** on native
Linux, every documented mutation example returning **401**, a Windows service that
silently lacks half the daemon's background machinery, crates.io publishing that has been
**silently failing since February**, and a weekly QA workflow that has never been able to
pass. The pattern is consistent: *what is easy to test is exquisitely tested; what is
risky has plausibly never been run.*

The maturation path is not "more features" — it is the opposite. The assessment's central
recommendation is a four-stage program: **restore truth** (make docs, CI, and metadata
match reality), **make the promise true** (fix the five verified product-breaking
defects), **consolidate** (one orchestrator, a certmesh diet, fold or shed ~6 of 15
crates — roughly 57.7k → ~40k LOC), and only then **launch** (SemVer, packaging, MCP
server, the r/selfhosted story). Done in that order, Koi's "less but more meaningful
parts" goal is achievable in weeks of focused effort, because the hard architectural
substance already exists.

---

## 2. Identity: declared vs. revealed

### Declared pillars

The repo's own front-matter and archived spec declare:

1. **"The missing LAN toolbox"** — discovery (mDNS), naming (DNS), trust (certmesh),
   reachability (proxy), observation (health), in one binary (README.md).
2. **"The secure path is the easy path"** (koi-spec.md:38).
3. **"The boundary is the local network. Everything inside that boundary belongs in Koi"**
   (koi-spec.md:1136) — with a disciplined "What Not to Build" list.
4. **Transport pluralism** — HTTP, IPC/NDJSON, CLI, embedded-Rust; any language, any
   container.
5. Audience: homelabs (5–15 machines), small orgs "with a duty of care but no IT
   department."

### Revealed identity (what the code and history actually say)

- **The claimed invention is the PKI, not the mDNS.** All nine defensive publications
  (2026-03-24) fence certmesh/ceremony/lease/UDP novelty — none claim mDNS novelty
  (README explicitly credits mdns-sd). Counting koi-crypto, koi-truststore, and
  binary-side wiring, the certmesh pillar is **~45% of the codebase**. The declared
  product is a LAN toolkit; the revealed product is a zero-config LAN PKI with a
  supporting cast.
- **There is a hidden second customer.** koi-udp and the embedded HTTP self-hosting exist
  because a sibling project (zen-garden's ORCH suite, Garden mesh UDP 7184) needed them —
  declared in KOI-0001's header but invisible in README/GUIDE. Vocabulary from that
  ecosystem ("Moss", "Rake", "pond", "garden") permeates certmesh internals
  (roster.rs:62, unlock_slots.rs:69). Koi serves two diverging audiences: the human
  homelab operator and a programmatic Sylin-ecosystem substrate — and the front-matter
  only admits the first.
- **The third, implicit philosophy is the real experiment:** building a multi-domain
  infrastructure product through agentic AI development — tool-agnostic AI context
  (`.agentic/`), three-voice documentation, ADR discipline, multi-agent security reviews,
  an archived implementation guide signed "-Claude". This experiment produced both the
  project's greatest strengths (process artifacts most hobby projects never have) and its
  signature failure modes (docs that describe intent rather than reality; an ADR that
  confabulated its own history; rules nobody enforces).
- **Development arc:** 176 commits in ~7 intense weeks (2026-02-07 → 2026-03-26), then
  near-silence (one reverted commit in May). The cadence of an experiment that reached its
  demonstration point — but the repo doesn't say so, and the broken automation keeps
  running unwatched.

---

## 3. Maturity scorecard

Scale: **Prototype → Feasibility → Alpha → Beta → Production.**

| Dimension | Level | Evidence (verified) |
|---|---|---|
| Architecture & boundaries | **Beta−** | Domain facade pattern real and propagated; zero cross-domain imports (enforced via integration traits); mdns-sd worker-thread isolation. Held back by: triple-orchestrator duplication (main.rs / windows.rs / koi-embedded) with behavioral divergence; koi-common turned into a presentation host (axum + 60KB HTML in the "shared kernel"). |
| Code quality (established paths) | **Beta** | 1 production unwrap across 15 crates; consistent spawn_blocking hygiene; Zeroizing on secrets; exhaustive error-mapping tests; thiserror→ErrorCode→HTTP discipline. |
| Functional verification | **Feasibility** | TLS proxy panics at startup, silently, since the axum 0.8 upgrade; status hardcodes `running: true`; browse concurrency semantics structurally false vs mdns-sd reality; Windows service materially weaker than `koi --daemon`; risk-inverted test pyramid (certmesh 264 tests; proxy data plane 0). |
| Security engineering | **Alpha+** | Real: envelope encryption, X25519 CA transfer, DAT constant-time auth, loopback bind, mTLS plane, executed 87-finding overhaul in one week. Open: LAN-sourced XSS on the dashboard origin (quote-escaping + `javascript:` URLs), unauthenticated GETs exposing CA roster/audit to any local process, `--endpoint` token confusion, echoing passphrase prompts, revocation that doesn't actually revoke (roster-only, no CRL/OCSP), no cargo-audit/SECURITY.md. |
| Documentation | **Alpha (bimodal)** | Volume and prose are production-grade; accuracy is bimodal per document. The primary onboarding path (README curl → 401; CONTAINERS.md → connection refused) describes the pre-2026-03-18 product. Reference docs contradict code (Ed25519 vs P-256, 90 vs 30 days, factory-reset "not implemented" vs shipped). Meta-docs (prior-art, archive, proposals) outweigh user docs 5:1. |
| Release & operations | **Prototype (decayed)** | Release-shaped automation nobody watches: publish silently broken since Feb (no pipefail; 3 crates missing from list; `cargo install koi-net` = 4-month-stale trap); QA cron red for 10+ weeks (deleted scripts); releases on every push with mutable tags; timestamp versioning carries no compatibility semantics; no CHANGELOG/MSRV check/signing/packaging. |
| UX (CLI + dashboard) | **Beta− / Alpha** | CLI discoverability genuinely excellent (catalog, `cmd?` help-query, graceful terminal degradation, platform service management). Dashboard/mDNS browser visually polished and useful — but read-only, XSS-vulnerable, and the command manifest has seven user-visible drift bugs with zero tests. |
| DX (API + embedding) | **Alpha** | OpenAPI + Scalar strong; koi-embedded's builder/handle concept is the right idea, but both consumer-facing READMEs contain non-compiling examples, remote mode silently degrades, koi-client is typed for mDNS only, hickory types leak. |
| Community readiness | **Pre-launch** | 0 stars, 0 issues, stale repo description, broken install path, no SECURITY.md/CoC/templates. (Not a criticism — it has never been launched — but the release machinery pretends otherwise.) |

**Overall placement: late Feasibility / early Alpha** — with pockets of genuine Beta
(mDNS registry, certmesh core loop, CLI surface design, CI hygiene) and the *process
trappings* of a much older project. The defining gap is not craft; it is **verification
of the actual product promises** and **honesty of the surrounding claims**.

---

## 4. Verified critical defects

Full evidence in [findings/verification-2026-06.md](findings/verification-2026-06.md).

| # | Defect | Severity |
|---|---|---|
| 1 | koi-proxy panics at listener start (`/*path` under axum 0.8.8), inside `tokio::spawn`, invisibly; `status()` hardcodes `running: true`; second panic in cert-watch callback. TLS termination has plausibly never worked. | Critical |
| 2 | HTTP adapter binds 127.0.0.1 only; CONTAINERS.md promises 0.0.0.0 + bridge-gateway access; no bind flag exists. Headline container story broken on native Linux Docker. | Critical |
| 3 | All non-GET endpoints require `x-koi-token`; README/CONTAINERS/http-api.md show tokenless POSTs; http-api.md never mentions auth. Every documented write example 401s. | High |
| 4 | crates.io publish silently broken (no pipefail → dead error handler; koi-udp/koi-runtime/command-surface missing from publish list). koi-net stale at Feb-12; `cargo install koi-net` is a trap. | High |
| 5 | Windows service (`koi install`) never spawns the runtime orchestrator or certmesh renewal/roster/failover tasks — duplicated wiring drifted. | High |
| 6 | mDNS browse facade hands out "independent" handles, but mdns-sd keeps one querier per type: concurrent discovers kill each other; `resolve()` kills subscribers; dashboard cache degrades permanently. | High |
| 7 | mDNS browser page: LAN-attacker XSS via unescaped quotes into HTML attributes + `javascript:` launch URLs; dashboard origin can read CA roster/audit via unauthenticated GETs. | High |
| 8 | qa.yml invokes shell scripts deleted in February; weekly QA red ever since, unnoticed. | Medium |
| 9 | surface.rs manifest drift (`rotate-totp` vs `rotate-auth`, five nonexistent flags, false factory-reset claims), zero tests. | Medium |
| 10 | `--endpoint` → empty token (mutations fail); certmesh sends the *local* token to *remote* endpoints. No `--token`/`KOI_TOKEN` escape hatch. | Medium |
| 11 | ADR-012 falsely records that cross-domain imports "never existed" (git proves they did, removed in aa979d4); ADRs 001–010 carry invented pre-repo dates with no retrospective marker. | Medium (integrity) |
| 12 | Reference docs contradict code: Ed25519 vs ECDSA P-256, 90-day vs 30-day certs, factory-reset "not yet implemented" vs shipped, architecture.md sizes off 4×, README MSRV 1.75 vs 1.92. | Medium |

---

## 5. Strengths — what to protect

1. **The integration thesis is real and unclaimed in the market.** Discovery → naming →
   trust → serving as one coherent pipeline, label-driven from container metadata. The
   2026 landscape research found no cross-platform open-source equivalent
   ([research/landscape-2026.md](research/landscape-2026.md) §5).
2. **The mDNS beachhead is genuinely defensible.** Avahi is semi-maintained and
   Linux-only; Bonjour-for-Windows is dead; systemd-resolved's mDNS is documented-flaky;
   every language reimplements mDNS in-process and then hits the container multicast
   wall. A cross-platform daemon with HTTP register/browse/resolve + leases has no
   incumbent.
3. **The lease/lifecycle engine** (session/heartbeat/permanent, ALIVE→DRAINING→EXPIRED,
   transport-adaptive defaults) is elegant, faithfully implements its design doc, and is
   the best-tested code in the project. The IPC session-drop → grace → unregister
   semantics are the cleanest container-lifecycle story in the product.
4. **Certmesh's core loop is a killer homelab feature**: create CA → TOTP join → trusted
   certs → auto-renew → OS truststore install. No incumbent combines enrollment auth +
   truststore install + mesh roster (mkcert is dead-simple but manual and unmaintained;
   step-ca is operationally heavy). koi-truststore (306 lines) is a model small crate.
5. **Structural discipline scaled.** The domain facade template propagated cleanly to
   five sibling crates; cross-domain access goes through injection traits; the
   orchestrator is a single, well-designed bridging point (orchestrator.rs, 458 lines).
6. **Real security engineering exists** where it was aimed: envelope encryption with slot
   tables, X25519 ephemeral CA transfer, no-shell validated reload hooks, constant-time
   token comparison, an 87-finding self-audit executed within a week.
7. **Process artifacts of unusual quality**: ADR corpus with honest reversals and
   negative-consequences sections; an executed consolidation roadmap with commit hashes;
   the `.agentic/` tool-agnostic AI context concept; the three-voice documentation
   taxonomy; defensive publications as an open-source IP stance.
8. **CLI discoverability design** (catalog with live status, `koi <cmd>?` detail pages,
   graceful terminal degradation, polished cross-platform service install) is a genuine
   differentiator worth keeping through any consolidation.

---

## 6. The lean-architecture plan: less but more meaningful parts

The guiding test for every component: *does it serve the pipeline — discover → name →
trust → serve — for the declared audience?* Three tiers emerge.

### Tier 1 — Core identity (keep, invest)

| Component | Action |
|---|---|
| koi-mdns | Keep. Fix the browse-multiplexing bug (one real browse per type, refcounted fan-out) — the highest-value structural fix in the project; restores the facade's promise and fixes resolve/dashboard interference. Restore the single-import rule (move handle internals into daemon.rs) or amend the rule. |
| koi-dns | Keep. The mDNS→DNS alias bridge, certmesh SAN feedback, and three-source resolution are the most differentiated logic outside certmesh. Add caching (currently stats a file and rebuilds the full snapshot per query). |
| certmesh core loop | Keep: create/join(TOTP)/renew/truststore/backup/manual-promotion. This is the product's claimed invention; protect it. |
| koi-runtime + orchestrator | Keep — it is the thesis demonstrator ("label a container, get everything for free"). Delete the Systemd/Incus/Kubernetes stub variants (honest two-variant enum); wire or remove the parsed-but-unconsumed `health_kind`/`certmesh` labels; implement Docker reconnect (currently a daemon restart permanently kills the capability). |
| koi-truststore, koi-config, koi-common (slimmed) | Keep. Return koi-common to a types-only kernel (see move 4). |

### Tier 2 — Supporting cast (keep, but demote/reshape)

| Component | Action |
|---|---|
| koi-proxy | **Rewrite, smaller.** Replace the broken axum/reqwest HTTP forwarder (~210 lines, panics, no WebSockets) with a rustls TCP/TLS passthrough using `copy_bidirectional` (~200 lines) — fixes both panics and the WebSocket gap simultaneously. Position as "the pre-wired TLS endpoint for certmesh certs," never as a Caddy/Traefik competitor. |
| koi-health | **Shrink.** Machine-health is a re-projection of mDNS+certmesh data the daemon already holds — fold it into status/dashboard. Keep only the service-checker (~220 lines), made concurrent. A domain crate is more structure than this needs. |
| koi-udp | Keep (it is well-made, cheap, and has the best integration suite) but **re-label honestly**: it is the container-bridging edge case and zen-garden substrate, not a peer pillar. Fix the token topology (child token, so `shutdown()` can't kill the daemon). |
| Dashboard + mDNS browser | Keep — the browser is the strongest UX artifact. Fix the XSS (quote-escaping or DOM construction; http/https allowlist on launch URLs). Move both out of koi-common into a `koi-dashboard` presentation crate. Make the always-on LAN-wide meta-browse lazy or opt-in. Freeze KOI-0002's open-ended phases. |
| koi-embedded | Keep the concept — embedding is the differentiator of the single-binary philosophy — but make it **the** orchestrator (see move 1). |
| koi-client | Keep. Put it on a types diet (move needed protocol types into koi-common; drop koi-mdns/koi-health deps so the "lightweight blocking client" claim becomes true); give it typed responses beyond mDNS. |

### Tier 3 — Shed list

| Item | Rationale | ~LOC freed |
|---|---|---|
| wordlist.rs as Rust const | `include_str!` + LazyLock parse, or the eff-wordlist crate. Zero functional cost. | 7,700 |
| FIDO2 (all three layers) | CLI hard-bails; slot marked insecure; rotate rejects it; zero external callers; redesign blocked on ecosystem maturity. The AuthAdapter trait makes re-adding cheap. Delete, don't quarantine. | ~500+ |
| Automatic CA failover machinery | Keep the X25519 manual `promote` (good crypto); drop the mDNS absence-watcher, lexicographic tiebreakers, and roster-sync loops. With 30-day certs, a dead CA means "renewals pause," not an outage. Largest block of plausibly never-exercised code. | ~800 |
| Compliance endpoint + CLI | Echoes the policy block (already in /status) plus an audit line count (already in /log). | ~100 |
| Trust-profile indirection | `cert_lifetime_days()` returns 30 for all profiles; "custom" reduces to two booleans. Expose the booleans. | ~150 |
| command-surface as a crate | Fold the used subset into the binary as a concrete module; delete generics, dead Confirmation/by_tag/by_scope/write_summary_catalog. Keep the rendered output (it's good). | ~400–600 |
| Pipe/NDJSON IPC adapter | Covers 1 of 8 domains, zero first-party consumers, one socat one-liner of documented use. Retire pipe.rs + cli.rs + dispatch coupling; preserve the session-lease semantics via an HTTP/SSE-connected registration. (If NDJSON is kept, commit to it across domains — the half-state is the worst position.) | ~430 |
| PipelineResponse status machinery | Zero production callers; contradicts published API docs. | ~60 + docs |
| Dead code inventory | `load_entries_with_certmesh`, `DnsCore.started_at`, `DnsZone::fqdn_suffix`, broadcast-channel self-tests ×3, stale `#[allow(dead_code)]`s, KoiScope::Internal. | ~300 |
| docs/prior-art + docs/archive out of main repo | 10.6k lines, 50% of docs/ volume, 0% user value. Separate archive repo or release artifact. | (docs) |
| .agentic/reference/* | Hand-maintained copies of docs/reference that have drifted from code AND from each other. Keep `.agentic/` for rules; link to docs/reference as the single inventory source. | (docs) |

### The five structural moves (in order of leverage)

1. **One orchestrator.** Make `crates/koi` a thin CLI/service shell over koi-embedded's
   composition (or extract a shared `koi-compose` layer). This single move deletes
   ~800–1,000 duplicated lines across main.rs / platform/windows.rs / koi-embedded,
   **fixes the Windows-service drift by construction**, collapses the four
   capability-status ladders and three event-forwarder copies, and makes main.rs honest
   about its "zero business logic" rule (the certmesh background tasks move into
   koi-certmesh behind a `spawn_background_tasks()` API).
2. **Certmesh diet** (Tier 3 items above): 18.6k → ~8–9k real LOC while keeping the killer
   loop intact. Move CA-creation orchestration out of the 230-line HTTP handler into
   `CertmeshCore::create()` (the project's own facade rule); split the 756-line
   `eval_init`; one `persist_roster()` helper for the ~12 copy-pasted blocks; unify the
   duplicated HOOK_FORBIDDEN validators. Consider extracting koi-crypto (+truststore) as a
   standalone repo later — the defensive publication already positions the slot-table
   design as independent work — but only after the diet.
3. **Manifest truth.** Either generate surface.rs from clap metadata or add a conformance
   test (every CommandDef name must round-trip through `Cli::try_parse_from`; every
   example must parse). The 1,931-line hand-written manifest with zero tests is a drift
   factory. |
4. **koi-common back to kernel.** Dashboard/browser/HTML move to a presentation crate;
   axum/async-stream/chrono/hostname leave every domain crate's transitive closure.
5. **Generic `DomainRuntime` + template extraction.** DnsRuntime and HealthRuntime are the
   same 80-line state machine; the paths/routes/error-map template is 5× copy-paste that
   already drifted. One shared implementation standardizes every future domain and cuts
   the measured per-domain tax (~65–75% of ~1,200 lines is scaffolding).

**Net effect:** ~57.7k → roughly **40k LOC**, 15 crates → **9–10**, three orchestrators →
one, four status ladders → one, with zero loss of the product's actual value. Every
remaining part earns its place.

---

## 7. Strategic opportunities (and what to shed strategically)

Full evidence: [research/landscape-2026.md](research/landscape-2026.md) and
[research/trends-opportunities-2026.md](research/trends-opportunities-2026.md).
Opportunities 6–14 — the collaboration/integration strategy (ACME facade, DNS sync
engine, OS-resolver adoption, tailnet coexistence, observability feeds, proxy
collaboration, Home Assistant channel, generic truststore, Proxmox-over-k8s) — are
developed in [research/collaboration-strategy-2026.md](research/collaboration-strategy-2026.md).

### Where Koi is uniquely positioned (priority order)

1. **MCP / agentic-AI substrate — strongest, cheapest, emptiest niche.** Local MCP
   discovery is unsolved (projects port-scan localhost; one weak Python incumbent);
   agents have a concrete "where is the service, can I trust it" problem; the MCP spec
   itself mandates DNS-rebinding protections that named, TLS-trusted local endpoints
   directly address. A `koi-mcp` surface is a thin wrapper over the existing HTTP API,
   and Koi can both *be* discoverable (`_mcp._tcp`) and *make other MCP servers
   discoverable* — LAN-level MCP infrastructure before any convention standardizes.
2. **The dev-loop golden path — "OrbStack domains, open and cross-platform."** Label a
   container → name + trusted cert + proxy + health, visible to every device on the LAN.
   OrbStack proved the demand and is macOS-only/proprietary; localias proved the
   tool-shape demand. This is also the demo that makes #1 legible. Requires fixing
   defects #1/#2/#3 first — the golden path currently 401s, can't be reached from
   containers, and terminates TLS in a crate that panics.
3. **The r/selfhosted consolidation story.** The #1 homelab pain is exactly Koi's
   domain (DNS + reverse proxy + certificate triangle). "One binary replaces five
   containers," Windows-native (genuinely underserved), with root-CA trust UX
   (koi-truststore) as the make-or-break review detail. Ship a first-class container
   image — the audience runs everything in containers regardless of the single-binary
   philosophy.
4. **"The easy button for `.internal`."** ICANN reserved `.internal` (2024); public CAs
   are forbidden from issuing for it; Let's Encrypt's new IP certs categorically exclude
   RFC1918. Private CA + local DNS + truststore is the *only* path to warning-free TLS on
   the new sanctioned private TLD — and that is precisely Koi's certmesh+dns+truststore
   trio. Mostly a positioning/docs play.
5. **IoT/Matter diagnostics (opportunistic).** The mDNS browser + known-type annotations
   (`_matterc._udp`, `_hap._tcp`, `_esphomelib._tcp`) + a commissioning-debug guide =
   cheap entry into the Home Assistant community. Documentation and presentation work
   only.

### Strategic shed list (do NOT chase)

Agent frameworks and MCP gateways/registries · ad-blocking DNS (Pi-hole/AdGuard own it) ·
reverse-proxy feature parity with Caddy/Traefik · tunneling/public ingress
(ngrok/Cloudflare/Pangolin) · overlay networking (Tailscale/NetBird) · Matter controller
ambitions · mDNS reflection across VLANs · service meshes/SPIFFE · enterprise
PKI/compliance (the existing compliance endpoint is the first step down this road —
delete it) · dashboards-as-product. Koi wins by being the boring, trustworthy layer
underneath all of these.

### Honest headwinds

Tailscale's gravity well ("install Tailscale, use ts.net certs" is good enough for many,
and Tailscale Services moves into service naming); PKI trust is reputation-bound and
certmesh's sophistication currently exceeds what a young project can ask users to trust;
the unmanaged-device root-install problem (phones, TVs) is unsolved for everyone,
including Koi — never market around it.

---

## 8. Staged maturation roadmap

> Execution note: each stage below is operationalized as self-contained agentic
> session prompts in [docs/prompts/](../prompts/README.md) (P01–P13), with the shared
> DX charter at [docs/prompts/CHARTER.md](../prompts/CHARTER.md).

### Stage 0 — Truth restoration (days; no design decisions required)

The cheapest, highest-integrity-yield work. A project whose docs, CI, and metadata tell
the truth can be assessed, contributed to, and trusted.

- Fix CONTAINERS.md/README against the loopback+token reality, or add `--http-bind` +
  token guidance and make the docs true that way (decide in Stage 1; until then,
  quarantine the broken examples with a banner).
- Write the single **"Networking & security model"** page (bind addresses, DAT lifecycle,
  CORS, mTLS port, threat model) and make README/GUIDE/CONTAINERS/http-api reference it.
- Fix qa.yml (point at the .ps1 scripts or delete the dead jobs); add `set -o pipefail` +
  the three missing crates to release.yml, or suspend publishing entirely until launch.
- Mark ADRs 001–010 "retrospectively documented 2026-02-15"; correct ADR-012 Block 4 to
  cite aa979d4; set ADR-011 to Implemented; archive the executed plan doc; fix the
  duplicate §7.7.
- Reconcile or delete contradicted rules (CONTRIBUTING's 300-line rule, the v2.0.0 spec
  strings, MSRV 1.75 claim, factory-reset "not implemented", Ed25519/90-day claims).
- Add a status banner to README: what Koi is (feasibility-validated), what state it's in,
  what's next. The momentum cliff is fine; pretending it isn't happening is not.

### Stage 1 — Make the promise true (1–2 weeks)

Fix the five product-breaking defects, in user-impact order:

1. Container reachability: `--http-bind` flag (default loopback; opt-in 0.0.0.0 or
   bridge-IP with DAT required) + a documented container token-distribution recipe.
2. koi-proxy: the ~200-line rustls passthrough rewrite (or, minimally: `/{*path}`, runtime
   Handle into the notify callback, real liveness in `status()`, one TLS integration test).
3. mDNS browse multiplexing (refcounted single browse per type).
4. Windows service parity — falls out of the one-orchestrator move; do at least the
   orchestrator+certmesh-task calls immediately if consolidation waits.
5. Dashboard XSS fixes + `--token`/`KOI_TOKEN` for explicit endpoints.

### Stage 2 — Consolidation (2–4 weeks)

The §6 program: one orchestrator → certmesh diet → manifest conformance → koi-common
kernel restoration → DomainRuntime/template extraction → Tier-3 shed list. Each move is
independently mergeable; sequence as listed (the orchestrator unification unlocks the
rest).

### Stage 3 — Hardening (2–3 weeks, overlapping Stage 2)

- Convert the HTTP-level slice of integration.ps1 into Rust integration tests that run on
  all three OSes in the existing CI matrix; keep PowerShell only for Windows SCM Tier-3.
- One real behavioral test per domain (the current broadcast-channel self-tests test
  tokio, not Koi); a TLS-termination test; a Docker-reconnect test.
- cargo-audit/cargo-deny + MSRV check + Dependabot; SECURITY.md.
- Re-audit the certmesh attack surface post-diet (revocation semantics documented
  honestly; unauthenticated-GET exposure decision).

### Stage 4 — Launch (when 0–3 are done)

- SemVer reset (0.3.0), CHANGELOG, tag-triggered releases (no more mutable tags),
  fixed publish list or binary-only publishing.
- Packaging: winget/scoop/brew + a first-class container image + compose snippet.
- The koi-mcp surface (strategic priority #1) and registry listings.
- Comparison docs (vs Avahi/Bonjour, vs mkcert/step-ca, vs NPM+Pi-hole stack) and the
  r/selfhosted + selfh.st launch posts, leading with the dev-loop golden path demo.

---

## 9. Closing judgment

As a **feasibility test of a usage philosophy**, Koi is a success and the experiment's
artifacts are worth keeping — the boundary model held, the composition loop works, the
agentic-development process produced real engineering at remarkable velocity, and the
market position it stumbled into is more defensible than the original mDNS framing
suggested.

As **software claiming to be what its README describes**, it is not yet honest: the four
most user-visible promises (containers over HTTP, TLS termination, Windows service
parity, `cargo install`) are all broken in the current tree, while the surrounding
machinery projects a maturity the verification loops don't back.

The path to "clean, lean architecture — less but more meaningful parts" is therefore
mostly *subtraction and truth-telling*, not construction: one orchestrator instead of
three, ~40k honest lines instead of 57.7k aspirational ones, nine crates that each earn
their place, docs that describe the shipped binary, and automation that someone actually
watches. The strategic window (MCP substrate, OrbStack-for-everyone, `.internal`) rewards
exactly that shape: a small, trustworthy, boring layer that other things build on.

---

*Assessment corpus: [findings/](findings/) (10 subsystem deep-reads + verification
record), [research/](research/) (landscape + trends). Method: multi-agent staged
assessment with adversarial verification; all severity-rated claims independently
re-derived from source before inclusion.*
