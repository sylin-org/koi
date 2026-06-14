# Surface Ledger

> **Rotation contract.** Before the lane leaves this repo or surface: tag; CI green;
> a tripwire exists for every surface the departing work was exercising; status
> endpoints tell the truth; this ledger is updated. Leave a guard at the door when
> you leave the room.

This is the mechanical memory behind the maintainer's serial-lane model (Epic E02).
Each row records a pillar/plane-level **surface**, **who exercises it**, **when it was
last exercised**, and **what guard protects it**. When the focus lane rotates away,
unguarded surfaces rot silently — the ledger turns that from a discovered fiction into
a known risk.

The motivating incident lives in this repo: the TLS **proxy** worked, regressed silently
at the axum 0.8 upgrade while nothing was exercising it, and `status()` kept reporting
`running: true` for months. Its row below reads **guard = none** — the truth, until
proxy work (E08+) changes it.

**Columns.** `Exercised by` ∈ {a named in-repo test/sample suite, `zen-garden`, `koan`,
`private downstream solution`, `none`}. `Guard` ∈ {test/CI job name, `none`}.
`Last exercised` is a real date (`YYYY-MM-DD`) or `unknown since <date>` — never a
guessed "works".

**Honesty notes for this repo.**
- **Dates** are seeded from `git log -1 --format=%as <paths>`.
- **CI exists** (`.github/workflows/ci.yml`: 3-OS build + test + clippy + fmt + MSRV +
  audit). Guards naming a domain suite run there. A `surfaces` job in that workflow lints
  *this ledger* (it does not run the domain suites).
- The **HKDF domain-separation byte strings** in `crates/koi-crypto/src/unlock_slots.rs`
  are **frozen** (STACK-0001 K3) — never renamed.

| Surface | Exercised by | Last exercised | Guard | Notes |
|---|---|---|---|---|
| mdns | koi-mdns suite | 2026-03-25 | koi-mdns tests (ci.yml) | Browse-multiplexing bug known (one querier per type kills concurrent browses) |
| dns | koi-dns suite | 2026-05-10 | koi-dns tests (ci.yml) | mDNS-to-DNS alias bridge; needs query caching |
| certmesh (CA / enroll / roster / renew) | koi-certmesh suite (264 tests) | 2026-06-12 | koi-certmesh tests (ci.yml) | The claimed invention; revocation is roster-only (no CRL/OCSP) |
| crypto (envelope enc / TOTP / auth) | koi-crypto suite | 2026-03-25 | koi-crypto tests (ci.yml) | HKDF domain-separation byte strings are FROZEN (STACK-0001 K3) |
| truststore | koi-truststore suite | 2026-03-20 | koi-truststore tests (ci.yml) | Platform cert install; a model small crate |
| proxy (TLS reverse proxy) | none | unknown since 2026-03-25 | none | Panics at axum-0.8 listener start; status() hardcodes running:true; data-plane 0 tests; outside all contracts until tested (STACK-0001) |
| udp (datagram bridging) | zen-garden | 2026-03-20 | koi-udp tests (ci.yml) | Exists for the zen-garden Garden-mesh substrate; token-topology fix pending |
| token / DAT auth | private downstream solution / in-flight | unknown since 2026-03-25 | none | DAT constant-time auth; in-flight downstream work, not inspected (CHARTER rule 8) |
| runtime / orchestrator (Docker/Podman) | koi-runtime suite | 2026-03-26 | koi-runtime tests (ci.yml) | Docker reconnect unimplemented; daemon restart kills the capability |
| health | koi-health suite | 2026-03-25 | koi-health tests (ci.yml) | Service + machine health; shrink candidate |
| config | koi-config suite | 2026-03-25 | koi-config tests (ci.yml) | Breadcrumb discovery |
| dashboard + mDNS browser | koi-dashboard tests | 2026-06-13 | koi-dashboard tests (ci.yml) | XSS closed structurally (DOM render + http/https launch allowlist) + CSP header; lazy meta-browse; lives in koi-dashboard crate, not the koi-common kernel (P06) |
| CLI command manifest (surface.rs) | none | unknown since 2026-06-13 | none | Hand-written manifest; seven user-visible drift bugs; zero tests |
| embedded / client API | koi-embedded + koi-client | 2026-05-10 | koi build (ci.yml); examples untested | Non-compiling README examples; remote mode degrades silently |

---

*Seeded by Epic E02 (2026-06-13). Every lane that touches a surface above updates its
row — `Last exercised` to today, `Guard` to the tripwire it left — before it leaves.*
