# Documentation Coverage Audit — 2026-06-22

> Capability-by-capability map of what Koi **does** vs. what the docs **cover**, across
> three doctypes: **card** (one-screen `docs/reference/cards/`), **how-to** (guide / recipe /
> tutorial), and **reference** (`docs/reference/*.md` + `.agentic/reference/`). Produced by a
> 6-agent audit (5 capability-cluster readers + 1 completeness critic) against the live code.
> This file is the working gap-tracker; check items off as the doc waves land.

## Coverage at a glance

- **33 capabilities** mapped across 5 clusters; the critic surfaced 9 more surfaces/gaps.
- **Cards: 2 of ~33** (`internal-zone`, `certmesh-invite`) — and both are *orphaned* (no
  `cards/` index, not linked from `docs/index.md`).
- **How-tos: broad** (20 guides + 2 recipes; no capability is wholly undocumented) but with
  specific holes + stale guides.
- **Reference: ~8 stale/wrong spots**, including one outright wrong value (cert validity).

## Reference truth-debt (Wave 1 — correctness)

| Doc | Fix |
|---|---|
| `docs/reference/cli.md` | add `--dns-qps`/`KOI_DNS_QPS`; add proxy `--backend-remote`; correct `acme enable` wording (prints the directory, doesn't "open the server"); add install-script env vars (`KOI_VERSION`/`KOI_INSTALL_DIR`/`KOI_NO_MODIFY_PATH`) + `KOI_DATA_DIR`; deepen `factory-reset` (destructive — add a warning) |
| `docs/reference/security-model.md` | GET-auth section is stale: enumerate per-method-authed surfaces (`/v1/udp/*`, `/v1/certmesh/log`) and the loopback-vs-remote-peer split for `diagnose` + `dns/{list,zone,entries}` (b1); add per-client DNS rate limiting; add the supply-chain/attestation story |
| `docs/reference/http-api.md` + `.agentic/reference/api-endpoints.md` | the GET-exemption header omits the b1 peer-gate on `diagnose` + `dns/{list,zone,entries}` |
| `docs/reference/envelope-encryption.md` | **wrong value**: "30 days" member validity → real default is **90/30/14** (`roster.rs`); mark FIDO2 "not yet shipped" |
| `docs/guides/dns.md` + `docs/guides/dns-coexistence.md` | document per-client rate limit + `--dns-qps`; flag that `curl …/v1/dns/zone` now needs `x-koi-token` from a **remote** host |
| `docs/tutorials/getting-started.md` | stale: still manual download + `tar`/`mv` — lead with the `install.sh`/`install.ps1` one-liner |
| `docs/guides/install-and-service.md` | add the install one-liners up front (currently assumes `koi` already on PATH) |
| `CONTAINERS.md` | omits the published GHCR image; the k8s example uses a `your-registry/koi` placeholder → use `ghcr.io/sylin-org/koi` + add a "run the image" section |
| `docs/guides/embedded.md` | stale: document `http_port(0)`/`bound_http_port()`, secure-by-default `InsecureConfig` fail-closed, `participate()`/`serve_adaptive`, `testkit`; fix the "no DAT gate" claim (untrue once `http_token()` set) |
| `docs/guides/health.md` | documents only service checks — add **machine health** (`machines[]`, cert-expiry, staleness/warnings) |
| `docs/reference/cards/internal-zone.md` | add the per-client rate-limit note; bump validation date |

## How-to gaps (Wave 3)

- **mDNS LAN browsing** (`/mdns-browser`, `/v1/mdns/browser/*`, lazy meta-browse) — no how-to.
- **ADR-020 trust-plane primitives** (sign/verify Envelope, seal/open, `watch_posture`, typed
  `Peer`, `participate()`) — flagship feature, no developer how-to (only the wire spec).
- **Install scripts / GHCR / provenance** — live only in README; need durable homes.
- **`koi factory-reset`** — destructive wipe with zero doc depth (one cli.md line); needs a
  safety doc.

## Cards (Wave 2)

The card doctype is **structurally un-adopted**: 2 of ~33 capabilities, no `cards/` index/landing,
and the two that exist are not linked from `docs/index.md`. Author cards for the flagship
capabilities, add an index, and wire everything into the docs landing. Priority card candidates:
**trust-plane/posture, runtime label-magic, proxy, health, MCP, install + verify (supply chain),
mDNS service ops, certmesh CA lifecycle, ACME, UDP bridging, embedded**.

## Systemic gaps (critic — Wave 3)

- **No "is it for me" / overview / concepts doc** — the Diataxis explanation quadrant is empty.
- **No unified ports & firewall reference** (5641 HTTP / 5642 mTLS / 5643 ACME / 53 DNS + proxy
  listen ports are scattered across security-model/system/acme/cli).
- **Thin tutorials** (2 total) relative to 22 guides — no AI-agent, container, or name-your-LAN
  tutorial.
- Under-documented flags: `--announce-http`/`KOI_ANNOUNCE_HTTP`, `--mtls-port`, `KOI_DATA_DIR`.

## Wave plan

- [ ] **Wave 1** — reference truth-pass (the table above).
- [ ] **Wave 2** — capability cards + `cards/` index + `docs/index.md` wiring.
- [ ] **Wave 3** — net-new how-tos + systemic docs (overview, ports/firewall, factory-reset
      safety, mDNS-browsing, container-image, provenance/supply-chain).

## Per-capability matrix (the tracker)

Legend: card / how-to / reference = path or `—` (missing); `!` = present but stale/wrong.

| Capability | Card | How-to | Reference | Pri |
|---|---|---|---|---|
| mDNS service ops (discover/announce/resolve/subscribe/admin/leases) | — | guides/mdns.md | cli/http-api/wire-protocol ✓ | med |
| mDNS LAN browsing (/mdns-browser, meta-browse) | — | — | http-api/architecture ✓ | med |
| DNS resolver core (.internal, serve/lookup/add/list, zone export) | internal-zone ! | guides/dns.md | cli ! (no --dns-qps), http-api/security-model ! (b1) | **high** |
| mDNS→DNS alias bridge | — | guides/dns.md | http-api/architecture ✓ | low |
| DNS coexistence + zone export | — | guides/dns-coexistence.md | http-api ! (zone curl now token-gated remote) | med |
| Certmesh CA lifecycle (create/status/unlock/log/enrollment/rotate-auth/destroy) | — | guides/certmesh.md, tutorials/trusted-https | cli/http-api/ceremony ✓ (security-model ! on log gate) | med |
| Certmesh enrollment (join/invite/member-csr/member-cert) | certmesh-invite ✓ | guides/certmesh.md, tutorials/trusted-https | http-api/cli/trust-protocol ✓ (certmesh.md table omits member-csr/cert) | low |
| Certmesh diagnose (trust-doctor) + trust-bundle | — | partial (certmesh.md, trust.md) | http-api/trust-protocol ✓ (http-api ! omits diagnose peer-gate) | med |
| Certmesh renewal/set-hook/promote/revoke/backup/restore (HA) | — | guides/certmesh-ha-recovery.md, certmesh.md | cli/http-api ✓ | low |
| koi trust (OS trust-store install/list/remove/export + diagnose) | — | guides/trust.md, recipes/container-trusted-cert, tutorials/trusted-https | guide-as-reference + cli ✓ | low |
| ACME RFC 8555 facade (dns-01) | — | guides/acme.md | http-api ✓, cli ! ("open the server" wording) | med |
| Envelope encryption + unlock slots | — | guides/certmesh.md | envelope-encryption.md ! (30d wrong; FIDO2 unclear) | med |
| ADR-020 posture / trust-plane primitives | — | — | trust-protocol.md ✓ (excellent) | **high** |
| proxy (TLS passthrough) | — | guides/proxy.md | http-api/architecture ✓, cli ! (no --backend-remote) | med |
| UDP bridging for containers | — | guides/udp.md, recipes/container-udp | http-api/cli/architecture ✓ | low |
| runtime adapter (Docker/Podman + label ingestion) | — | guides/runtime.md, integrations.md | http-api/cli/architecture ✓ | med |
| health checks (HTTP/TCP, machine + service) | — | guides/health.md ! (no machine health) | http-api/cli/architecture ✓ | med |
| HTTP/OpenAPI API + /docs + /openapi.json | — | guides/api-authentication.md | http-api ! (b1) | med |
| GET /v1/sd/prometheus | — | guides/integrations.md | http-api ✓ | low |
| MCP (stdio + /v1/mcp + _mcp._tcp + server-card) | — | guides/mcp.md | http-api/cli ✓ | med |
| Transports — IPC + piped stdio NDJSON | — | cli.md inline | wire-protocol/api-endpoints ✓ | low |
| Embedded dashboard + browser + /v1/dashboard/* | — | tutorials/getting-started step 4 | http-api/system ✓ (Lantern/Vellum codename) | med |
| Unified koi status + /v1/status + /v1/host | — | guides/system.md | http-api ✓ (example omits new fields) | low |
| koi token show/write (DAT) | — | guides/api-authentication.md | security-model/cli ✓ (security-model ! carve-outs) | med |
| koi install/uninstall (OS service + firewall) | — | guides/install-and-service.md ! (no one-liner) | cli ✓ | low |
| koi launch | — | tutorials/getting-started | cli ✓ | low |
| koi-embedded library | — | guides/embedded.md ! (missing http_port0/secure-default/participate/testkit) | rustdoc only | **high** |
| Install scripts (install.sh/install.ps1) | — | — (README only) | cli ! (no env vars) | **high** |
| Published GHCR image | — | CONTAINERS.md ! (omits the image) | — | **high** |
| Signed provenance / attestations + SBOM | — | — (README + release-template only) | — | **high** |
| Release pipeline (tag → archives/checksums/Release/crates.io/container) | — | — | — (workflows only) | med |
| Never-silent installer onboarding | — | — | — (scripts only) | med |
| **koi factory-reset (destructive wipe)** — *critic-found, readers missed* | — | — | cli.md one-liner only | **high** |

---

*Audit run wf_c0f65a46-e5c (6 agents, 33 capabilities). Code citations in the source records;
key proof: `crates/koi-serve/src/http.rs:621-687` (b1 auth carve-outs), `crates/koi/src/cli.rs`
(full CLI surface), `crates/koi-certmesh/src/roster.rs:46-55` (90/30/14 cert policy).*
