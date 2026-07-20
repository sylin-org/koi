Status: complete
Run ID: 20260719T034411Z
Project: koi
Target: F:\Replica\NAS\Files\repo\github\sylin-org\koi
Created: 2026-07-19T03:44:11Z
Verified at (UTC): 2026-07-19
Playbook version: 0.1.0

# Project profile

Labels in this profile have strict meanings: **Fact** is supported by repository or cited primary evidence; **Inference** is a synthesis of those facts; **Hypothesis** requires adoption evidence; **Owner choice** is a decision the maintainer must approve. No owner choice below is treated as approved merely because this analysis recommends it.

## Owner goal and non-goals

- **Fact:** Koi's declared product loop is **discover → name → trust → serve**: mDNS/DNS-SD discovery with leases, an automatically populated private DNS zone (`.internal` by default), a private CA with guided enrollment and OS trust-store installation, and TLS termination plus health checks. It is designed as one cross-platform binary with no account or cloud dependency and is intended to remain useful without internet access. Sources: [README](../../README.md), [overview](../../docs/overview.md).
- **Inference:** The coherent product is not any one of those components. It is the shared local service identity that lets one service record drive discovery, DNS, certificate issuance, health, serving, exports, and automation.
- **Owner choice — recommended, not approved:** Position Koi as a **local-first LAN service identity and control plane**. The plain-language promise is: **Koi turns services on a LAN into stable, trusted `.internal` names—automatically, offline, and without a cloud account.** “LAN service fabric” is acceptable shorthand, but public copy should explain the outcome before using a category label.
- **Fact:** Koi explicitly excludes public-internet/WAN edge routing, public certificates, enterprise-scale PKI or authoritative DNS, per-user accounts and RBAC, hostile local processes or tenants, and TLS-verifier-enforced real-time revocation. Its certificate revocation is roster/boundary enforcement; already issued leaf certificates remain valid until expiry because Koi distributes neither CRLs nor OCSP responses. Source: [overview: when not to use Koi](../../docs/overview.md#when-not-to-use-it).
- **Owner choice:** Do not market Koi as a VPN, public reverse proxy, zero-trust access product, enterprise PKI, or full service mesh. Those labels create expectations for reachability, identity policy, traffic enforcement, telemetry, HA, and multitenant controls outside the stated threat model.

## Primary user and triggering problem

- **Fact:** The declared users are homelabbers and self-hosters, developers on a LAN, small teams with a handful of machines, and container hosts whose bridge networks cannot carry multicast. Source: [overview: who it is for](../../docs/overview.md#who-its-for).
- **Inference:** The primary adopter is the person who owns and operates a trusted local network and can install software or configure DNS on its machines. In a homelab, user, administrator, and operator are usually the same person. In a small team, the likely adopter and ongoing steward is a developer-platform owner or IT generalist. Koi is open source; there is no buyer or sales role in this model.
- **Fact:** Adjacent official documentation validates the triggering friction. Bonjour exists because changing IP addresses otherwise force manual network configuration ([Apple Bonjour](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/NetServices/Introduction.html)); Docker Compose names are stable only inside the Compose network while container IPs change on recreation ([Docker networking](https://docs.docker.com/compose/how-tos/networking/)); and self-signed development certificates cause trust errors while `mkcert` still leaves server configuration to the operator ([mkcert](https://github.com/FiloSottile/mkcert)). External sources verified 2026-07-19 UTC.
- **Inference:** The triggering job is: **“A service is running locally, but other devices still need its current IP, port, DNS entry, and certificate setup before they can use it reliably and without browser warnings.”**
- **Hypothesis:** The highest-intent trigger is the transition from one host to several: a second container host, laptop, phone, VM, or lab machine makes `localhost`, bookmarks to IP addresses, and container-local DNS visibly insufficient.

## First successful outcome

- **Fact:** The repository offers a roughly one-minute visible-result tutorial and identifies **Trusted HTTPS across two machines** as the headline journey. Sources: [getting started](../../docs/tutorials/getting-started.md), [trusted HTTPS tutorial](../../docs/tutorials/trusted-https.md).
- **Owner choice:** Define first product success as: **from a second supported machine, the user opens a service by a stable `.internal` URL over HTTPS, receives the expected content without a certificate warning, and can see why it is healthy and trusted.** Discovery alone is activation evidence, but not the complete product promise.
- **Inference:** This outcome is stronger than a successful daemon start because it proves the entire cross-machine chain: service discovery or registration, local name resolution, enrollment and trust installation, certificate issuance, and TLS serving.
- **Hypothesis:** A reproducible first-success path under five minutes, with no public DNS or cloud sign-in, will outperform feature-led onboarding for the primary audience. The time claim must be measured on clean Windows, Linux, and macOS hosts before publication.
- **Owner choice:** The activation proof should capture elapsed time, operating systems, runtime type, whether DNS configuration was automatic or manual, whether trust installation needed elevation, and the first successful HTTPS request. Do not reduce activation to install-script completion.

## Primary and secondary archetypes

| Archetype | Classification | Job and environment | Why Koi fits | Boundary |
| --- | --- | --- | --- | --- |
| Homelab or self-hosting operator | **Primary — Fact/Inference** | Runs dashboards, media, automation, storage, and developer tools across a few machines and containers | Wants memorable browser-trusted local URLs without assembling and reconciling discovery, DNS, CA, proxy, and health systems | Koi does not provide WAN reachability, user SSO, or a public edge |
| LAN developer or small-team platform owner | **Primary — Fact/Inference** | Needs ephemeral services on laptops, VMs, and container hosts to be findable and trusted by teammates | Cross-platform daemon, HTTP/OpenAPI and CLI surfaces, runtime labels, ACME, exports, and an embeddable Rust API support gradual automation | Not a replacement for enterprise identity, policy, or HA infrastructure |
| Lab, classroom, workshop, studio, or disconnected edge-site operator | **Secondary — Hypothesis** | Controls a bounded network where internet access may be unreliable or disallowed | Account-free local operation and private naming/trust match the environment | Multi-subnet discovery, deployment administration, and support burden require field validation |
| Local appliance or developer-tool vendor | **Secondary — Hypothesis** | Wants a shipped application to become discoverable, named, and trusted with minimal host integration | `koi-embedded`, typed handles, optional heavy features, and standard protocols offer an integration path | Rust-first embedding and pre-1.0 API stability narrow the near-term market |
| Enterprise service-mesh or PKI team | **Excluded — Fact** | Requires workload attestation, fine-grained policy, HA, multitenancy, compliance, and active revocation | Koi may provide a local discovery edge or export | Consul, SPIRE, Istio, Smallstep, or equivalent systems own the core requirement |

## Maturity, support surface, and maintainer capacity

- **Fact:** The current release is v0.9.0. The project describes itself as pre-1.0, feasibility-validated, consolidating, subject to breaking changes, and not ready for load-bearing infrastructure. Source: [README: project status](../../README.md#project-status).
- **Fact:** The Rust 2021 workspace contains 17 crates, supports Rust 1.92+, and is dual-licensed Apache-2.0 OR MIT. The architecture separates domain cores from integration bridges and enforces domain independence with an architecture test. Sources: [workspace manifest](../../Cargo.toml), [architecture reference](../../docs/reference/architecture.md), [architecture test](../../crates/koi-common/tests/architecture.rs).
- **Fact:** The user-facing surface is broad for a pre-1.0 project: 63 CLI leaf commands, seven domain HTTP namespaces plus system endpoints, OpenAPI/docs, dashboard and browser UIs, IPC/stdio, MCP over stdio and Streamable HTTP, ACME, Prometheus HTTP service discovery, and embedded/client Rust APIs. Source: [surface ledger](../../docs/SURFACES.md).
- **Fact:** CI covers Windows, Linux, and macOS builds/tests plus formatting, linting, MSRV, audit, surface/documentation guards, and cross-host checks. Release automation produces six native targets, multi-architecture container images, checksums, SBOM/provenance artifacts, and crates.io publication. Sources: [CI workflow](../../.github/workflows/ci.yml), [QA workflow](../../.github/workflows/qa.yml), [release workflow](../../.github/workflows/release.yml), [publish workflow](../../.github/workflows/publish.yml).
- **Inference:** Engineering evidence is unusually deep for the release maturity, but the number of capabilities increases documentation, compatibility, support, and security obligations. A+ quality requires reducing surprise and sharpening the golden path more than adding surface area.
- **Fact:** The repository does not promise an SLA, paid support, or a maintainer response time. **Inference:** Adoption work must assume bounded maintainer capacity: asynchronous issue support, a small validated platform matrix, explicit non-goals, and no launch volume that depends on immediate high-touch onboarding.

## Installation, use, and evidence

- **Fact:** The indexed owned product page at [sylin.org/koi](https://sylin.org/koi) already leads with the bounded outcome “See what is running, give it a stable `.internal` name, and make it trusted—no accounts, no cloud,” gives `koi mdns discover` as the first useful command, distinguishes “reach for” from “choose something else,” and repeats the v0.9.0/pre-1.0 constraints. The GitHub repository's homepage metadata field was empty at verification time, so this strong owned page is not discoverable from the repository header. External page and repository metadata verified 2026-07-19 UTC.
- **Fact:** Supported acquisition paths are checksum-verifying shell and PowerShell installers, GitHub release archives, a multi-architecture GHCR image, `cargo install koi-net`, and source builds. Releases include supply-chain provenance verification instructions. Source: [README: installation](../../README.md#installation).
- **Fact:** Windows, Linux, and macOS use the same pure-Rust mDNS engine and install respectively as a Windows SCM service, systemd unit, or launchd service. The binary can run as daemon, standalone command, daemon client, or embedded Rust library. Sources: [README: platform support](../../README.md#platform-support), [overview: run modes](../../docs/overview.md#four-ways-to-run-it).
- **Fact:** Implemented interoperability surfaces include Docker/Podman lifecycle ingestion, selected Traefik and caddy-docker-proxy label parsing, DNS/hosts/dnsmasq export, a private experimental ACME facade, Prometheus HTTP-SD-shaped output, and 11 MCP tools plus four resources. These are implementation facts, not proof that every third-party workflow works end to end; the readiness audit records material gaps in the container, label, ACME, and Prometheus paths. Source: [README: works with your stack](../../README.md#works-with-your-stack), [surface ledger](../../docs/SURFACES.md), [readiness audit](readiness-audit.md).
- **Fact:** The repository contains extensive unit, integration, real-binary, cross-host, and trust-state-machine evidence, but its own documentation records important residuals including Docker event reconnect being unimplemented. Source: [surface ledger](../../docs/SURFACES.md).
- **Inference:** The most persuasive evidence package is a clean-machine, two-host recording backed by an exact transcript and compatibility matrix. Internal test counts support trust, but prospective users first need proof that their browser, resolver, runtime, and OS trust store work together.
- **Owner choice:** Preserve the owned page's current bounded language as the canonical short positioning. Add `https://sylin.org/koi` to the GitHub homepage field before any adoption push; this is a discoverability repair, not a copy rewrite.

## Constraints and open questions

The following are explicit constraints or future owner choices with a stated disposition:

- **Fact — security boundary:** Management HTTP binds to loopback by default, mutations require a daemon token, and inter-node certmesh traffic uses mTLS. Deliberately exposing management HTTP beyond loopback still requires a confidential transport boundary; bearer-token authentication alone does not encrypt traffic. Source: [security model](../../docs/reference/security-model.md).
- **Fact — trust boundary:** Koi assumes a trusted machine owner and does not defend against hostile local processes or multitenant hosts. Generic TLS clients can continue accepting a revoked member's unexpired certificate because there is no CRL/OCSP distribution.
- **Fact — network boundary:** mDNS is local-network multicast. VLAN, routed-subnet, guest-network, and overlay scenarios require explicit unicast DNS, gateways, or forwarding guidance; `.internal` being reserved does not configure resolvers automatically.
- **Fact — reliability boundary:** The current source analysis found a startup reconciliation race for already-running containers, an event-watcher path that exits instead of reconnecting after Docker stream failure, incomplete custom data-root propagation in embedded mode, and documentation drift. These are release-readiness work, not positioning advantages.
- **Recommendation for owner review:** Lead with homelab/self-hosting operators and LAN developers, use local-first LAN service identity/control plane as the category, preserve the pre-1.0 warning, and keep all external publication unauthorized until the readiness blockers are repaired. The no-publication gate is a playbook constraint; the category and audience choices still require owner approval.
- **Owner choice — before 1.0:** Define the supported topology matrix, first-success time target, compatibility promise, security review threshold, upgrade policy, and support response policy. Until those are chosen and evidenced, wording must remain “designed to” or “supports the documented matrix,” not “just works everywhere.”
