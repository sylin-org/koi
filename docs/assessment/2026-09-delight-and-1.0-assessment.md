# Koi approaching 1.0: capability, quality, and delight assessment

Assessment date: **2026-09-04**. Source: `dev` at `f625557c9fe81c9483eba80413efdc706d59f6dd`. This is an assessment and a proposed direction, not release acceptance or an implementation plan already approved for execution.

**My judgment: Koi has the substance of a valuable product, but its engineering maturity currently exceeds its ease of adoption.** Its strongest achievement is making local services participate in a coherent lifecycle across operating systems. Its largest remaining opportunity is making that lifecycle feel like one completed task to the person using it.

Discovery supplies curiosity and immediate reward. Trusted access supplies lasting relief. Truthful recovery supplies confidence. Those are three different forms of delight, and Koi needs all three.

I would continue toward 1.0 with a narrower promise, corrected user journeys, and evidence attached to the exact candidate. I would prioritize helping someone reach and keep using one trusted local service over adding another capability. Certmesh deserves a central place in that promise, with a much gentler path into its existing machinery.

**What was assessed, and what the evidence means.**

This review covered the root documentation, workspace and dependency boundaries, CI and release workflows, fleet acceptance records, CLI and installation guidance, discovery providers and presentation, DNS, runtime composition, certificate issuance and membership, trust and authorization, ACME, MCP, embedded and language clients, dashboard assets, and the adjacent desktop workbench. The web dashboard and mDNS browser were inspected against the installed Windows daemon, including a 390-pixel mobile viewport and a no-results search. The desktop was assessed through source, documentation, and its UI tests; its native UI and phone deployment were not exercised in this session.

Facts below are distinguished as **observed**, **source-confirmed**, **recorded evidence**, or **recommendation**. This was broad product and repository assessment with targeted verification. It was not a line-by-line security audit, an exhaustive regression run, or a usability study with representative participants.

The existing native fleet soak was in progress. No service restart, CA creation, enrollment, trust-store change, firewall change, or deployment was performed for this assessment. The checks and evidence boundaries are recorded in [the verification note](2026-09-assessment-verification.md).

**The release situation is more complicated than “nearly 1.0.”**

| Surface | State at assessment time | Implication |
|---|---|---|
| Latest published stable release | `v0.9.0`, published June 25 | An unqualified stable install does not represent everything described by development documentation. |
| Latest published prerelease | `v1.0.0-rc.2`, published August 24 | This remains an explicit opt-in artifact. |
| Reviewed source | `1.0.0-dev.0` on `dev` | The old RC freeze was withdrawn for the observable-domain rebuild. |
| Current native candidate campaign | OD-3 frozen source `b3eb47e08817045f9371703d780ada9aab00995d` | All five native readiness rows are recorded ready; the six-hour soak is scheduled through September 4, 23:30 UTC, with final reconciliation still required at this snapshot. |
| Latest hosted CI inspected | September 4 run on `main`, commit `b09f0f3` | Failed Windows DNS tests and the lean closure check; cross-host job skipped. It does not test the reviewed `dev` tree. |

The installed Windows binary matched the OD-3 recorded SHA-256. Compared with that frozen source, reviewed HEAD had no changes under `crates`, the workspace manifests/lockfile, packaging, or the two bootstrap installers. Later evidence commits should not be mistaken for a new product build. Conversely, historical green results should not be promoted to proof of a changed product. Sources: [release list](https://github.com/sylin-org/koi/releases), [active epic](../../fleet/epics/002-observable-domain-boundaries.md), [upgrade guide](../guides/upgrading.md), [hosted CI run](https://github.com/sylin-org/koi/actions/runs/33878240432).

**Who should feel delighted?**

The best initial audience is the technical person responsible for several local applications across a mixed network: a homelab operator, a developer with containers and physical devices, or a small team without a dedicated infrastructure function. Other audiences matter, but giving them equal prominence on the first screen makes the product harder to understand.

| User | What delight means | Koi's current advantage | What gets in the way | A useful success test |
|---|---|---|---|---|
| Curious newcomer | “I can finally see what is here.” | Immediate discovery; recognizable service labels; live browser | Protocol names, noisy type lists, empty-result ambiguity | Identify and open one real service without reading a protocol reference. |
| Homelab operator | “My services have names, HTTPS, and survive the weekend.” | DNS, certmesh, proxy, native service lifecycle, recovery tooling | Resolver adoption, client root trust, service-name certificate wiring | Open one stable trusted URL from a second machine, then recover after restart. |
| Container developer | “I added the label and my app became usable.” | Runtime events compose discovery, DNS, health, and optional proxy | `koi.certmesh=true` does not issue a workload certificate; several host/container boundary choices remain | Start, change, and remove a container; its usable endpoint follows every transition. |
| Small-team operator | “I know who can access this, and I can withdraw access.” | Pinned invites, local key custody, named principals, audit, diagnosis | Coarse authorization, manual CA continuity, several meanings of trust | Explain a member's authority and revocation effect accurately before granting it. |
| Application/agent builder | “I can query a real network contract instead of guessing.” | Coherent inventory, HTTP, SDKs, MCP, typed errors | Version spread, client compatibility, auth bootstrap, uneven transport behavior | Connect a supported client using one verified recipe; handle stale/unavailable state correctly. |
| Rust embedder | “I reuse the hard platform work without inheriting a service.” | Shared composition; optional heavy backends; lifecycle ownership | Large facade, exact internal versions, public API changes during development | A small example builds against the published version, serves, observes changes, and shuts down cleanly. |
| Household member / phone user | “The thing I want is there, and I can tap it.” | Pond's deliberate read-only sharing; desktop's curated views | Binary-oriented onboarding, root installation, protocol-heavy browser | Reach a selected service with understandable trust status; never need to learn PKI. |
| Contributor / maintainer | “I can change one thing without breaking six others.” | Domain boundaries, ADRs, architecture guards, physical evidence | Oversized modules and multiple competing planning/status documents | Find the current task, make a bounded change, and run the right checks without historical reconstruction. |

These are proposed outcome tests, not measured user-study results.

**What Koi can actually do.**

| Capability | Current substance | Assessment |
|---|---|---|
| Discovery | mDNS/DNS-SD browse, resolve, publish, leases, lifecycle observation, platform capability routing | A strong entry point and a real cross-platform differentiator. Validate the observed type-classification problem before release. |
| Naming | Static, discovered, and certificate-derived names; cooperative DNS listener; TXT records and zone export | Useful and composable. A record in Koi does not establish that the user's OS, browser, or second machine resolves through Koi. |
| Certmesh | Private CA, creation ceremony, pinned single-use invites, CSR issuance, local key custody, renewal/key rotation, membership, signed trust data, backup and promotion | Substantial product value. The surrounding explanations and completed service-access journey lag the implementation. |
| OS trust | Managed root installation/removal, observation, export, diagnosis | Valuable independently of Koi-issued certificates. OS-store success needs to be distinguished from success in a particular browser, runtime, or container. |
| Runtime integration | Docker/Podman inventory and label ingestion; reconstruction after restart; transient desired sets for DNS/health/proxy | Probably the best practical demonstration of the whole product. Automatic per-container identity issuance is absent. |
| TLS proxy | TLS termination, live certificate inputs/reload, forwarding, explicit remote-backend choices | Useful as a simple completion mechanism. It should remain easy to combine with an existing proxy. |
| ACME | Private-zone issuance through a dedicated TLS listener, dns-01, EC account keys, wildcard support | A strong interoperability door. A working server is only part of a turnkey Caddy/Traefik/client integration. |
| Health and events | HTTP/TCP checks, transitions, status, SSE, outbound webhooks, Prometheus discovery | These make the system useful after onboarding. Present meaningful changes and recovery, not every low-level observation. |
| UDP bridging | Host socket access through HTTP/SSE for isolated workloads | A valuable specialist feature. Keep it discoverable through recipes rather than making newcomers learn it. |
| Developer interfaces | CLI, HTTP/OpenAPI, local IPC, Rust embedding, Python/TS clients | Broad and thoughtfully designed. Compatibility claims must name versions and behavior by transport. |
| Agent interfaces | MCP inventory/discovery/mutations; stdio and HTTP; certificate-bearing management callers | Promising, especially on private/offline networks. Named identity is ahead of fine-grained permissions. |
| Human interfaces | Built-in dashboard/browser; separate native workbench; narrow Pond LAN adapter | The pieces exist, but users encounter different visual language and different levels of assistance. |

Implementation evidence: [workspace](../../Cargo.toml), [architecture](../reference/architecture.md), [runtime orchestrator](../../crates/koi-compose/src/orchestrator.rs), [certmesh source](../../crates/koi-certmesh/src/lib.rs), [MCP guide](../guides/mcp.md), [Pond decision](../adr/042-pond-read-only-lan-adapter.md).

**The good: Koi has earned strengths worth protecting.**

1. **It owns an unusually useful combination of responsibilities.** Containers, OS discovery, names, identity, and lifecycle are usually separate integration chores. Koi can coordinate them once. The value is greatest when a service changes or disappears and every derived surface follows it.

2. **The architecture now gives truth a concrete home.** The command/status/event boundaries, immutable snapshots, explicit ownership, and commit-before-publication ordering are well matched to a product that must explain what is happening. A UI cannot be reassuring if its status is guessed from configuration. The current aggregate and its guards provide a credible foundation for both human and machine interfaces. All 15 architecture checks passed in this assessment. See [ADR-043](../adr/043-observable-domain-boundaries.md) and [architecture tests](../../crates/koi-common/tests/architecture.rs).

3. **The project takes operating systems seriously.** The fleet records address real SCM, systemd, OpenRC, firewall, immutable-desktop, restart, and provider behavior. Windows support is being proved through native behavior rather than inferred from successful compilation. The provider selection model also acknowledges that an OS may support reading discovery correctly while requiring a different publication provider.

4. **Trust has useful lifecycle depth.** CSR-only enrollment and local key custody, finite invites, renewal with key rotation, explicit authority state, signed trust bundles, and restore paths are more meaningful than merely generating PEM files. [Issuance](../../crates/koi-certmesh/src/core_enroll.rs), [renewal](../../crates/koi-certmesh/src/core_renewal.rs), and [principal authorization](../../crates/koi-certmesh/src/principal.rs) expose actual responsibilities that can be inspected and tested.

5. **Coexistence and reversibility are strong product principles.** Respecting incumbents, reporting contention, tracking installed roots, and restoring exact state directly reduce adoption anxiety. The user should feel that Koi is a considerate guest. [Gentle participation](../adr/035-gentle-participation.md) is a better long-term differentiator than a longer feature list.

6. **The CLI has a considered learning path.** Bare-command status, domain examples, detailed command help, JSON, and HTTP equivalents help a user move from exploration to automation. Preserve this discoverability while making the first recommended action unambiguous.

7. **There is already a better human experience inside the ecosystem.** The desktop workbench has “Glance,” watched items, grouped change episodes, “since you last looked,” role-aware trust actions, and explicit stop-sharing. Its 38 UI tests passed. These features show that Koi can explain a network in everyday terms. They should inform the common product experience; they are not hypothetical new inventions.

8. **The repository records its own failures.** Withdrawn freezes, unclaimed platform evidence, historical regressions, and precise restoration requirements are signs of useful engineering candor. Preserve the evidence, then make its conclusion easier for a release reviewer or new contributor to find.

**The bad: capability breadth still asks the user to do too much assembly.**

The main onboarding path gets someone from installation to a list of services, then to a daemon, then to a DNS record. That is progress, but the emotional payoff is incomplete when the user still cannot type the name in their usual browser. The tutorial verifies Koi's resolver with Koi's own client. It needs a second, clearly distinguished check using the consumer that the user actually cares about. See [getting started](../tutorials/getting-started.md).

The first dashboard is organized around implementation domains. In the observed installation, discovery was working, DNS had learned records, and the web UI responded promptly. Nevertheless, a newcomer saw ten capability cards, several empty panels, and a container-runtime connection error containing `hyper legacy client`. Only the mDNS card offered a direct next step. A long API catalogue sat above the activity feed. This is a useful technical console, but a weak welcome.

Keep technical details available. Lead with a sentence such as “Koi found services on your network,” followed by the next useful action. An uninitialized certmesh is an opportunity to set up trust; it is not yet evidence that the network is protected. A container runtime that is not connected should state that fact and explain how to connect it, with the transport error behind details. Relevant failures must remain visible, but they should not require the user to interpret library internals. Source: [dashboard asset](../../crates/koi-dashboard/assets/dashboard.html).

The vocabulary is also expensive. “Open,” “authenticated,” “sealed,” “posture,” “member,” “authority,” “trust,” “principal,” and “CA locked” each have legitimate meanings. Users need them presented as answers to distinct questions: Does this device have an identity? Is that identity healthy? Can it issue certificates? Does this client trust the issuer? What may this caller do? A green capability indicator cannot answer all five.

Certmesh creation is intentionally deliberate, which is appropriate when establishing authority. But keyboard entropy collection, passphrase handling, TOTP registration, security presets, daemon configuration, invitations, resolver setup, and client trust can accumulate before the first useful HTTPS request. Preserve the moments that explain authority and recovery. Evaluate whether extra ceremony such as key mashing earns its place in the novice path. The domain already generates randomness; the product question is whether this interaction helps users understand or safely complete their task. [Creation flow](../guides/certmesh.md), [ceremony implementation](../../crates/koi-certmesh/src/init_ceremony.rs).

The “My Organization” preset is particularly easy to overread. It selects enrollment and unlock behavior; it does not establish enterprise-grade authorization, externally audited PKI, managed device rollout, or automatic disaster recovery. Explain the actual choices, and sell outcomes that have been validated.

**The ugly: concrete contradictions and failure states that can undermine trust.**

The following deserve explicit ownership before release. “High” means a user can be materially misled or fail a central journey; it does not assert an exploitable vulnerability.

| ID | Finding and evidence | Why it matters | Recommended treatment |
|---|---|---|---|
| D01 — High | The [HA/recovery guide](../guides/certmesh-ha-recovery.md) promises 90-day leaves, renewal at 30 days, 14-day grace, and weeks of runway. [Current policy](../../crates/koi-certmesh/src/roster.rs) defaults new meshes to 7/3/1; existing meshes retain stored policy. | An operator could plan recovery around a window they do not have. Renewal grace also does not extend normal TLS certificate validity. | Derive recovery advice from actual policy and earliest expiry. Correct the runbook and show a concrete deadline. |
| D02 — High | The [trusted HTTPS tutorial](../tutorials/trusted-https.md) says default member SANs are the hostname and `.local`, and that `.internal` is absent. [IssuanceNames](../../crates/koi-certmesh/src/issuance_names.rs) now generates the hostname and configured-zone FQDN; [enrollment](../../crates/koi-certmesh/src/core_enroll.rs) uses it. | The tutorial can direct users to a name their new certificate does not cover. | Version the recipe and verify a real second-client URL with the exact released leaf. Service aliases still require their own authorized SANs. |
| D03 — High | [SECURITY.md](../../SECURITY.md) describes `/v1/certmesh/status` as the public minimal bootstrap read. [Current middleware](../../crates/koi-serve/src/http.rs) protects full status from remote peers; `/v1/certmesh/bootstrap` is the public preflight. | The security explanation disagrees with the enforceable contract. Other prose also overgeneralizes that all mutations use DAT, despite the deliberate enrollment exception. | Maintain one generated or tested route/auth matrix and link to it. Treat security documentation as a release artifact. |
| D04 — High | Observed browser “service types” included hostnames and full instance names. The authoritative mDNS snapshot also contained them: 35 type entries, 18 outside a simple `_service._tcp` / `_service._udp` shape. | This corrupts the user's basic map of the network and fills the mobile view with meaningless categories. It is not just a CSS problem. | Reproduce with captured/synthetic mixed PTR answers. Inspect query-owner/type validation in the [Windows adapter](../../crates/koi-mdns/src/windows_dnsapi.rs) and [discovery projection](../../crates/koi-mdns/src/discovery.rs). Exact root cause is not proven by this assessment; subtype-aware validation is required. |
| D05 — High for launch evidence | Latest hosted `main` CI is red; reviewed `dev` is outside the push/PR branch trigger. The historical failure rejected `zbus` and hit Windows socket error 10013 in a DNS retry test. Current source permits required platform `zbus` and replaces the old DNS runtime/test. | The visible CI badge and the currently accepted native product do not describe the same tree. | Obtain a complete hosted run for the exact candidate and make branch/candidate coverage explicit. Do not report those historical failures as proven current defects, or the current fixes as hosted green. |
| D06 — Medium | Both [shell installer](../../install.sh) and [PowerShell installer](../../install.ps1) finish by recommending `koi mdns discover` as “no daemon”; current source requires explicit `--standalone` for that mode. | The final onboarding instruction can immediately fail on a fresh current-source install. Older stable artifacts have a different mode contract. | Make bootstrap output version-aware or use an instruction valid for the selected release. Test the printed next action. |
| D07 — Medium | Searching for a nonexistent service returned “No services discovered yet” while the browser still showed 26 instances. | A working search falsely implies failed discovery. | Separate “no matching services” from “nothing discovered,” with a clear-filter action. [Browser asset](../../crates/koi-dashboard/assets/mdns-browser.html). |
| D08 — Medium | Type filters are clickable `span`s, histogram rows are clickable `div`s, and sorting uses click handlers on headers, without corresponding keyboard controls. | Core exploration is mouse-oriented. In the mobile view, categories consume the first screen before useful results. | Use semantic buttons and sortable-header controls, visible focus, accessible state, and a compact filter affordance. Audit contrast and reduced motion; this review did not establish full WCAG conformance. |
| D09 — Medium | `koi.certmesh=true` is accepted and represented in [runtime metadata](../../crates/koi-runtime/src/instance.rs), but does not issue or inject a workload certificate. The README's “announce, name, certify, and watch” language suggests a more complete automatic path. | A plausible configuration carries an unmet expectation at the heart of the product promise. | Show an explicit unsupported/request-only result, correct the headline, and design service identity as a complete later feature. |
| D10 — Medium | [Certmesh prose](../guides/certmesh.md) still says there is no distributed revocation list, while the trust protocol/source implement signed trust-bundle propagation for Koi-aware participants. It also calls a 24-hour lifetime effectively instantaneous revocation. | Operators cannot tell which clients stop accepting a revoked identity and when. | Explain Koi-aware enforcement and ordinary third-party TLS separately. A day is not instantaneous. State remaining validity and observation delay explicitly. |

**D04 disposition (2026-09-05):** the assessment's suspected boundary is now
confirmed. Windows `DnsStartMulticastQuery` returns a linked result containing the
requested PTR plus legal additional PTR/SRV/TXT/A/AAAA records. The adapter walked
that complete list but did not compare each PTR owner with the requested browse
owner, so additional service-instance and host PTRs were projected as meta-query
service types. R03 corrects this at the provider boundary with ASCII
case-insensitive, trailing-dot-insensitive owner comparison; keeps unknown valid
base service types; and handles subtype queries and escaped instance labels without
UI filtering. The synthetic regression proves classification and convergence, not
the still-pending installed Windows resource gate.

Several additional inconsistencies share the same cause. The [ACME guide](../guides/acme.md) opens with a no-plugin/no-special-configuration promise, then correctly explains that stock Caddy needs a DNS provider module. The HTTPS tutorial says browsers, curl, and language runtimes all pick up OS root installation; actual client behavior varies. Current Node documents explicit system-CA configuration, and Android distinguishes system roots from application acceptance of user-added roots. Those distinctions should be part of a client-specific verification flow. [Node CA options](https://nodejs.org/api/cli.html#--use-system-ca), [Android trust configuration](https://developer.android.com/privacy-and-security/security-config).

The recurring failure is **drift between a completed implementation, an older explanation, and the user's actual outcome**. Documentation cleanup alone will recur unless critical examples, policy values, and public contract claims receive executable checks.

**Repository quality: serious engineering, with a growing cost of understanding it.**

The tracked tree contains 678 files, including 302 Rust files and 165,460 physical Rust lines. These counts include inline tests, integration tests, examples, and the lab; they are not production LOC. There are 19 workspace members, 181 Markdown documents under `docs`, and 60 Rust files longer than the contributor guide's approximate 800-line target. `koi-certmesh` accounts for 30,467 Rust lines; the lab for 20,938. The largest files include `koi-lab/src/lab.rs` (4,923), the embedded handle (4,039), certmesh core tests (3,872), and Pond serving (3,362).

| Quality dimension | Judgment | Evidence and practical consequence |
|---|---|---|
| Architectural direction | Strong | Domain ownership and aggregate projections have real guards. Continue enforcing dependency direction and lifecycle ownership. |
| Failure handling | Substantial | Cancellation, durable transactions, rollback, restarts, provider transitions, and exact restoration are first-class concerns in code and fleet records. |
| Test breadth | Substantial, uneven by surface | Native and cross-participant records complement unit tests. UI semantic/accessibility defects show why source guards and mock tests cannot substitute for browser tasks. |
| Current release confidence | Incomplete | Native OD-3 final reconciliation and exact-candidate hosted green were not available at this snapshot. macOS installed lifecycle is separately qualified in the surface ledger. |
| Maintainability | Under pressure | Clear crate boundaries coexist with large modules, extensive platform code, and a large historical corpus. Feature breadth raises the ongoing ownership cost. |
| Documentation | Rich but inconsistent | Enough material exists to explain nearly everything; finding the current truth requires cross-checking versions, code, ADRs, and handoffs. |
| Supply chain | Useful foundations | Locked builds, MSRV checks, audit job, checksums, provenance, release manifests, and channel tests exist. The inspected audit job passed; that is not an independent security audit. |
| Contributor experience | Needs consolidation | CONTRIBUTING points to a June assessment and old work orders as the current plan, while active development is driven by a newer fleet epic. |

I would not launch another broad refactor merely to meet a line-count target. Extract test modules and implementation concerns when doing related work, preserve the new domain contracts, and prioritize a smaller number of actively supported user outcomes. Arbitrarily splitting a long file does not reduce conceptual complexity.

The documentation needs one small, authoritative navigation layer: published behavior, development changes, supported combinations, current work, and historical evidence. The existing surface ledger should remain the evidence store, while a generated release summary makes it usable. Its opening historical proxy example still says a guard is absent even though later rows record newer guards; this illustrates why narrative summaries need dates or derivation too.

CI should include the language-client and release-contract checks in the routine candidate gate. Some bootstrap and manifest checks already run in release workflows; add the TS/Python client and version-contract checks to ordinary candidate validation too. Keep physical native gates for native claims. Add a few real-browser acceptance tasks covering search, keyboard interaction, reconnect, and the first successful endpoint. Avoid measuring quality by the total number of green tests.

**Certmesh is the strongest strategic opportunity, if it becomes easier to use as a whole.**

Certmesh can turn Koi from a useful discovery tool into infrastructure people rely on daily. The compelling outcome is: “This service has the right name, this device is the one I intended, this client trusts it, and renewal keeps it working.” Users do not particularly want a CA to administer. They want the repeated certificate and identity problems to stop consuming attention.

The market already has credible individual tools. `mkcert` makes local development certificates easy. Caddy manages local HTTPS and its own CA. `step-ca` provides substantial automated X.509/SSH issuance and provisioning. OrbStack sets a high convenience benchmark with automatic container names and HTTPS. Those facts make the quality of Koi's cross-machine lifecycle more important than claiming novelty for private certificates. [mkcert](https://github.com/FiloSottile/mkcert), [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https), [step-ca](https://smallstep.com/docs/step-ca/), [OrbStack container domains](https://docs.orbstack.dev/docker/domains).

My strategic inference is that Koi's best position is **trusted local participation across mixed operating systems and existing tools**. Discovery is its entry point; identity and dependable access deepen its value. Keep Pi-hole, AdGuard, Caddy, Traefik, and Tailscale as collaboration partners. Split DNS is already an established mechanism for directing selected queries to a local resolver. [Tailscale DNS](https://tailscale.com/docs/reference/dns-in-tailscale).

I would develop certmesh along five concrete product paths:

1. **A guided trusted-service flow.** Start with the intended URL and backend. Check name ownership, DNS from the intended client, authorized certificate names, trust, listener, and backend reachability. Finish with “Open service” and a receipt showing what was verified. Reuse existing domain operations; do not create a second lifecycle model in the UI. The flow can initially guide the existing steps before automating more of them.

2. **A diagnosis that follows a user's URL.** The existing trust doctor is valuable. Extend the experience to answer why a particular URL fails: wrong resolver, missing record, blocked port, SAN mismatch, missing root, expired identity, revoked caller, or unhealthy backend. Give one next action with the exact observed evidence. This is likely more delightful than adding another configuration screen.

3. **Trust onboarding by client type.** Generate an invitation or client setup package containing the public root, fingerprint, applicable instructions, and a verification URL. Distinguish enrolling a machine identity from teaching a browser/runtime to trust a CA. Explicit user consent remains necessary where the OS requires it; QR codes cannot remove platform trust rules. Reuse the desktop's grant explanation and fingerprint presentation.

4. **Renewal and recovery assurance.** Show last successful renewal, the earliest failure deadline, CA availability, backup freshness, and whether recovery has been exercised. Base urgency on actual expiry, not generic “days remaining” prose. Report “Recovered” after a verified recovery and avoid repetitive healthy-renewal alerts. Manual promotion may remain appropriate; the recovery experience must reflect the current short-lived policy.

5. **Finished integrations.** Ship and verify one complete dns-01 hook or provider path with one supported proxy/client before advertising broad ACME convenience. For container identities, distinguish host-level TLS termination from per-workload key custody. A workload certificate feature needs issuance authorization, rotation, delivery, cleanup, and revocation semantics, not just recognition of another label.

Certmesh should be a strong named product story within Koi. I would **not split it into a separate daemon or repository before 1.0**. DNS, trust observation, host identity, runtime composition, and renewal benefit from one coherent system. A focused install/profile or landing page is a cheaper way to test independent demand. Consider a separate distribution only after actual users repeatedly want certmesh without the rest.

There are boundaries to make explicit. The management principal guard deliberately grants active callers coarse authority over mounted surfaces; it does not implement per-principal tool permissions. Ordinary TLS clients do not automatically enforce Koi's signed membership state. No evidence reviewed here establishes an independent security audit. The “organization” audience therefore needs carefully scoped claims and, before broader expansion, focused external review of enrollment, key custody, recovery, and authorization. Source: [principal guard](../../crates/koi-certmesh/src/principal.rs), [trust protocol](../reference/trust-protocol.md).

**The other opportunities, in order of practical value.**

| Opportunity | Why it could delight | Next bounded investment | Priority |
|---|---|---|---|
| One container becomes one usable local service | Demonstrates the full promise with familiar tools | A copyable Compose example with an actual trusted URL, explicit client setup, restart proof, and exact cleanup | First |
| Explain and repair a failed connection | Turns network confusion into a short task | URL-focused diagnosis built on existing observed state | First |
| Common human presentation across web/desktop/Pond | Removes relearning and exposes existing good UX | Share vocabulary, service summaries, empty states, and supported actions; keep operator and read-only boundaries distinct | Next |
| Useful changes, remembered | Helps operators notice what matters while staying quiet | Bring watched items, episode grouping, and “since you last looked” into the common experience | Next |
| Caddy/Traefik/private-CA collaboration | Delivers value without replacement anxiety | One maintained integration with a published compatibility test | Next |
| Local agent discovery with individual identity | Replaces endpoint guessing and shared-identity ambiguity | Verify actual client compatibility, bootstrap, certificate selection, and revocation; add permission scoping when justified | Targeted pilot |
| Consumer-facing phones and appliances | Expands access beyond the operator's desk | Selected read-only service access and client-specific trust guidance | Later, constrained by platform behavior |
| Enterprise PKI/general fleet management | Large possible scope | Validate demand and support capacity before building policy, enrollment, and recovery breadth | Defer |

MCP is a useful distribution channel, but should not dictate the whole product. Koi's `_mcp._tcp` convention is not universal client support. Its custom token and mTLS options need named-client recipes; the published MCP HTTP authorization specification describes an OAuth-based interoperable flow. That does not make Koi's private integration worthless, but it prevents assuming every MCP host can connect merely because it understands MCP. Also distinguish stdio snapshots from live HTTP resource updates, as Koi's guide already does. Treat discovered TXT metadata as network data, not instructions or proof of trust. [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [Koi MCP guide](../guides/mcp.md).

**What I would require for a delightful 1.0.**

Release priorities should be finite and tied to the promise, rather than an invitation to keep adding features.

| Gate | Concrete result | Acceptance evidence |
|---|---|---|
| Candidate identity and validation | One named source/artifact set with complete hosted checks and reconciled native results | CI links, artifact hashes, supported-platform matrix, OD-3 verdict and restoration |
| Truthful critical documentation | D01–D03, D06, and revocation/client-trust claims corrected for the release | Executed tutorial examples, policy/route contract assertions, versioned docs |
| Honest discovery | The observed non-type entries are explained and corrected at the responsible boundary | Mixed-answer regression plus a physical Windows browser check |
| Complete beginner path | Install → discover → open one real service | Clean-machine run by someone who did not write the instructions |
| Complete trust path | Create/invite/join → correct URL → verified second-client HTTPS → renewal/restart | Exact certificate names and native client results, with no validation bypass |
| Recovery path | Interrupted service or unavailable CA produces a useful diagnosis and a tested route back | Deadline based on actual leaf policy; restore/rejoin effects accurately stated |
| Usable first screen | Working discovery is apparent; empty states suggest a next action; library errors are explained | Desktop/mobile task checks, keyboard controls, search state verification |
| Honest limits | Users understand client root trust, revocation scope, manual continuity, and optional integrations | A short linked limits page, verified against the actual release |

Changes to product code needed for these gates must follow the active epic's replacement-freeze rules; this assessment does not authorize relabeling an existing frozen artifact. A new grand redesign is unnecessary. Fix the false instructions and observed defects, improve the first screen, and choose which two or three end-to-end journeys 1.0 stands behind.

After that, the first substantial product iteration should deliver the guided trusted-service flow, a finished proxy integration, and URL-focused diagnosis. Fine-grained agent authority, richer workload identity delivery, and broader consumer-device support follow demonstrated demand.

**How to measure delight without confusing it with feature usage.**

Use moderated tasks and opt-in local diagnostics initially. The following are proposed measures, not existing telemetry or claimed results:

- Time from installation to a recognized, useful service; record zero-result networks separately.
- Percentage completing a second-machine trusted HTTPS request without outside help or disabling validation.
- Number of concepts and documentation jumps encountered before first success.
- Time to identify the cause of a failed URL, and whether the suggested remedy actually resolves it.
- Successful renewal/restart/restore outcomes for the advertised configurations.
- Unnecessary alerts and repeated alerts per failure episode.
- Completion of the same discovery task using keyboard only and a narrow viewport.
- Ability to remove Koi's service, trust, and derived resources while preserving unrelated host configuration.

Recruit users for the different jobs in the persona table. Observe where they stop, what they think a green indicator means, and whether they can explain what installing a root or revoking a member changes. A successful demonstration run by the author proves functionality; an unassisted run by a new user tests delight.

**The product opinion I would keep in view.** Koi is most appealing when it makes a difficult local-network task feel ordinary and dependable. Its engineering has already supplied much of the hard machinery. The next step is to let users experience the completed result: find something useful, give it a trustworthy way to be reached, and know it will still work tomorrow.
