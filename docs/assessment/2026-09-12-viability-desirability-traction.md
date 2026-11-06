# Koi: viability, desirability and traction assessment

Assessment date: 12 September 2026. Source reviewed: 791f87ebe0a8ba93246f60ce0b283c13fb86595b, version 1.0.0-dev.0. External offerings and public adoption counters were checked on the assessment date.

**Koi is technically credible and worth continuing as a focused open-source solution. Its desirability is plausible for a specific audience, but independent demand and sustained adoption remain unproven. The best opportunity is to make container and LAN services easier to find, use and maintain across existing stacks. The current risk is spending more effort expanding and refining the platform than discovering which complete task people actually need it for.**

This assessment follows the recorded project preference for open-source adoption and sustainability. It does not assume a commercial sales model. Recommendations are proposals, not changes to the accepted architecture or active implementation campaign.

| Dimension | Assessment | Confidence and reason |
| --- | --- | --- |
| Technical viability | Favorable for a bounded LAN utility | High: substantial implementations, reconciliation, security boundaries and passing CI for the inspected commit |
| Desirability | Promising for container/LAN operators; weakly established beyond them | Medium: recognizable integration friction, but no independent interviews or measured task savings |
| Differentiation | Credible in lifecycle integration; weak in feature inventory | Medium-high: competitors already combine naming, local HTTPS, discovery and diagnosis |
| Readiness for broad adoption | Uneven | High: public setup gaps, distribution inconsistencies, unfinished outcome journeys and divergent validation states |
| Capacity to gain traction | Plausible through a narrow task and ecosystem integrations | Medium-low: a distribution route exists, but current public signals do not demonstrate pull |
| Long-term sustainability | Conditional on scope discipline and wider ownership | Medium: a large infrastructure surface and one publicly listed human contributor |

**What the code establishes**

Koi has moved well beyond an idea expressed in documentation. Its runtime composition translates container inventory into mDNS registrations, DNS entries, health checks and proxy configuration. It subscribes before reading the initial snapshot, reconciles existing instances, retries, and owns cleanup. These details address the failures that make small networking scripts unreliable after a restart or missed event. The combination is a real asset. [Runtime orchestration](E:/repo/github/sylin-org/koi/crates/koi-compose/src/orchestrator.rs:85)

The architecture also gives domains explicit lifecycle ownership while sharing composition across daemon and embedded consumers. The service catalog distinguishes an observed service from one with a current successful check, a stale observation or ambiguous identity. That creates a useful foundation for answering whether a service can actually be used. [Core lifecycle](E:/repo/github/sylin-org/koi/crates/koi-compose/src/cores.rs:657), [catalog conditions](E:/repo/github/sylin-org/koi/crates/koi-compose/src/catalog.rs:1035)

Security work is substantive: authenticated mutations, protected sensitive reads, conservative handling of unknown peers, certificate checks, CA pinning during renewal and transactional identity persistence. This is positive engineering evidence; it is not equivalent to an independent security audit. [HTTP authorization](E:/repo/github/sylin-org/koi/crates/koi-serve/src/http.rs:689), [renewal](E:/repo/github/sylin-org/koi/crates/koi-certmesh/src/core_renewal.rs:98), [identity persistence](E:/repo/github/sylin-org/koi/crates/koi-certmesh/src/repository.rs:269)

The strongest design choice is compatibility with existing infrastructure. Selected container labels, DNS delegation, certificate files, ACME, HTTP and Prometheus exports let an operator adopt a portion of Koi. That can reduce the cost of trying it. The product value will depend on how much configuration and troubleshooting these connections actually remove.

**Where capability falls short of the promised experience**

| Confirmed finding at the inspected commit | Why it matters | Evidence |
| --- | --- | --- |
| The container certmesh label records intent; it does not issue or inject a container identity | Label → discoverable service is further along than label → trusted service URL | [Runtime metadata](E:/repo/github/sylin-org/koi/crates/koi-runtime/src/instance.rs:143) |
| ACME requires an exact service-name/account grant, but the grant operation has no production caller in the inspected source | A fresh stock-daemon user cannot complete the current grant-based ACME setup through the public operator surfaces | [Grant operation](E:/repo/github/sylin-org/koi/crates/koi-certmesh/src/service_names.rs:114), [enforcement](E:/repo/github/sylin-org/koi/crates/koi-certmesh/src/service_names.rs:254), [explicit guide limitation](E:/repo/github/sylin-org/koi/docs/guides/acme.md:64) |
| The new UI renders service identity and condition, while useful launch and setup journeys remain unfinished | Infrastructure visibility alone does not complete the user's task | [Service row](E:/repo/github/sylin-org/koi/crates/koi-ui/src/components/service_row.rs:6), [Home](E:/repo/github/sylin-org/koi/crates/koi-ui/src/screens/home.rs:8) |
| The trusted-HTTPS tutorial's vanity-name section still describes broader issuance without the new grant prerequisite | An operator can follow apparently valid instructions into a missing step | [Tutorial](E:/repo/github/sylin-org/koi/docs/tutorials/trusted-https.md:201), [current ACME contract](E:/repo/github/sylin-org/koi/docs/guides/acme.md:26) |
| The README advertises an npm package that returned 404 from the public registry | A low-friction trial path currently fails before users see value | [README](E:/repo/github/sylin-org/koi/README.md:277), [recorded registry checks](E:/repo/github/sylin-org/koi/docs/assessment/findings/2026-09-12-public-adoption-snapshot.json) |

These are completion and communication gaps, not evidence that the CA or discovery engine is fictional. Earlier assessments contain defects that have since been repaired; their old conclusions should not be treated as a current defect list.

The full secure journey still asks users to understand daemon installation, CA creation, enrollment, DNS configuration, proxying, certificate names, client root installation and browser-specific trust. The tutorial accurately acknowledges many of these constraints. Its ten-minute headline has not been validated here with newcomers. Koi will earn adoption when it guides and verifies these steps with substantially less effort than the alternatives. [Trusted HTTPS journey](E:/repo/github/sylin-org/koi/docs/tutorials/trusted-https.md:19)

Three distinctions need to stay explicit. Discovery does not establish reachability. A certificate issued by Koi is not automatically trusted by every phone, browser or application runtime. An HTTP discovery API does not transparently adapt every unmodified application that expects native multicast. Those boundaries constrain the broad promise of connecting everything local.

**How the current alternatives change the case**

The market already validates interest in pleasant local networking and HTTPS. It does not establish that people want Koi specifically. The principal competitor is often an existing setup that is inconvenient but adequate.

| Alternative | Documented offering | Consequence for Koi |
| --- | --- | --- |
| OrbStack | Container and Compose domain names, automatic HTTPS and proxying, local CA, and container trust injection on macOS | An integrated container experience is already a benchmark. Koi must demonstrate value across other runtimes, multiple hosts and physical LAN services. [Domains](https://docs.orbstack.dev/docker/domains), [HTTPS](https://docs.orbstack.dev/features/https), [platform FAQ](https://docs.orbstack.dev/faq) |
| mkdev | Open-source single binary combining local CA, reverse proxy, mDNS LAN sharing, native trust stores, TUI and diagnostics; documents Windows, Linux and macOS | A close neighbor already claims much of the broad bundle. Koi's distinction must involve lifecycle, discovery interfaces and shared identity beyond manually configured development routes. Its operational quality was not tested here. [Upstream project](https://github.com/venkatkrishna07/mkdev) |
| Tailscale | Device naming, Serve, service-level names and routing through Services, access controls and redundancy; split DNS and subnet routers | Comparing only against older device-level MagicDNS understates the overlap. Tailscale can reach devices that cannot run its client. Koi can contribute LAN discovery and local naming while Tailscale provides remote access. [Services](https://tailscale.com/docs/features/tailscale-services), [DNS](https://tailscale.com/docs/reference/dns-in-tailscale), [non-client devices](https://tailscale.com/docs/use-cases/personal-or-at-home-use/access-devices-without-tailscale) |
| Caddy, step-ca and mkcert | Existing local trust/certificate tools; Caddy includes automatic internal HTTPS and an ACME server; step-ca supplies private certificate automation | Private CA and ACME functionality alone provide little differentiation. Koi must improve enrollment, diagnosis or coordination with discovery and runtime state. [Caddy HTTPS](https://caddyserver.com/docs/automatic-https), [Caddy ACME server](https://caddyserver.com/docs/caddyfile/directives/acme_server), [step-ca](https://smallstep.com/docs/step-ca/), [mkcert](https://github.com/FiloSottile/mkcert) |
| Traefik plus DNS/CA components | Label-driven Docker routing and configurable ACME services | Reading existing labels is sensible, but the meaningful benefit is less duplicate configuration and correct lifecycle behavior. [Docker provider](https://doc.traefik.io/traefik/reference/install-configuration/providers/docker/), [ACME](https://doc.traefik.io/traefik/reference/install-configuration/tls/certificate-resolvers/acme/) |
| Avahi and Docker helpers | Existing container-label publication and multicast-reflection approaches; Home Assistant documents an isolated-Docker HomeKit setup using an Avahi reflector | The problem is solvable today. Sell reduced assembly and support effort; prove actual application compatibility. [docker-mdns](https://github.com/phyber/docker-mdns), [Avahi container](https://github.com/flungo-docker/avahi), [HomeKit guidance](https://www.home-assistant.io/integrations/homekit/#docker-network-isolation) |
| Docker MCP Gateway and Tailscale Aperture | MCP server lifecycle, catalog/discovery or aggregation, credentials and routing | MCP is a useful interface and distribution channel. Its presence does not establish a unique category. Koi could supply accurate LAN facts to these systems. [Docker gateway](https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/), [Dynamic MCP](https://docs.docker.com/ai/mcp-catalog-and-toolkit/dynamic-mcp/), [Aperture MCP](https://tailscale.com/docs/aperture/mcp-server) |

A further substitute is a real domain with automated DNS-01 certificates for a private service. The service itself need not be exposed publicly for that challenge. This can avoid installing a private root on each client, at the cost of public-domain/DNS dependencies. Offline operation and names under private control are valuable only to adopters who care about those trade-offs. [Let's Encrypt DNS-01](https://letsencrypt.org/docs/challenge-types/)

Likewise, Docker already offers host networking on Linux and an optional Desktop implementation with specific limitations. Koi should explain the benefit of retaining bridge networking, rather than making absolute statements that containers cannot participate in local networking. [Docker host networking](https://docs.docker.com/engine/network/drivers/host/)

My inference is that the defensible advantage can become accumulated interoperability, reliable recovery, useful diagnosis and the trust earned by maintaining these across releases. The individual protocols and the size of the feature set offer limited protection from alternatives.

**Who is likely to want it**

| Audience | Fit | What would make adoption rational |
| --- | --- | --- |
| Technically capable container/LAN developers and homelab operators, especially mixed Windows/Linux environments | Strongest initial hypothesis | A container can discover or publish a real LAN service while retaining isolation, and names/state remain correct through recreation and host changes |
| Maintainers of LAN-aware applications and small appliances | Strong distribution opportunity, unvalidated | A supported API or embedded component replaces their own discovery and lifecycle glue without forcing a new stack |
| Offline labs, workshops and small device test networks | Plausible secondary audience | Account-free operation and repeatable naming/trust matter enough to justify setup and maintenance |
| Existing Tailscale/Caddy/Pi-hole users | Selective fit | Koi eliminates a specific remaining coordination task; replacing their working setup would usually weaken the proposition |
| General households and nontechnical users | Weak current fit | They need completed device/browser journeys and very little certificate or resolver knowledge |
| Enterprise identity or multi-tenant agent infrastructure | Poor current primary target | Coarse principal authority, ordinary-TLS revocation limits and current support capacity do not match those requirements |

Keep the broad Find/Trust/Connect identity, but lead acquisition with a task. A useful initial proposition is: **“Make your container services discoverable on your LAN, and keep their names and status correct when they change.”** Follow it with a demonstrated second-device result. Once service-certificate wiring is complete, trusted HTTPS can become the next visible outcome.

For application developers, demonstrate both directions separately: a labelled service appears on the LAN, and an application inside a container finds a LAN service through Koi. The second direction needs a participating application or adapter. Neither should be implied from a dashboard screenshot alone.

**What the traction evidence actually says**

| Public signal on 12 September 2026 | Observation | Interpretation |
| --- | --- | --- |
| GitHub | 1 star, 0 forks, one listed human contributor | Very little visible community formation; concentrated maintenance |
| Issues and PRs | 45 combined records, all PRs; authors were the maintainer and bots | No public issue-based user-feedback record in this query |
| Release assets | 199 aggregate downloads across 20 releases; rc.2 had 7 | Small exposure signal; includes files other than binaries and repeated/automated downloads |
| crates.io koi-net | 247 lifetime downloads, 186 reported recent downloads, 17 for rc.2 | Does not establish active installations or retained usage |
| npm | Scoped package not found | Packaging exists locally, but this advertised public acquisition path is unavailable |
| Retention and independent task completion | Not measured in this assessment or established by the reviewed evidence | The most important adoption questions remain open |

These counters were fetched directly from the [GitHub repository API](https://api.github.com/repos/sylin-org/koi), [releases API](https://api.github.com/repos/sylin-org/koi/releases?per_page=100), [issues API](https://api.github.com/repos/sylin-org/koi/issues?state=all&per_page=100), [contributors API](https://api.github.com/repos/sylin-org/koi/contributors?per_page=100), [crates.io API](https://crates.io/api/v1/crates/koi-net) and npm. The [dated snapshot](E:/repo/github/sylin-org/koi/docs/assessment/findings/2026-09-12-public-adoption-snapshot.json) preserves values and limitations. Private deployments and container-image usage were not measured.

This is **absence of demonstrated traction, not proof of absent demand**. The project has enough implementation to test a specific adoption thesis; it does not yet have evidence for forecasting broad uptake.

Distribution is currently making that test harder. GitHub still describes the project narrowly as local mDNS discovery and has an empty homepage field, although an owned Koi page exists. The published stable version is 0.9.0, the latest prerelease is rc.2, and local source is on a development line. Each is legitimate, but instructions and claims need to follow the selected artifact. Prepared package-manager scaffolds should be clearly distinguished from installable channels. [Owned page](https://sylin.org/koi/), [release status](E:/repo/github/sylin-org/koi/README.md:303), [packaging state](E:/repo/github/sylin-org/koi/packaging/README.md:3)

There is also no obvious automatic global growth mechanism. Adding another participant can make one network more useful, but that does not necessarily recruit another independent network. Reproducible examples, recommendations and integrations into downstream projects are more credible distribution mechanisms than expecting the software to become viral on its own. This is a strategic inference, not a measured growth result.

**The main advantages and liabilities**

The advantages are a real coordination layer, practical cross-platform knowledge, account-free local operation, standard interfaces, explicit state and cleanup, and an architecture that lets users retain existing tools. These support both direct operator use and adoption by other projects.

The liabilities are the setup burden around DNS and trust, incomplete last steps in key workflows, substantial competitive overlap, moving documentation and release contracts, and limited external evidence. The maintenance concern is particularly serious: discovery providers, OS services, certificate renewal, trust stores, runtime reconnection and several interfaces interact in ways a single green unit-test run cannot fully cover. More code generation does not remove the work of reproducing user environments or sustaining their trust.

Security also limits positioning. Active remote principals currently receive coarse authority; ordinary TLS clients do not consume Koi's revocation metadata and can accept an unexpired certificate without CRL/OCSP. Deliberately exposed HTTP remains plaintext despite token authentication. These are documented boundaries, not newly demonstrated exploits. An owner-operated LAN is a much better fit than a multi-tenant security platform. [Security model](E:/repo/github/sylin-org/koi/docs/reference/security-model.md:150), [principal authorization](E:/repo/github/sylin-org/koi/crates/koi-certmesh/src/principal.rs:89), [ACME constraints](E:/repo/github/sylin-org/koi/docs/guides/acme.md:22)

**Strategic opportunities, in order**

1. **Complete one container-to-second-device journey.** Start from a known installable artifact, publish one service, open the real application from another machine, then stop/recreate it and prove correct disappearance and recovery. Use that as the acceptance unit. Extend the same journey to an exact trusted service name once the grant and certificate wiring exists.
2. **Make one existing-stack integration excellent.** Choose Caddy or Traefik with one resolver setup. Supply exact tested versions, all required hooks/adapters, grant creation, renewal and recovery instructions. A complete supported recipe is more persuasive than several format-compatibility claims.
3. **Use discovery and diagnosis as an easy first trial.** Let people solve one visible problem before asking them to operate a CA. Explain whether failure is discovery, DNS, reachability, certificate identity or client trust. Measure whether this first trial leads to continuing use rather than an interesting one-time scan.
4. **Recruit downstream maintainers.** A LAN-aware application or appliance that uses Koi can introduce it to people at the moment they need it. Make one small HTTP/SDK integration reproducible and supportable. Keep embedding compatibility and upgrade expectations narrow until real consumers establish requirements.
5. **Treat agent access as an extension of useful network facts.** Demonstrate an agent locating the right service and diagnosing a real failure. Read-only onboarding and appropriately restricted credentials matter more than growing the MCP tool count. Broader agent infrastructure should follow demonstrated users.

Keep further runtimes, general proxy features, overlay networking, enterprise PKI and broad dashboards out of the near-term expansion agenda unless an adopter supplies a concrete need. The existing task campaign already contains much of the missing implementation. The strategic change is to organize progress around completed user outcomes and bring external observation forward.

**A practical 90-day validation plan**

The numbers below are proposed decision thresholds for a small exploratory cohort, not market benchmarks or forecasts. Ten people cannot prove market size; they can reveal whether the current direction deserves the next investment.

| Period | Work and evidence | Decision it enables |
| --- | --- | --- |
| Days 1–14 | Select one supported artifact and task. Repair its installation/docs mismatch. Observe five independent qualified operators attempting the narrow task, recording time, interventions, failure stage and current alternative. Use direct observation without remote telemetry. | Does the problem recur, and do users understand why Koi helps? |
| Days 15–45 | Complete the missing steps revealed by those trials. Expand to ten operators, including real mixed-OS networks. Verify second-device access, container recreation and cleanup; add HTTPS/renewal only on a candidate that supports that whole path. | Can at least 7 of 10 complete the chosen task from documentation without live maintainer rescue? |
| Days 46–90 | Follow up at 30 days, measure continued use and support time, and seek one independently reproducible integration example. Publish a focused demonstration when its stated scope is reliable. | Are at least 6 of 10 still using it for a recurring task, and can at least two explain a concrete advantage over their previous setup? |

Record support minutes, not just successful outcomes. A workflow that technically succeeds but requires repeated bespoke help may be desirable without being sustainable for this project. Ask why people stop; do not assume missing features are the answer.

If people keep discovery/lifecycle but avoid certmesh, make the default experience reflect that demand and retain trust as an optional deeper capability. If only downstream developers retain it, favor the library/API path. If interested operators repeatedly return to their existing stack even after activation becomes reliable, narrow the project further or reconsider the adoption thesis. More features should not be the automatic response.

**Verification and limits**

The canonical campaign ledger records no active candidate for the current development line, with final candidate and usability acceptance work still queued. Earlier release and physical-validation records apply to their specific artifacts. Passing development CI therefore does not establish current release acceptance. [Campaign ledger](E:/repo/github/sylin-org/koi/docs/prompts/delight/LEDGER.md:15)

The inspected local commit has a [successful hosted CI run](https://github.com/sylin-org/koi/actions/runs/34014784712). A newer remote development commit also has [successful CI](https://github.com/sylin-org/koi/actions/runs/34088797694); its source was not substituted for the local assessment. The latest observed public-main [CI run failed](https://github.com/sylin-org/koi/actions/runs/33878240432), and the 7 September [scheduled QA run on main failed](https://github.com/sylin-org/koi/actions/runs/34078224022): three OS integration jobs and Windows service lifecycle failed, while Linux/Windows concurrency jobs passed. Job outcomes were checked, but their logs were not diagnosed, so neither their cause nor applicability to development HEAD is asserted.

Focused local checks produced 33 passing Node contract tests and two failures caused by the absence of a POSIX shell on this Windows environment. Python produced seven passes and one skip because the optional cryptography dependency was unavailable. These checks do not certify the installers or cross-language cryptography end to end. No full Rust rebuild, fresh LAN deployment, trust-store modification or independent security audit was performed.

Repository inspection covered composition/runtime, catalog and UI, certificate issuance and authorization, serving/MCP, install/release documentation, CI configuration and current acceptance records. Competitor capabilities were researched from official documentation and upstream projects; no competitor was installed or benchmarked. No users were interviewed. Earlier assessments were used as historical context, not as substitutes for current verification.

**Recommendation:** continue Koi with a narrower adoption promise and explicit evidence gates. Its best prospects come from reliably completing a recurring container/LAN task and being easy for other projects to adopt. The next decisive evidence is an independent operator choosing to keep it after a month.
