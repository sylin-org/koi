# Koi Strategic Opportunity Assessment: The 2025–2026 Landscape

> Research conducted June 2026 via web search as part of the project maturity assessment.
> Companion: [landscape-2026.md](landscape-2026.md). Synthesis: [../2026-06-maturity-assessment.md](../2026-06-maturity-assessment.md).

## Macro context (why this moment matters)

Three structural shifts converged in 2025–2026 that are directly relevant to a "local network toolkit":

1. **MCP became the universal agent-tool standard.** Adopted by Anthropic, OpenAI, Google, Microsoft, AWS; official registry launched Sept 2025; protocol stewardship moved to the Linux Foundation at end of 2025. Glama's registry alone indexes ~34,000 MCP servers; Docker Desktop ships an MCP Catalog/Toolkit with 200+ servers ([GitHub MCP Registry](https://github.blog/ai-and-ml/github-copilot/meet-the-github-mcp-registry-the-fastest-way-to-discover-mcp-servers/), [Glama registry](https://glama.ai/mcp/servers), [Docker MCP Toolkit](https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/), [Cloud Native Now](https://cloudnativenow.com/editorial-calendar/best-of-2025/docker-inc-embraces-mcp-to-make-ai-agent-integration-simpler-2/)).
2. **The local-first/self-hosted movement is mainstream-adjacent.** Home Assistant passed 2M active installations and Slashdot framed it as leading a "local-first rebellion" (Dec 2025); the selfh.st survey grew to 4,081 respondents (roughly double 2023) ([HA State of the Open Home](https://www.home-assistant.io/blog/2025/04/16/state-of-the-open-home-recap/), [Slashdot](https://news.slashdot.org/story/25/12/07/1955259/how-home-assistant-leads-a-local-first-rebellion), [selfh.st survey](https://selfh.st/survey/2025-results/), [Linuxiac coverage](https://linuxiac.com/self-hosters-confirm-it-again-linux-dominates-the-homelab-os-space/)).
3. **Naming + certificates on private networks got formal recognition and new pressure.** ICANN reserved `.internal` for private use (July 29, 2024) — and public CAs *cannot* issue certs for it, making private CAs structurally necessary ([Wikipedia .internal](https://en.wikipedia.org/wiki/.internal), [Slashdot](https://it.slashdot.org/story/24/08/08/145223/icann-reserves-internal-for-private-use-at-the-dns-level)). Meanwhile CA/Browser Forum ballot SC-081v3 shrinks public TLS cert lifetimes to 47 days by March 2029, driving an industry-wide cert-automation scramble; private PKI is exempt, which makes "run your own CA with automation" more attractive, not less ([DigiCert](https://www.digicert.com/blog/tls-certificate-lifetimes-will-officially-reduce-to-47-days), [Keyfactor](https://www.keyfactor.com/education-center/what-are-47-day-certificates/), [HashiCorp](https://www.hashicorp.com/en/blog/47-day-certificates-lifespan-mandate-how-we-can-help)).

Koi's unusual shape — discovery + DNS + private CA + TLS proxy + health + runtime adapter in one cross-platform binary with an HTTP/IPC/CLI surface — sits at the intersection of all three. Below, each opportunity with evidence strength, requirements, and anti-goals.

---

## 1. Agentic AI development — STRONGEST OPPORTUNITY

**Evidence strength: Strong, and the niche is nearly empty.**

What the research shows:

- **Local MCP discovery is an unsolved, actively-discussed problem.** LibreChat has an open discussion on dynamic discovery of MCP servers running on users' machines (a Shopify team built a tunnel hack for it) ([LibreChat #9837](https://github.com/danny-avila/LibreChat/discussions/9837)). The `ultimate_mcp_client` project already listens for `_mcp._tcp.local.` via zeroconf and falls back to *port-scanning localhost* to find MCP servers ([GitHub](https://github.com/Dicklesworthstone/ultimate_mcp_client)) — i.e., the community is independently reinventing DNS-SD for MCP, badly. A `.well-known/mcp.json` convention is also emerging for web-hosted servers ([Ekamoira](https://www.ekamoira.com/blog/mcp-server-discovery-implement-well-known-mcp-json-2026-guide)).
- **The existing competition is thin.** The only mDNS MCP server found is `mcp-mdns` — a small Python package with modest tooling (browse/resolve/register) and no traction metrics ([Glama](https://glama.ai/mcp/servers/daedalus/mcp-mdns)). Adjacent servers exist for Nmap scanning, Home Assistant (`hass-mcp`), Docker, Kubernetes, and grab-bag "homelab MCP" servers ([Nmap MCP](https://glama.ai/mcp/servers/@mohdhaji87/Nmap-MCP-Server), [hass-mcp](https://pypi.org/project/hass-mcp/), [homelab-mcp](https://mcpservers.org/servers/bjeans/homelab-mcp), [kubernetes-mcp-server](https://medium.com/k8slens/18-best-devops-mcp-servers-for-2026-the-definitive-guide-bfde04654a35)). Nothing offers discovery + naming + certs + health as one coherent agent-facing surface.
- **Agents have a concrete "where is the service?" problem.** Agentic verification loops (Playwright MCP, Chrome DevTools MCP) require the agent to know which port the app is on; current solutions are hacks like writing the port to `.playwright-mcp/port.txt` ([Chrome DevTools MCP blog](https://developer.chrome.com/blog/chrome-devtools-mcp), [chrome-with-playwright](https://lobehub.com/mcp/ssv445-chrome-with-playwright)). Sandboxed agents (e2b, Daytona — which pivoted to AI-agent infra in Feb 2025; Modal; Vercel Sandbox) hit network-namespace walls reaching host services — the canonical example being `OLLAMA_HOST=0.0.0.0` workarounds ([ZenML comparison](https://www.zenml.io/blog/e2b-vs-daytona), [Northflank](https://northflank.com/blog/daytona-vs-e2b-ai-code-execution-sandboxes), [local LLM agentic coding](https://blog.alexewerlof.com/p/local-llms-for-agentic-coding)).
- **The MCP spec itself mandates the security properties Koi provides.** Streamable HTTP servers MUST validate Origin headers against DNS rebinding and SHOULD bind to localhost only; the Rust MCP SDK shipped a DNS-rebinding advisory in 2025 ([MCP spec transports](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports), [rmcp GHSA-89vp-x53w-74fx](https://github.com/modelcontextprotocol/rust-sdk/security/advisories/GHSA-89vp-x53w-74fx), [Auth0 analysis](https://auth0.com/blog/mcp-streamable-http/)). Named, TLS-secured, locally-trusted endpoints (instead of raw `localhost:port`) directly mitigate this class of problem.
- **People are already wiring agents to home infrastructure.** XDA: "I connected Claude Code to my home server through MCP, and now I manage my entire lab by talking to it"; Medium posts on Claude + k8s observability stacks; "Make Your Homelab AI Agent Ready" ([XDA](https://www.xda-developers.com/connected-claude-code-through-mcp-manage-entire-lab-by-talking/), [Medium](https://medium.com/@emmanueleshunjnr/i-connected-claude-ai-to-my-kubernetes-homelabs-observability-stack-using-mcp-here-s-how-9e5b46e9bb5f), [Medium/Wade W](https://medium.com/@_wadew/make-your-homelab-ai-agent-ready-b80247628660)). Docker's research says >25% of production code is AI-authored and agent users merge ~60% more PRs ([Docker State of App Dev](https://www.docker.com/blog/2025-docker-state-of-app-dev/)) — the population of agents that need to *find and trust* local services is growing fast.

**What Koi would need:**

- A **Koi MCP server** (likely a thin layer over the existing HTTP API — `koi-client` or a new `koi-mcp` crate) exposing: discover/resolve services, announce/unregister, DNS lookup/add, health snapshot, runtime instance list, proxy status, and cert provisioning as MCP tools. The OpenAPI surface (`surface.rs`, utoipa manifests) means tool schemas can be generated rather than hand-written.
- **Advertise the MCP endpoint itself via `_mcp._tcp` DNS-SD** — Koi could both *be* discoverable and *make other MCP servers discoverable*, positioning it as LAN-level MCP infrastructure before any convention is standardized.
- One-line registration in Docker MCP Catalog / GitHub MCP Registry / Glama / PulseMCP for distribution.
- A documented recipe: "give your coding agent a stable name + trusted TLS for the app it's building" (announce + DNS + proxy + cert in one command).

**Do NOT chase:** building an agent framework, an MCP gateway/router (crowded: Docker, Microsoft, Obot, dozens more — see [MCP Gateways 2026](https://bytebridge.medium.com/mcp-gateways-in-2026-top-10-tools-for-ai-agents-and-workflows-d98f54c3577a)), an MCP registry, or sandbox runtimes (e2b/Daytona/Modal own that). Koi is the *substrate agents discover services through*, not the agent platform.

---

## 2. Local-first / self-hosted renaissance — STRONG, CORE AUDIENCE

**Evidence strength: Strong demand signal; crowded but fragmented tooling.**

- **Scale and growth:** selfh.st 2025: 4,081 respondents; Linux 81%, Docker ~90%, Proxmox 45%, Podman 11% ([selfh.st](https://selfh.st/survey/2025-results/), [Linuxiac](https://linuxiac.com/self-hosters-confirm-it-again-linux-dominates-the-homelab-os-space/)). Home Assistant 2M+ installs ([HA blog](https://www.home-assistant.io/blog/2025/04/16/state-of-the-open-home-recap/)). One market report sizes "homelab" at $6.8B (2025) → $13.4B (2035) — treat as directional only ([MRF](https://www.marketresearchfuture.com/reports/homelab-market-21555)).
- **The #1 recurring infrastructure pain is exactly Koi's domain: the DNS + reverse proxy + certificate triangle.** Guides and threads repeatedly describe the same multi-tool gauntlet: pick NPM/Caddy/Traefik, set up Pi-hole/AdGuard for local DNS rewrites, fight Let's Encrypt DNS-01 propagation delays, deal with split-horizon DNS, and manually install root certs on every device for anything self-signed ([davidisaksson.dev](https://davidisaksson.dev/posts/reverse-proxy/), [fullmetalbrackets](https://fullmetalbrackets.com/blog/reverse-proxy-using-nginx-adguardhome-cloudflare), [selfhosting.sh](https://selfhosting.sh/foundations/reverse-proxy-explained/)). The standard "easy" answer (NPM + Let's Encrypt + public domain) requires owning a domain and leaking hostnames to CT logs — a known grumble.
- **mDNS-in-Docker is a pervasive, decade-old wart.** Containers on bridge networks can't resolve or announce `.local`; the community maintains a folklore of workarounds: avahi socket mounts, mDNS reflector containers, dnsmasq DNS→mDNS bridges, host networking ([Nathan Peck](https://nathanpeck.com/mdns-resolution-in-scratch-docker-containers/), [Medium](https://medium.com/@andrejtaneski/using-mdns-from-a-docker-container-b516a408a66b), [flungo-docker/avahi #2](https://github.com/flungo-docker/avahi/issues/2), [TrueNAS forums](https://forums.truenas.com/t/avahi-blocks-mdns-port/22560)). Koi's runtime adapter (bollard, label-driven announce) + DNS resolver is a direct, packaged answer: containers get names without touching images.
- **Private CA interest is rising in this audience.** step-ca is explicitly maintained "so that indie developers and homelabbers can easily automate certificate management"; fresh 2025 homelab tutorials keep appearing ([smallstep/certificates](https://github.com/smallstep/certificates), [Jan Wildeboer, July 2025](https://jan.wildeboer.net/2025/07/letsencrypt-homelab-stepca/), [smallstep tiny CA](https://smallstep.com/blog/build-a-tiny-ca-with-raspberry-pi-yubikey/)).

**What Koi would need:**

- A **"one binary replaces five containers" narrative** aimed at the NPM + Pi-hole-rewrites + step-ca + Uptime-Kuma-lite stack: `koi` gives names (mDNS+DNS), certs (certmesh), TLS (proxy), and health in one install — including on Windows, which almost no homelab tooling supports natively (selfh.st: Windows Server <6%, but Windows *desktop* hosts are underserved).
- Day-one content for the channels that move this community: a selfh.st writeup, r/selfhosted launch post, comparison docs vs. NPM/Caddy/Traefik + Pi-hole + step-ca.
- **Root-CA trust UX is the make-or-break detail** — koi-truststore's platform cert installation is the differentiator; document it heavily (the single biggest complaint about self-signed/private-CA setups is per-device trust).
- Integration affordances, not replacements: export/upstream modes so Koi's DNS coexists with Pi-hole/AdGuard (people will not drop their ad-blocker DNS).

**Do NOT chase:** ad-blocking DNS (Pi-hole/AdGuard own it), full reverse-proxy feature parity with Traefik/Caddy (middlewares, plugins), dashboards-as-product (Homepage/Dashy etc.), media/app catalogs, or anything resembling email. Also do not require a daemon-always architecture purity fight — homelabbers run everything in containers; ship a first-class container image and compose snippet even though the binary is the point.

---

## 3. Dev-environment orchestration — MODERATE-TO-STRONG, SHARPEST WEDGE

**Evidence strength: Strong qualitative friction; OrbStack proved the demand; one structural headwind.**

- **OrbStack's `*.orb.local` automatic domains + zero-setup HTTPS is one of its most-praised features** — dynamic cert generation, root CA auto-installed, works container-to-container ([OrbStack domains](https://docs.orbstack.dev/docker/domains), [OrbStack HTTPS](https://docs.orbstack.dev/features/https), [Arcjet blog](https://blog.arcjet.com/secure-local-node-js-dev-servers-with-orbstack/)). But it is macOS-only and proprietary. **"OrbStack domains for everyone, everywhere" is an open, unclaimed position** — and it is nearly a description of Koi's runtime adapter + DNS + certmesh + proxy.
- **localias** (Caddy wrapper: `.test` aliases, /etc/hosts management, auto-TLS, even mDNS serving to phones) shows independent demand for exactly this tool shape ([GitHub](https://github.com/peterldowns/localias), [Show HN](https://news.ycombinator.com/item?id=36006628)) — but it's a thin wrapper without discovery, health, or an API.
- **Remaining friction is well-documented:** Caddy's `*.localhost` certs aren't browser-trusted until you install its root CA ([dev.to](https://dev.to/lovestaco/serving-local-apps-securely-with-caddy-and-authentik-fixing-tls-warnings-in-development-29op)); compose services resolve by service-name internally but `localhost:port` from the host, breaking configs in both directions ([AIS](https://www.ais.com/using-docker-compose-to-locally-develop-and-test-microservices/)); compose "has not kept up with development sprawl" at dozens-of-services scale ([Docker blog](https://www.docker.com/blog/scaling-docker-compose-up/)); testing secure-context features (WebAuthn, service workers, HTTP/2) locally still requires HTTPS ceremony ([writesoftwarewell](https://writesoftwarewell.com/rails-localhost-secure-context-local-https-caddy/)). Tailscale Serve/Funnel only proxies `127.0.0.1`, Funnel is restricted to ports 443/8443/10000, and both require a tailnet ([Serve docs](https://tailscale.com/docs/features/tailscale-serve), [Funnel docs](https://tailscale.com/docs/features/tailscale-funnel)).
- **Headwind:** Docker's 2025 report says 64% of developers now primarily use *non-local* environments (up sharply) ([Docker State of App Dev](https://www.docker.com/blog/2025-docker-state-of-app-dev/)). Local-dev tooling TAM is large but no longer growing the way agent tooling is — and devcontainers/Codespaces partially sidestep the problem Koi solves.

**What Koi would need:**

- A polished `koi dev`-style golden path: label a compose service (or just run it) → it gets `name.koi.internal` (or `.local`), a trusted cert, a proxy port, and a health check, visible to teammates' phones/laptops on the LAN. The runtime adapter labels (`KoiMetadata`: dns_name, proxy, certmesh, health) already encode this; productize the workflow and document it as the headline use case.
- Cross-platform parity proof (the Windows + Linux story beats OrbStack's macOS-only).
- This wedge composes with #1: the same named-and-trusted endpoint story is what the coding agent consumes via MCP.

**Do NOT chase:** becoming a container runtime/Docker Desktop alternative, devcontainer spec tooling, internet tunneling (ngrok/Funnel/Cloudflare own public exposure — Koi should stay LAN-scoped and integrate rather than compete), or IDE plugins as a primary surface.

---

## 4. Edge/IoT discovery infrastructure — MODERATE, OPPORTUNISTIC

**Evidence strength: Real and persistent pain, but Koi addresses the diagnostic/dev slice, not the consumer slice.**

- Matter commissioning and operation depend on mDNS/DNS-SD (`_matterc._udp`, `_matter._tcp`), with Thread devices proxied via SRP on border routers ([Google Matter primer](https://developers.home.google.com/matter/primer/commissionable-and-operational-discovery)). Failures are common and miserable to debug: "mDNS error 99" OTBR crashes, commissioning stalls despite verified mDNS, cross-VLAN multicast breakage ([HA community](https://community.home-assistant.io/t/solved-how-i-fixed-my-openthread-border-router-crashing-matter-commissioning-failures-mdns-error-99/1010466), [HA community 2](https://community.home-assistant.io/t/matter-over-thread-commissioning-stalls-after-successful-thread-attach-for-eve-thermo-gen5-ula-routing-and-mdns-verified/1005391), [IoT segmentation guide](https://smartsmssolutions.com/resources/blog/business/iot-segmentation-matter-thread)). Thread 1.4's credential-sharing fix is rolling out piecemeal, leaving fragmented meshes ([Bitdefender](https://www.bitdefender.com/en-gb/blog/hotforsecurity/thread-1-4-slow-rollout)).
- The ecosystem is growing: Matter 1.5 (Nov 2025, cameras/closures/energy), Matter Compliant Platform certification for Espressif/Nordic/NXP/SiLabs, HA's record certification year ([CEPRO](https://www.cepro.com/news/connectivity-standards-alliance-releases-matter-1-5-adding-cameras-closures-and-new-energy-features/623552/), [CSA](https://csa-iot.org/newsroom/matter-compliant-platform-certification-building-on-proven-foundations-for-faster-trusted-smart-home-innovation/), [HA WWHA recap](https://www.home-assistant.io/blog/2025/12/09/wwha-2025-recap/)).

**What Koi would need:** Position the existing mDNS browser + `koi mdns discover`/`subscribe` as an **mDNS/DNS-SD diagnostic and development companion** — "is my device actually advertising? what does the network see, live?" — for ESPHome/Matter firmware developers and HA power users. Cheap additions: known-service-type annotations (`_matterc._udp`, `_hap._tcp`, `_esphomelib._tcp`, `_googlecast._tcp`), a record-level inspection view, and a how-to for debugging commissioning failures. This is documentation + presentation work on top of what already exists.

**Do NOT chase:** becoming a Matter controller/fabric admin (Home Assistant, Apple, Google own this; certification is expensive), an mDNS reflector/multicast router across VLANs (avahi-reflector territory, easy to do badly and dangerous to network stability), Thread border router functionality, or device firmware tooling. IoT here is a *user acquisition channel* into the HA/homelab community, not a product direction.

---

## 5. Zero-trust at home / TLS-everywhere on LAN — MODERATE, AS AN ANGLE NOT A MARKET

**Evidence strength: Strong top-down doctrine; thin-but-growing bottom-up enthusiast practice.**

- NIST finalized SP 1800-35 in June 2025 — 19 example ZTA builds with 24 vendors, operationalizing 800-207's "no implicit trust by network location" ([NIST](https://csrc.nist.gov/pubs/sp/1800/35/final), [Cloudflare summary](https://blog.cloudflare.com/nist-sp-1300-85/)). Machine identity / mTLS / SPIFFE is standard enterprise discourse ([GitGuardian mTLS guide](https://blog.gitguardian.com/mutual-tls-mtls-authentication/), [Petronella](https://petronellatech.com/blog/machine-identity-is-the-new-perimeter-mtls-spiffe-for-zero-trust/)).
- Bottom-up: hobbyists publish zero-trust home labs (ESP32 + private CA + MQTT-over-mTLS, complete with real-world lessons like clock-skew cert failures) ([radouane.me](https://blog.radouane.me/2025/zero-trust-iot-lab-at-home-esp32-openwrt-mtls-ids-honeypot/)); step-ca homelab adoption (above); and the `.internal` reservation makes private CAs the *only* path to TLS on the new sanctioned private TLD ([Wikipedia](https://en.wikipedia.org/wiki/.internal)). The 47-day mandate keeps "cert automation" in every practitioner's feed ([Keyfactor](https://www.keyfactor.com/education-center/what-are-47-day-certificates/)).
- However: no evidence of *mass* appetite for mTLS between LAN services in homes. The realistic 2026 home/SMB bar is "HTTPS with a trusted cert on everything, no browser warnings," not mutual auth. mTLS is an enthusiast/SMB-edge feature.

**What Koi would need:** Frame certmesh as **"TLS-everywhere for your LAN in minutes, aligned with zero-trust direction"** — server certs + auto-renewal + truststore install as the headline; mTLS between services as the advanced chapter (certmesh's enrollment ceremonies, roster, and revocation already support it). The `.internal` + private-CA pairing is a genuinely good story: Koi can be "the easy button for `.internal`." Publishing a comparison vs. step-ca (which has no DNS, no discovery, no proxy) clarifies positioning.

**Do NOT chase:** enterprise PKI/compliance markets (Keyfactor/DigiCert/Venafi/HashiCorp territory; sales-led), SPIFFE/SPIRE workload-identity integration, service meshes, identity-aware proxies/SSO (Authentik/Authelia/Pocket ID own homelab auth), or security-product certification claims. Zero-trust is *marketing language and architectural alignment* for Koi, not a product category to enter.

---

## Competitive frame (what makes Koi's position defensible)

Every neighbor solves one face of the problem: **Avahi/Bonjour** (mDNS only, no DNS/certs, painful in containers), **Pi-hole/AdGuard/Technitium** (DNS, no discovery/certs), **Caddy/Traefik/NPM** (proxy+ACME, no discovery, public-domain-oriented), **step-ca** (CA only), **mkcert** (dev certs, no automation/daemon), **OrbStack** (the full vision, but macOS-only and proprietary), **localias** (thin Caddy wrapper), **Tailscale** (overlay network, account-bound, 127.0.0.1-proxy-limited). Nobody offers discovery + naming + trust + health as one open, cross-platform, API-first substrate. That integration *is* the product.

## Prioritized recommendations

1. **Ship a Koi MCP server now** (highest leverage, lowest cost — wraps the existing HTTP API; the niche has one weak incumbent and the registries provide free distribution). Advertise it via `_mcp._tcp` and write the "named, TLS-trusted services for your coding agent" post.
2. **Productize the dev-loop golden path** ("OrbStack domains, open and cross-platform"): label container → name + trusted cert + proxy + health, one command. This is also the demo that makes #1 legible.
3. **Launch into r/selfhosted / selfh.st with the consolidation story** (replaces NPM+Pi-hole-rewrites+step-ca glue; solves mDNS-in-Docker; Windows-native). Root-CA trust UX is the review-deciding detail.
4. **Add IoT/Matter diagnostic affordances** to the mDNS browser (service-type annotations, commissioning-debug guide) as a community-entry side bet.
5. **Use zero-trust/`.internal`/47-day narratives as framing**, not roadmap: "TLS-everywhere on your LAN, the easy way."

Deliberate non-goals across all five: agent frameworks, MCP gateways, ad-blocking, tunneling/public exposure, Matter controller status, service meshes, enterprise PKI, and feature-parity wars with Caddy/Traefik. Koi wins by being the boring, trustworthy layer underneath all of those.
