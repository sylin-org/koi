# Koi Landscape Assessment: Local-Network Tooling, 2025–2026

> Research conducted June 2026 via web search as part of the project maturity assessment.
> Companion: [trends-opportunities-2026.md](trends-opportunities-2026.md). Synthesis: [../2026-06-maturity-assessment.md](../2026-06-maturity-assessment.md).

Structure: (1) per-capability incumbent analysis, (2) the container-mDNS question, (3) the LAN-TLS question, (4) new entrants, (5) honest synthesis of Koi's differentiation.

---

## 1. Capability-by-Capability Incumbent Analysis

### 1.1 mDNS/DNS-SD daemons (vs. Koi's mDNS domain)

**Avahi** — The Linux incumbent, but visibly decaying. A 2022 GitHub issue asked outright "Is Avahi abandoned? New maintainer?" ([avahi/avahi#388](https://github.com/avahi/avahi/issues/388)); releases are rare and security response is slow — the fix for CVE-2025-59529 was still under discussion months after disclosure ([Ubuntu CVE tracker](https://ubuntu.com/security/CVE-2025-59529)). Distros have started disabling it in updates ([Manjaro forum, 2025](https://forum.manjaro.org/t/no-more-ipp-everywhere-avahi-disabled-after-stable-update-2025-05-14/178259)). Linux-only, C, D-Bus API (no HTTP), root daemon. *Gap Koi fills: cross-platform, HTTP/REST API, lease/heartbeat lifecycle, no D-Bus. Gap Koi doesn't fill: Avahi's deep distro integration (nss-mdns, CUPS/IPP discovery) — Koi can't be the system resolver for `.local` on Linux without competing with the host stack.*

**Apple Bonjour/mDNSResponder** — Canonical implementation on macOS/iOS; open source ([apple-oss-distributions/mDNSResponder](https://github.com/apple-oss-distributions/mDNSResponder)). But **Bonjour for Windows is effectively dead**: last standalone release 2015, and Windows 11 25H2's LSA protection now actively blocks the outdated `mdnsNSP.dll` ([elevenforum](https://www.elevenforum.com/t/bonjour-for-windows-version-3-0-0-10-vs-version-2-0-2-and-windows-11-lsa.41412/), [winhelponline](https://www.winhelponline.com/blog/mdnsnsp-bonjour-blocked-lsa/)). Windows has had native mDNS since 10 1703, and even iTunes/Windows MIDI 2.0 dropped Bonjour ([Wikipedia](https://en.wikipedia.org/wiki/Bonjour_(software))). *Implication: there is no good cross-platform mDNS daemon with a modern API in 2026 — the Windows story in particular is fragmented between half-implemented native mDNS and a zombie Apple port. This is Koi's strongest single claim.*

**systemd-resolved** — Default on most modern Linux distros; has mDNS resolver+responder but it is demonstrably flaky: "mDNS/LLMNR stop working after a while" ([systemd#36078](https://github.com/systemd/systemd/issues/36078), Jan 2025), "fails to respond to mdns" ([systemd#36315](https://github.com/systemd/systemd/issues/36315), Feb 2025), long-standing conflicts when Avahi coexists ([RH bugzilla 1867830](https://bugzilla.redhat.com/show_bug.cgi?id=1867830), [ArchWiki](https://wiki.archlinux.org/title/Systemd-resolved), [Debian forums](https://forums.debian.net/viewtopic.php?t=156449)). It resolves but does not do DNS-SD service browsing/registration in any practical API form. *Koi's mDNS layer coexists rather than replaces; the flakiness of resolved is evidence the "it just works" baseline doesn't exist on Linux.*

**mDNS libraries** (what developers actually use): [keepsimple1/mdns-sd](https://github.com/keepsimple1/mdns-sd) (Rust — Koi's own engine), python-zeroconf, mdnsjava, mdns_lite (Elixir), etc. Every language re-implements mDNS in-process. No incumbent offers "one host daemon, HTTP API, any language" — [troglobit/mdnsd](https://github.com/troglobit/mdnsd/blob/master/API.md) is the closest Unix attempt and it's a C library/daemon, not HTTP. *Genuine gap.*

### 1.2 Local DNS resolvers for friendly names (vs. koi-dns)

**Pi-hole / AdGuard Home / Technitium / dnsmasq** — Extremely mature, huge communities. For *local records specifically*: Pi-hole and AdGuard Home do basic A/CNAME local records; Technitium is a full authoritative server (zones, DNSSEC, DHCP, split-horizon, clustering, DoH/DoT/DoQ) and is increasingly recommended as the "serious" homelab DNS ([Lawrence Systems forum](https://forums.lawrencesystems.com/t/dns-options-adguard-home-vs-pihole-vs-technitium/25320), [selfhosting.sh comparison](https://selfhosting.sh/compare/pi-hole-vs-technitium/), [XDA on Technitium](https://www.xda-developers.com/pihole-alternative-called-technitium/), [AdGuard vs Technitium](https://dev.to/selfhostingsh/adguard-home-vs-technitium-which-dns-server-pg9)). dnsmasq remains ubiquitous in routers. *Honest assessment: standalone local DNS is a crowded, well-served space. Koi-dns cannot win on DNS features. Its only defensible angle is integration — DNS records auto-populated from mDNS discovery, certmesh membership, and container lifecycle, with zero zone-file editing. No incumbent does that wiring automatically.*

**The "*.local" pain** is real and persistent: `.local` is reserved for mDNS, multicast doesn't cross VLANs by design, and homelabbers run Avahi reflectors/mdns-repeater with known noise/security tradeoffs ([XDA: mDNS across VLANs](https://www.xda-developers.com/make-mdns-work-across-vlans/), [OpenWrt forum on avahi reflectors](https://forum.openwrt.org/t/advice-needed-iot-vlan-mdns-avahi-ssdp/242639), [christophersmart.com](https://blog.christophersmart.com/2020/03/30/resolving-mdns-across-vlans-with-avahi-on-openwrt/)). A unicast DNS view of mDNS-discovered services (which Koi's dns+mdns combination implies) is a legitimately useful bridge that today requires manual glue.

### 1.3 Overlay networks: Tailscale, NetBird, ZeroTier (partial overlap)

These solve a *different* problem (WAN-spanning private networks) but increasingly absorb Koi's use cases:

- **Tailscale**: MagicDNS gives friendly names; `tailscale cert` gives real Let's Encrypt certs for `*.ts.net` names; **Tailscale Services** (beta Oct 2025, [GA 2026](https://tailscale.com/blog/services-ga)) adds named virtual services with stable MagicDNS names decoupled from machines ([blog](https://tailscale.com/blog/services-beta), [docs](https://tailscale.com/kb/1552/tailscale-services)) — this is service discovery, Tailscale-style. Limits: proprietary control plane (Headscale unofficial), names confined to `tailNNNN.ts.net`, certs leak hostnames to CT logs, 90-day manual renewal unless using Caddy integration ([Tailscale HTTPS docs](https://tailscale.com/docs/how-to/set-up-https-certificates)), and **only devices in the tailnet benefit** — a smart TV, printer, or guest device on the LAN sees nothing.
- **NetBird**: fully open-source (BSD-3) self-hostable control plane, DNS groups/match-domains, raised a **$10M Series A (Jan 2026)** ([tech.eu](https://tech.eu/2026/01/13/netbird-announces-10m-series-a-to-expand-open-source-vpn-alternative/), [comparison](https://wz-it.com/en/blog/netbird-vs-tailscale-comparison/)). Momentum is real.
- **ZeroTier**: BSL-licensed since 1.4.2 (not OSI open source) ([ZeroTier on GPL→BSL](https://www.zerotier.com/news/on-the-gpl-to-bsl-transition/)), L2 capable (can even carry multicast/mDNS across sites — its unique trick).

*Honest assessment: for the "developer wants friendly names + HTTPS on their own machines" use case, Tailscale is the dominant convenient answer in 2026 and is expanding into service abstractions. Koi's differentiation is being LAN-native (no overlay, works for every device on the network including non-enrolled ones), no account/SaaS, and no `.ts.net` namespace dependency.*

### 1.4 Private CA / LAN TLS (vs. koi-certmesh)

- **mkcert**: beloved, simple, ~v1.4.4 with no substantive release since 2022; issues pile up; per-machine manual root distribution; no renewal, no revocation, no multi-host story ([releases](https://github.com/FiloSottile/mkcert/releases), [discussion on avoiding per-device CA imports](https://github.com/FiloSottile/mkcert/discussions/587)). Dev-laptop tool, not a network tool.
- **step-ca (Smallstep)**: the serious self-hosted ACME CA ([private ACME server](https://smallstep.com/blog/private-acme-server/)). Mature, well-documented, but operationally heavy for homelab: you run a CA server, bootstrap roots onto every client (`step ca bootstrap`), default 24h cert lifetimes fight standard ACME clients ([smallstep ACME client docs](https://smallstep.com/docs/tutorials/acme-protocol-acme-clients/)), and root distribution to phones/TVs/IoT remains manual ([apalrd's homelab CA writeup](https://www.apalrd.net/posts/2023/network_acme/), [koromatech step-ca guide](https://koromatech.com/master-ssl-pki-in-your-homelab-build-a-self-hosted-ca-with-step-ca-phase-1-part-1/)).
- **Caddy local CA**: Caddy auto-creates a Smallstep-powered local CA and auto-installs the root into the *local* trust store; other machines still need manual root install ([Caddy automatic HTTPS docs](https://caddyserver.com/docs/automatic-https), [caddy community thread](https://caddy.community/t/caddy-and-local-https/14284)).
- *Koi certmesh's differentiated bits*: ceremony-based enrollment with TOTP/FIDO2, envelope-encrypted CA key, roster/audit/compliance, auto-install into platform trust stores (koi-truststore), standby promotion. **No incumbent combines enrollment auth + trust-store installation + mesh roster in one tool.** The risk: this is the most complex part of Koi and the part where "just use Caddy/step-ca/Tailscale certs" is the entrenched reflex. And the unsolvable part — getting the root onto unmanaged devices (iOS profiles, Android warnings, smart TVs) — is equally unsolved for Koi ([iOS root CA install](https://uclobby.com/2014/01/09/installing-private-ca-root-certificate-on-ios-devices/), [homelab PKI writeup](https://derlev.xyz/blog/2024/homelab-pki/)).

### 1.5 Reverse proxy (vs. koi-proxy)

**Caddy, Traefik, Nginx Proxy Manager** own this space completely. Traefik's Docker-label auto-discovery and caddy-docker-proxy's label-driven Caddyfile are the standard patterns ([caddy-docker-proxy](https://github.com/lucaslorentz/caddy-docker-proxy), [2026 comparison](https://homelabaddiction.com/nginx-proxy-manager-vs-caddy-vs-traefik/), [PkgPulse 2026 guide](https://www.pkgpulse.com/guides/caddy-vs-traefik-vs-nginx-proxy-manager-reverse-proxies-2026)). *Koi-proxy cannot and should not compete feature-wise; its only justification is being the pre-wired TLS termination endpoint for certmesh certs so users don't have to configure Caddy against a private CA. Position it as convenience glue, not a proxy.*

### 1.6 Health checks (vs. koi-health)

Served by Uptime Kuma, Gatus, Beszel, Homepage widgets, etc. — enormous, mature ecosystem. *Koi-health is table-stakes glue (feeding DNS/proxy/mDNS state), not a differentiator. Don't market it as one.*

### 1.7 UDP bridging (vs. koi-udp)

Prior art exists for UDP-over-HTTP/WebSocket tunneling — [erebe/wstunnel](https://github.com/erebe/wstunnel), [GOST](https://gost.run/en/tutorials/reverse-proxy-tunnel/) — but these are firewall-traversal tools, not "host daemon offers containers a leased UDP socket via HTTP+SSE" APIs. Koi's framing (container in bridge network gets host UDP presence — for mDNS-adjacent protocols, SSDP, WS-Discovery, game servers) appears novel. *Novel but niche; the audience that needs it overlaps heavily with the container-mDNS audience.*

### 1.8 Container runtime discovery (vs. koi-runtime)

Label-driven container automation is a proven pattern (Traefik, caddy-docker-proxy, [phyber/docker-mdns](https://github.com/phyber/docker-mdns) — Avahi-publishing from Docker labels, Linux-only; [mageddo/dns-proxy-server](https://github.com/mageddo/dns-proxy-server) — container hostnames into DNS; gliderlabs/resolvable, abandoned). **OrbStack** (macOS-only, commercial) is the gold standard UX here: every container gets `name.orb.local` + automatic HTTPS with auto-trusted local CA, zero config ([docs](https://docs.orbstack.dev/docker/domains), [HTTPS](https://docs.orbstack.dev/features/https)) — proof the integrated experience is wanted; no cross-platform open-source equivalent exists. *Koi's koi-runtime + mdns + dns + certmesh + proxy is effectively "open-source OrbStack-domains for any Linux/Windows host." That's a strong, articulable position.*

---

## 2. Is "mDNS for containers via host daemon + HTTP API" a real unsolved pain in 2026?

**Yes — the pain is well-documented and the existing answers are all workarounds.** Evidence:

- Docker's bridge networking blocks multicast by design; issues span a decade and remain open-ended: [moby#3043 multicast between containers](https://github.com/moby/moby/issues/3043), [moby#23659 external multicast inside container](https://github.com/moby/moby/issues/23659), [moby#38531 cannot access .local domains in Docker](https://github.com/moby/moby/issues/38531).
- Application ecosystems hit it constantly: Home Assistant officially documents that mDNS/zeroconf discovery requires host networking and *still* partially fails ([home-assistant.io#14153](https://github.com/home-assistant/home-assistant.io/issues/14153), [core#36303](https://github.com/home-assistant/core/issues/36303), [HA community thread](https://community.home-assistant.io/t/discovery-not-possible-because-the-docker-container-is-not-on-the-same-network/175620)); Homebridge ([docker-homebridge#552](https://github.com/homebridge/docker-homebridge/issues/552)); Shairport-sync's "Host name conflict" when container-Avahi fights host-Avahi ([shairport-sync#1704](https://github.com/mikebrady/shairport-sync/issues/1704)).
- Current workarounds, each deficient: host network mode (breaks isolation, collides daemons), macvlan (router/Wi-Fi headaches), mounting host D-Bus + Avahi socket into containers (Linux-only, privileged-ish, fragile — [Andrej Taneski's Medium walkthrough](https://medium.com/@andrejtaneski/using-mdns-from-a-docker-container-b516a408a66b), [conway.scot](https://conway.scot/mdns-docker/)), host-side dnsmasq forwarding tricks for `.local` *resolution* ([Nathan Peck's writeup](https://nathanpeck.com/mdns-resolution-in-scratch-docker-containers/)), and label-watching Avahi publishers ([phyber/docker-mdns](https://github.com/phyber/docker-mdns), [damonmorgan fork](https://github.com/damonmorgan/docker-mdns)) which handle *publishing only*, on Linux only, with Avahi as a dependency.
- **What does not exist**: a cross-platform host daemon exposing register/browse/resolve over plain HTTP that any container on a bridge network can call, with lease-based cleanup when the container dies. The demand signal is the steady stream of issues above plus the per-language reimplementation pattern (every stack embeds python-zeroconf/mdns-sd/etc. and then hits the multicast wall in containers anyway).

**Caveats for honesty**: the population that (a) runs containers, (b) needs LAN-facing mDNS (AirPlay/HomeKit/Chromecast/printers), and (c) won't just use host networking, is a subset of homelabbers. Many users' actual need is "reach my container by name from my laptop," which Traefik+local-DNS or OrbStack already solve without mDNS. Koi's pitch should be precise: it solves *LAN-visible service announcement and discovery for containerized apps*, not generic container DNS.

## 3. Is "TLS on the LAN without certificate warnings" still unsolved for homelabs in 2026?

**Substantially yes — every mainstream approach has a structural flaw.** What people actually do:

1. **Real domain + Let's Encrypt DNS-01 wildcard + split-horizon DNS** — the dominant r/selfhosted answer ([Ben Soer's Medium guide](https://medium.com/@bensoer/setup-tls-certificates-with-letencrypt-for-your-homelab-with-coredns-docker-and-traefik-525158ed78fc), [HomeLab Starter](https://homelabstarter.com/homelab-certificate-management/)). Falls short: requires owning a domain, a DNS provider with API support, leaks internal hostnames to CT logs (wildcards mitigate), and ties LAN trust to external infrastructure.
2. **Tailscale certs** — easy but `*.ts.net` only, tailnet-only clients, CT exposure, 90-day manual renewals outside Caddy ([Tailscale docs](https://tailscale.com/docs/how-to/set-up-https-certificates), [XDA walkthrough](https://www.xda-developers.com/enabled-https-secure-self-hosted-apps-tailscale/)).
3. **mkcert / Caddy local CA / step-ca** — works, but root distribution to every device is manual and ongoing, and step-ca is operationally heavy (see 1.4).
4. **New 2025–2026 development**: Let's Encrypt now issues **IP-address and 6-day certificates, GA Jan 15 2026** ([announcement](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability), [2025 preview](https://letsencrypt.org/2025/01/16/6-day-and-ip-certs)). Important nuance: IP certs require http-01/tls-alpn-01 — the IP must be *publicly reachable* — so **RFC1918 LAN addresses remain categorically excluded from publicly-trusted TLS**. The CA/Browser Forum forbids certs for private IPs/internal names; that constraint is permanent, which means private-CA approaches are the only path for purely-internal TLS, and the root-distribution problem they carry is the actual unsolved core.

**Where Koi lands**: certmesh automates the CA + issuance + machine trust-store install + renewal/roster across enrolled machines — a real improvement over mkcert-by-hand and lighter than step-ca. But it cannot solve the unmanaged-device problem (phones, TVs, guests) any better than anyone else, and it asks users to trust a young project for PKI, where conservatism is rational. The honest positioning: "as easy as mkcert, as automated as step-ca, mesh-aware like neither" — for the enrolled-machine population only.

## 4. Notable new entrants, 2024–2026

- **Pangolin** (Fossorial, YC '25) — self-hosted Cloudflare-Tunnel alternative (WireGuard + Traefik + identity), ~19k GitHub stars, the breakout homelab networking project of 2025 ([Show HN](https://news.ycombinator.com/item?id=44526015), [XDA](https://www.xda-developers.com/replaced-cloudflare-tunnel-with-pangolin-own-my-whole-ingress-path/)). Solves *ingress from outside*, not LAN-internal naming/trust — complementary, but it absorbs homelab mindshare and the "secure access to my services" budget.
- **NetBird** — $10M Series A Jan 2026, fully open-source mesh VPN with DNS management ([tech.eu](https://tech.eu/2026/01/13/netbird-announces-10m-series-a-to-expand-open-source-vpn-alternative/)).
- **Tailscale Services** (beta Oct 2025 → GA) — service-level naming/policy abstraction ([blog](https://tailscale.com/blog/services-beta)); Tailscale is moving up-stack into exactly the "stable name for a service, wherever it runs" territory.
- **Anchor / lcl.host** — hosted private-CA-as-a-service giving developers `*.lcl.host` local HTTPS with trust-store sync ([anchor.dev](https://anchor.dev/blog/introducing-lcl-host)) — validates demand for "local TLS without ceremony," though it's localhost-dev-focused and SaaS-dependent.
- **OrbStack** (macOS) — `*.orb.local` container domains + automatic HTTPS, zero-config ([blog](https://orbstack.dev/blog/orbstack-1.1-https)) — the UX benchmark Koi should cite.
- **Technitium DNS** — not new but newly ascendant as the homelab DNS power tool ([XDA](https://www.xda-developers.com/pihole-alternative-called-technitium/)).
- No direct competitor found for "single cross-platform Rust binary unifying mDNS + DNS + CA + proxy + container discovery over an HTTP API." Searches for such a tool surface only single-purpose projects.

## 5. Synthesis: where Koi is differentiated vs. already-served

**Genuinely differentiated (defensible):**

1. **Cross-platform mDNS daemon with an HTTP/IPC API** — Avahi is Linux-only and semi-maintained, Bonjour-for-Windows is dead, systemd-resolved is flaky, and every language reimplements mDNS in-process. Nothing else offers language-agnostic register/browse/resolve over HTTP with leases. This is Koi's beachhead.
2. **Container mDNS presence without host networking** (runtime watcher + label-driven announce + UDP bridge) — documented decade-old pain, only Linux-only Avahi-glue workarounds exist.
3. **The integration itself**: discovery → DNS names → certs → proxy as one coherent zero-config pipeline ("open-source OrbStack-domains for any host"). Incumbents each solve one layer; the wiring is the product.

**Already well-served (Koi should frame as glue, not as competing features):**

- Standalone local DNS (Technitium/AdGuard/Pi-hole/dnsmasq), reverse proxying (Caddy/Traefik/NPM), health checks (Uptime Kuma/Gatus), private ACME CA at scale (step-ca), overlay networking and remote access (Tailscale/NetBird/Pangolin).

**Structural headwinds to acknowledge:**

- The Tailscale-shaped gravity well: for many developers "install Tailscale, use ts.net certs" is good enough, and Tailscale Services moves further into service naming.
- PKI trust is reputation-bound; certmesh's sophistication (TOTP/FIDO2 ceremonies, envelope encryption) exceeds what the homelab audience expects from a young project, while the hard residual problem (unmanaged-device root install) stays unsolved for everyone.
- Breadth risk: seven capabilities invite comparison with seven mature incumbents; the credible narrative is the mDNS/container/naming/trust *pipeline*, with proxy/health as conveniences.
