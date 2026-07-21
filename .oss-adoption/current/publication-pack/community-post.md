Status: complete
Run ID: 20260719T034411Z
Project: koi
Created: 2026-07-19T03:44:11Z

# Community post draft

Target community: r/selfhosted, only after Koi is truthfully production-ready
Current rules verified: 2026-07-19 at https://www.reddit.com/r/selfhosted/about/rules/
Publication gate: closed; maintainer review and explicit posting authorization required

## Draft

This is a future message concept, not an authorized post. The maintainer must re-check all
facts, links, maturity language, rules, and support capacity before writing the final post.

> I maintain Koi, an open-source LAN toolbox for a problem I kept recreating in homelabs:
> getting a service running is easy, but making it discoverable, giving it a stable local
> name, trusting it over HTTPS, and keeping that state in sync usually means wiring several
> tools together by hand.
>
> Koi connects that path in one cross-platform binary: mDNS/DNS-SD discovery, local DNS,
> private CA and trust-store workflows, TLS serving, health, and Docker/Podman lifecycle.
> It runs locally without an account or cloud dependency.
>
> It is meant to sit under the stack you already like. Pi-hole, AdGuard, or dnsmasq can
> forward one zone to Koi. Tailscale can use its resolver for split DNS. Caddy or Traefik
> can consume its private ACME/certificate path and existing labels. Prometheus can consume
> its HTTP service-discovery export.
>
> The evaluation path starts with `koi mdns discover`, then a documented discover -> name
> -> trust -> serve demo using a disposable service. Installation, security boundaries,
> upgrade, and removal guidance live at https://sylin.org/koi and
> https://github.com/sylin-org/koi.
>
> I would value clean-machine reports from mixed Windows/Linux/macOS networks, native Linux
> bridges, Docker Desktop, Pi-hole/AdGuard, and Caddy/Traefik setups - especially where the
> trust boundary or uninstall behavior is unclear.

At preparation time Koi's own status says pre-1.0 and not load-bearing. This concept must
therefore not be posted now. The owner may write a final version only after recording the
production-ready decision and satisfying the community rule truthfully.

## Rule and tone check

- Disclose maintainer affiliation in the first sentence and avoid repeated promotion.
- Link a released, downloadable, self-hostable build a reader can try immediately.
- Meet the current production-ready rule; this is the hard gate not met today.
- Keep install/use, security, limitations, upgrade, uninstall, and trust-removal docs
  aligned with the released artifact.
- Explain features and operator benefit without attacking adjacent projects.
- Ask for reproducible operational feedback, never stars, votes, or amplification.
- Re-open the official rules URL on posting day because community rules can change.

## Follow-up plan

- Reserve two hours after posting and daily review time for the following week.
- Reply personally, disclose uncertainty, and reproduce reports before offering a fix.
- Convert confirmed problems into issues without copying identifying/private information.
- Correct factual errors in the thread where authorized.
- Stop outreach if a severe trust/reliability defect appears or support is untriaged for
  more than seven days.
- Review completed installs, retained use, issue quality, and integration patterns after
  two weeks; points and stars are secondary context.
