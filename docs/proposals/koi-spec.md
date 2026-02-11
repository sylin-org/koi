# Koi — Local Network Toolkit

**Version:** 2.0.0-draft
**Date:** February 2026
**Author:** Leon (sylin.org)
**Status:** Design Specification
**Review:** Architecture review, ISO 27001 security evaluation, integration feasibility assessment

---

## 1. Overview

### 1.1 What is Koi?

Koi is a single-binary local network toolkit that makes LAN services discoverable, trustworthy, named, monitored, and reachable over HTTPS. It provides five capabilities — each under its own namespace — that solve specific pain points in local network operations:

1. **mDNS** — cross-platform service discovery. They find each other.
2. **Certmesh** — certificate mesh with TOTP enrollment. They trust each other.
3. **DNS** — lightweight local resolver. They name each other.
4. **Health** — present-tense network state. They watch each other.
5. **Proxy** — TLS-terminating reverse proxy. They serve each other.

Together, they close a fundamental loop: a container starts, Koi discovers it, secures it with TLS, gives it a friendly DNS name, monitors its health, and — if needed — terminates TLS on its behalf. The result is `https://grafana.lan` just works, on every device, no config.

### 1.2 Design Philosophy

Koi occupies the gap between "works on my laptop" tools (mkcert, avahi-browse) and enterprise infrastructure (step-ca, Active Directory Certificate Services, Venafi). It is designed for:

- Homelabs (5–15 machines, one operator)
- Small businesses (shared office network, a few technical staff)
- Institutions (schools, libraries, clinics — where there is a duty of care but not an IT department)

The guiding principle: **the secure path is the easy path.** Every design decision optimizes for the user never being tempted to bypass security out of frustration.

### 1.3 Single Binary, Capability Monikers

Koi ships as one binary. Capabilities are organized under root-level monikers:

```
koi mdns <command>       # Service discovery
koi certmesh <command>   # Certificate mesh
koi dns <command>        # Local DNS resolver
koi health <command>     # Network health
koi proxy <command>      # TLS-terminating reverse proxy
koi status               # Unified dashboard (cross-cutting)
koi version              # Build info
koi help                 # Usage
```

This taxonomy scales. Future capabilities slot in without touching existing namespaces. No user's muscle memory breaks when a new capability ships.

The root namespace is reserved for cross-cutting commands that span all capabilities.

### 1.4 Migration from Current Koi

The current Koi codebase provides mDNS service discovery and REST API endpoints. These existing features move under the `koi mdns` moniker:

- `koi discover` → `koi mdns discover`
- `koi announce` → `koi mdns announce`
- All existing REST endpoints move under `/v1/mdns/...`

Backward-compatible aliases print a deprecation notice for one release cycle. Existing scripts continue to work.

---

## 2. Unified Dashboard

```
koi status
```

Calls across all active capabilities and returns a single-screen summary:

```
koi v2.0.0 — local network toolkit

  mdns       3 services discovered, 0 stale
  certmesh   12 members, all certs valid (next renewal: 6d)
  dns        47 local names, upstream: 192.168.1.1
  health     11 up, 1 down (stone-09: 4h ago)
  proxy      2 services proxied, 0 errors
```

Each capability also has its own deep-dive status:

```
koi mdns status          # Detailed mDNS state
koi certmesh status      # Enrollment roster, cert expiry, CA health
koi dns status           # Registered names, upstream config, query stats
koi health status        # Per-machine and per-service health
koi proxy status         # Active proxies, cert sources, backend health
```

---

## 3. Capability: mDNS Gateway

### 3.1 Purpose

Bridges mDNS/DNS-SD across network boundaries where native multicast doesn't reach. Solves a specific Windows pain point: Windows does not natively participate in mDNS service discovery the way macOS and Linux do.

### 3.2 CLI Surface

```
koi mdns discover        # Find services on the local network
koi mdns announce        # Advertise a service
koi mdns status          # Show discovered services, cache state
```

### 3.3 Service Advertising

Koi advertises its own presence via mDNS service type `_koi._tcp`. This is how other Koi instances discover each other, and it forms the foundation for certmesh's CA discovery and DNS's resolver advertisement.

### 3.4 Service Registry

The mDNS registry tracks discovered services with TTL/staleness and last-seen timestamps. This data feeds into:

- **Certmesh** — CA discovery (`_certmesh._tcp`), SAN auto-population, failover detection
- **DNS** — service alias generation (mDNS service types become friendly DNS names)
- **Health** — machine presence detection (last-seen timestamps drive up/down status)
- **Proxy** — backend discovery (proxy can auto-detect backend addresses)

---

## 4. Capability: Certmesh

### 4.1 Problem Statement

**The mkcert ceiling.** mkcert solves localhost HTTPS on a single machine. It stops there. It has no concept of distributing trust across a network — every additional machine requires manual root CA installation.

**The Let's Encrypt floor.** Let's Encrypt DNS-01 challenge works for LAN services but requires: public domain ownership, Cloudflare API tokens (full zone access), manual Caddy/Traefik configuration, and complex renewal automation. It's a real solution, but the setup cost is disproportionate for a homelab.

**The gap.** Between mkcert (too small) and step-ca or enterprise CLM platforms (too big), there is no tool for 5–15 machine networks that want TLS without browser warnings and without a week of setup.

**The catalyst.** CA/Browser Forum Ballot SC-081v3 (approved April 2025) mandates shorter TLS certificate lifetimes:

| Date | Maximum Lifetime |
|------|-----------------|
| March 2026 | 200 days |
| March 2027 | 100 days |
| March 2029 | 47 days |

Manual certificate management becomes unsustainable. Homelab operators renewing every few weeks instead of annually need automation that doesn't require enterprise infrastructure.

### 4.2 Two Operating Modes

#### Local CA Mode (Zero Internet)

Creates a private certificate authority, mints certs signed by its own root, and distributes the root cert to all mesh members. This is mkcert scaled to a network.

- No domain required
- No internet required
- Browsers trust local services because the root CA is in every machine's trust store
- Trade-off: each machine must have the root cert installed (certmesh handles this automatically during enrollment)

#### Let's Encrypt Bridge Mode (Requires Domain)

Uses DNS-01 challenge with a real domain to obtain publicly trusted certificates for internal services.

- Requires: a domain you own, DNS provider API access (e.g., Cloudflare)
- Routes `*.home.yourdomain.com` to internal services
- Handles renewal automatically, including the 47-day timeline
- Trade-off: requires internet access and domain ownership

Both modes use the same enrollment, failover, and lifecycle infrastructure. The only difference is where the certificates come from.

### 4.3 Trust Profiles

On `koi certmesh create`, the user answers one question:

```
Welcome to Certmesh.

Who's this network for?

  1. Just me          (homelab, personal projects)
  2. My team          (small office, studio, lab)
  3. My organization  (school, library, clinic)

Choice [1]:
```

This sets security defaults appropriate to the trust model. Every feature remains available regardless of profile — profiles set the posture, not the ceiling.

#### Profile: Just Me

**Trust model:** I trust myself. Protect me from accidents.

| Setting | Value |
|---------|-------|
| Approval required | No |
| Operator name | Not prompted |
| Enrollment | Always open |
| Scope constraint | None |
| TOTP rotation reminder | None |
| Compliance summary | Simple health check |
| Cert lifetime | 30 days, renew at day 20 |
| Audit log | On (minimal) |

#### Profile: My Team

**Trust model:** I trust these people, but people come and go. Protect me from turnover.

| Setting | Value |
|---------|-------|
| Approval required | Yes |
| Operator name | Prompted |
| Enrollment | Open by default, `close-enrollment` available |
| Scope constraint | Inferred from current subnet |
| TOTP rotation reminder | Every 6 months |
| Compliance summary | Standard |
| Cert lifetime | 30 days, renew at day 20 |
| Audit log | On (standard) |

#### Profile: My Organization

**Trust model:** I answer to someone. Protect me from liability.

| Setting | Value |
|---------|-------|
| Approval required | Yes |
| Operator name | Required |
| Enrollment | Closed by default (must explicitly open) |
| Scope constraint | Required (prompted for domain and subnet) |
| TOTP rotation reminder | Every 6 months |
| Compliance summary | Full (audit-ready) |
| Cert lifetime | 30 days, renew at day 20 |
| Audit log | On (full, with operator attribution) |

The selected profile is stored in roster metadata as `trust_profile: personal | team | organization`.

### 4.4 CLI Surface

```
koi certmesh create              # Initialize CA, TOTP enrollment
koi certmesh join                # Discover mesh, enroll with TOTP
koi certmesh promote             # Become standby CA
koi certmesh status              # Enrollment roster, cert expiry
koi certmesh revoke <host>       # Remove machine from mesh
koi certmesh backup              # Export CA key + roster (encrypted)
koi certmesh restore             # Rebuild from backup
koi certmesh rotate-secret       # Generate new TOTP secret, invalidate old
koi certmesh open-enrollment     # Open enrollment window (--duration <time>)
koi certmesh close-enrollment    # Close enrollment window
koi certmesh compliance          # Security summary (adapts to trust profile)
koi certmesh log                 # View audit log
koi certmesh unlock              # Decrypt CA key after reboot
koi certmesh set-hook            # Set post-renewal reload command
```

Create-time flags (all optional, profiles set defaults):

```
koi certmesh create \
  --require-approval \
  --operator "Maria Santos" \
  --domain "lincoln-elementary.local" \
  --subnet 192.168.1.0/24
```

### 4.5 Enrollment Flow

#### Step 1 — Create the Mesh

Machine A: `koi certmesh create`

1. **Trust profile selection.** User chooses Just Me / My Team / My Organization.
2. **Entropy collection.** Before generating the CA key, active entropy is collected from the operator:

```
Creating certmesh CA...

Let's generate a strong foundation.
Mash your keyboard randomly... GO!

████████████████████ 100%

✓ Collected 256 bits of entropy
```

Three options (inherited from Zen Garden's Keystone pattern):
   - **Keyboard mashing** — the default. The operator's chaotic keystrokes seed the CA key directly. Fun and secure.
   - **Auto-generated passphrase** — XKCD-style word sequence, displayed for the user to record.
   - **Manual entry** — for operators who use a password manager.

The CA keypair is born from human entropy. On hardware with a TPM, the TPM's hardware RNG is mixed in as an additional source.

3. **Root CA generation.** ECDSA keypair generated, seeded by the collected entropy.
4. **CA key encryption.** The CA private key is encrypted at rest with a passphrase. After reboot, `koi certmesh unlock` is required before the CA can sign.
5. **TOTP secret generation.** A TOTP shared secret is created (seeded by the same entropy pool) and encrypted alongside the CA key.
6. **QR code display.** The TOTP secret is presented as a QR code for scanning into an authenticator app (Google Authenticator, Authy, etc.).
7. **Trust store installation.** The root CA public cert is installed in Machine A's local trust store.
8. **mDNS advertisement.** Machine A begins advertising `_certmesh._tcp` via Koi's mDNS.
9. **Self-certification.** Machine A mints its own service certificate, signed by the new root CA. Cert files are written to the standard cert path (see §4.9).
10. **Audit log.** First entry: `pond_initialized | operator=<name> | profile=<profile>`.

#### Step 2 — Join the Mesh

Machine B: `koi certmesh join`

1. **Discovery.** Koi discovers `_certmesh._tcp` via mDNS. Connects to the CA's certmesh API.
2. **TOTP challenge.** User is prompted for a six-digit code from their authenticator app.
3. **Rate limiting.** Three failed attempts trigger a 5-minute lockout.
4. **Approval (if enabled).** On the CA node, the administrator sees:

```
Enrollment request from: stone-05 (192.168.1.50)
TOTP code: valid
Approve? [y/N]:
```

Two-party authorization: the joiner provides the code, the administrator approves at the CA. (Disabled in "Just me" profile.)

5. **Certificate issuance.** On successful enrollment:
   - Machine B receives the root CA certificate (public only — the trust, not the power)
   - The CA mints a service certificate for Machine B with auto-populated SANs: hostname, FQDN, mDNS name (e.g., `machine-b.local`), all LAN IP addresses known to Koi
   - Machine B receives its service certificate and private key

6. **Trust store installation.** Machine B installs the root CA cert in its OS trust store. Platform-specific:
   - Linux: `/usr/local/share/ca-certificates/` + `update-ca-certificates`
   - Windows: `certutil`
   - macOS: Keychain

7. **Cert file installation.** Machine B writes cert and key files to the standard cert path (see §4.9).

8. **Certificate pinning.** Machine B records the CA's certificate fingerprint. Future connections verify both valid CA chain AND expected fingerprint.
9. **Registry update.** Machine A adds Machine B to the enrollment roster.
10. **Audit log.** Entry: `stone_joined | host=stone-05 | approved_by=<operator>`.

#### Step 3 — Ongoing Lifecycle

- Machine A tracks all enrolled members via Koi mDNS.
- Before certs expire (default: renew at day 20 of a 30-day lifetime), Machine A mints fresh certificates and pushes them to members via Koi's REST API (`/certmesh/renew` endpoint, validated by existing cert chain).
- Members install new cert files automatically (overwrite at standard cert path).
- After cert renewal, if a reload hook is configured (see §4.9), Koi executes it to notify services of the new cert.
- Every 5 minutes, members validate their cert chain with the CA (health heartbeat). Failures log warnings: expired CA, clock drift, trust store issues.

### 4.6 Failover Architecture

#### Promotion

Machine B (already enrolled as a member) runs `koi certmesh promote`.

1. TOTP challenge — same UX as joining.
2. The root CA private key is transferred, encrypted, over the TOTP-verified channel.
3. Machine B receives the full enrollment roster.
4. Machine B becomes the **standby** (warm secondary). Machine A remains the **primary** (active CA).
5. The standby syncs the roster periodically from the primary — a pull model. The response is the full registry plus a signed manifest, so the standby can verify integrity.

#### The Failover Dance

**Primary dies:**

1. Machine A's `_certmesh._tcp` service disappears from mDNS.
2. Machine B (standby) notices after a 60-second grace period (avoids failover on network hiccups).
3. Machine B promotes itself to primary. Begins minting certs, pushing renewals, answering join requests.

**Old primary returns:**

1. Machine A starts up, advertises mDNS.
2. Before claiming primary, it looks for an existing `_certmesh._tcp` primary on the network.
3. It finds Machine B. Instead of fighting for the crown, Machine A defers: "You're primary now. I'll be secondary."
4. Machine A pulls the current roster from Machine B (which may have changed — new members joined, certs renewed during A's absence), syncs up, settles into standby.

#### Design Principles

- **One active CA at a time.** No parallel signing, no serial number conflicts, no racing renewals.
- **No election protocol.** The rule: "If I wake up and someone I trust is already primary, I defer." Trust is verifiable — the primary's claim is signed by the same root CA key.
- **Deterministic tiebreaker.** If both CAs come up simultaneously and both see no primary: lowest hostname alphabetically (or earliest enrollment timestamp) wins. Whoever loses checks again, sees the winner, defers.
- **Graceful degradation.** If both CAs are down, members keep running with existing certs. Nothing breaks immediately — services stay up, HTTPS keeps working. Certs just aren't being renewed. When either CA returns, life resumes.

### 4.7 Institutional Controls

These features are activated by the "My team" and "My organization" trust profiles, or by explicit flags on any profile.

#### TOTP Secret Rotation

```
koi certmesh rotate-secret
```

Generates a new TOTP secret, displays a new QR code, invalidates the old one. Existing enrolled machines are unaffected — they're already in the mesh. Only future enrollments use the new secret.

**Use case:** Run when someone with access leaves the organization.

#### Enrollment Windows

```
koi certmesh open-enrollment --duration 1h
  Enrollment window open until 15:30 UTC.

koi certmesh close-enrollment
  Enrollment window closed.
```

Outside an enrollment window, valid TOTP codes are rejected. The IT person opens enrollment while setting up machines. The rest of the time, it's closed.

#### Operator Attribution

```
koi certmesh create --operator "Maria Santos"
```

Associates a human name with actions in the audit log. This is attribution, not authentication.

#### Certificate Scope Constraints

```
koi certmesh create --domain "lincoln-elementary.local" --subnet 192.168.1.0/24
```

The CA only mints certificates for hostnames within the specified domain and IPs within the specified subnet. Requests outside scope are refused and logged.

#### Compliance Summary

```
koi certmesh compliance
```

Adapts output to the trust profile:

**"Just me"** — simple health check:
```
certmesh: healthy
  12 members, all certs valid
  Next renewal: 6 days
```

**"My organization"** — full audit-ready summary:
```
Certmesh Security Summary
─────────────────────────
Created:          2026-02-10 by Maria Santos
Profile:          organization
CA protection:    TPM 2.0 (hardware-backed)
TOTP secret:      Last rotated 2026-02-10
Enrollment:       Closed (last open: 2026-02-10 14:00-15:00)
Approval mode:    Required (two-party)
Cert lifetime:    30 days (renews at day 20)
Scope:            lincoln-elementary.local / 192.168.1.0/24
Members:          12 active, 0 revoked
Certs expiring:   0 within 7 days
Last audit event: 2026-02-08 stone-09 cert renewed
Health:           All members reachable
```

### 4.8 Security Model

#### Trust Architecture

- The root CA private key lives only on the primary CA (and promoted standby). It never leaves those machines.
- Members receive: root CA public cert (for trust) and their own service cert + key (for identity).
- Compromise of a member = revoke that member's cert. Mesh intact.
- Compromise of the CA key = full mesh compromise. Mitigated by: encryption at rest, TPM sealing when available, passphrase-required unlock after reboot.

#### Cryptographic Controls

| Control | Implementation |
|---------|---------------|
| CA key at rest | Encrypted with operator passphrase. Requires `koi certmesh unlock` after reboot. Sealed in TPM when hardware supports it. |
| TOTP secret at rest | Encrypted alongside CA key, same protection. |
| Certificate pinning | On first enrollment, members record CA cert fingerprint. Future connections verify chain AND fingerprint. |
| Cert lifetime | 30-day default, auto-renew at day 20. Exercises renewal machinery constantly. |
| Enrollment rate limiting | 3 failed TOTP attempts → 5-minute lockout. |
| SAN auto-population | Hostname, FQDN, mDNS name, all LAN IPs from Koi discovery. Prevents "cert doesn't match" bypasses. |
| Entropy collection | Active keyboard mashing (248+ bits), mixed with TPM hardware RNG when available. |

#### Revocation

`koi certmesh revoke <host>` removes a machine from the mesh. The revocation list is pushed with roster sync. Members check the list before accepting certmesh management connections. Services on a revoked host continue with technically valid certs until expiry, but short renewal cycles (30 days) limit exposure.

#### Audit Log

Append-only, timestamped, signed. Records every: enrollment, promotion, revocation, failover event, cert renewal, enrollment window open/close, TOTP rotation, and failed enrollment attempts.

#### Backup and Recovery

```
koi certmesh backup
```

Exports: CA private key, TOTP secret, full roster, audit log. Encrypted with a user-provided passphrase (distinct from the unlock passphrase).

CLI requires confirmation:

```
⚠ This file can impersonate any machine on your network.
  Store it offline. Do not leave it in a Downloads folder.

Type EXPORT to continue:
```

`koi certmesh restore` rebuilds from the backup file. Prompts for the backup passphrase, then the new unlock passphrase.

### 4.9 Certificate File Management

Certmesh mints certificates. But minting isn't enough — services need to *find* the cert and key files. This section specifies where certs live, how services consume them, and what happens on renewal.

#### Standard Cert Path

Koi writes certificate files to a well-known, predictable location:

```
~/.koi/certs/
  <hostname>/
    cert.pem        # Service certificate (public)
    key.pem         # Service private key
    ca.pem          # Root CA public certificate
    fullchain.pem   # cert.pem + ca.pem concatenated
```

This follows the same convention used by Let's Encrypt, Caddy, and every major ACME client. Services are configured once to point at these paths. When certmesh renews, it overwrites the files in place.

On Linux, the default path is `~/.koi/certs/`. On macOS, `~/Library/Application Support/koi/certs/`. On Windows, `%LOCALAPPDATA%\koi\certs\`. The path is printed during enrollment and available via `koi certmesh status`.

#### Three Consumption Scenarios

**Scenario A — Service speaks TLS natively.**

Most production services support TLS configuration: Grafana, Nginx, PostgreSQL, Redis 6+, Node.js, Go, Rust applications. Point the service at the cert path once:

```ini
# grafana.ini
[server]
protocol = https
cert_file = /home/koi/.koi/certs/stone-05/cert.pem
cert_key  = /home/koi/.koi/certs/stone-05/key.pem
```

This is a one-time configuration. Some services hot-reload certs when files change (Nginx with `nginx -s reload`, Caddy automatically). For services that don't, Koi supports reload hooks.

**Scenario B — Docker container.**

Volume-mount the cert directory into the container:

```yaml
# docker-compose.yml
services:
  grafana:
    image: grafana/grafana
    volumes:
      - ${HOME}/.koi/certs/stone-05:/etc/koi-certs:ro
    environment:
      GF_SERVER_PROTOCOL: https
      GF_SERVER_CERT_FILE: /etc/koi-certs/cert.pem
      GF_SERVER_CERT_KEY: /etc/koi-certs/key.pem
```

Docker volume mounts are live — when Koi renews certs on the host, the container sees the new files immediately without restart (assuming the service hot-reloads).

**Scenario C — Service doesn't speak TLS.**

Some services only speak plain HTTP — legacy apps, simple tools, custom scripts. For these, `koi proxy` terminates TLS on their behalf (see §7).

#### Reload Hooks

After cert renewal, Koi can execute a command to notify a service of the new files:

```
koi certmesh set-hook --reload "systemctl reload grafana-server"
koi certmesh set-hook --reload "docker exec nginx nginx -s reload"
koi certmesh set-hook --reload "/usr/local/bin/restart-my-app.sh"
```

The hook runs after cert files are written, before the renewal is marked complete. If the hook fails (nonzero exit), the renewal is logged as degraded but the new cert files remain in place.

Hooks are per-machine, not per-service — they run on the machine that received the renewed cert. If you need per-service hooks, use a script that handles routing internally.

### 4.10 Certmesh Health Monitoring

Every 5 minutes, each mesh member:

1. Connects to the CA's certmesh endpoint.
2. Validates the certificate chain.
3. Verifies the CA cert fingerprint matches the pinned value.
4. Logs the result.

Failures trigger local warnings. Catches: expired CA, clock drift, trust store corruption, reimaged machines that lost their trust store. This is a smoke detector — runs silently, costs nothing, screams when something's wrong.

### 4.11 ISO 27001 Alignment

Certmesh was reviewed against ISO 27001 Annex A controls for proportionality to its target use cases.

| Control | Annex A Reference | Implementation |
|---------|-------------------|----------------|
| Authentication information | A.5.17 | TOTP enrollment — human-in-the-loop authorization |
| Records protection | A.5.33 | Single canonical CA, signed roster, deterministic failover |
| Use of cryptography | A.8.24 | Encrypted key at rest, certificate pinning, active entropy collection, TPM when available |
| Secure authentication | A.8.5 | TOTP rate limiting (3 attempts / 5-minute lockout) |
| Logging | A.8.15 | Append-only signed audit log with operator attribution |
| Monitoring | A.8.16 | Health heartbeat with cert chain validation |
| Security policies | A.5.1 | Trust profiles, compliance summary, security model documentation |

**Assessment:** For homelab through small institutional use (5–15 machines, technical operators), this model exceeds what most commercial products provide at comparable scale. The secure path is the easy path — users have no incentive to bypass security.

---

## 5. Capability: DNS

### 5.1 Purpose

The hosts file killer. Every homelab operator and small network administrator faces the same problem: services are running, discovery works, TLS works — and then someone types `192.168.1.47:8080` into a browser because there's no friendly name. The `.local` mDNS names work on some platforms, flake out on others, and completely fail inside container networks.

Koi DNS is a lightweight local resolver that gives services friendly names by putting a DNS face on data Koi already owns. It is not a replacement for Pi-hole, CoreDNS, or any full-featured DNS server. It answers queries for a local zone using Koi's service registry, and forwards everything else upstream.

### 5.2 Architecture

Koi starts a DNS resolver that listens on a configurable port (default: 53). It answers authoritatively for a local zone (default: `.lan`, configurable) and forwards all other queries to an upstream resolver.

**Record sources — in order of priority:**

1. **Manual static entries** — explicitly added via `koi dns add`. The hosts file replacement.
2. **Certmesh SANs** — every SAN on every certmesh member's certificate becomes a resolvable name.
3. **mDNS registry** — every service discovered by Koi gets a DNS name derived from its mDNS hostname and service type.

**Record types served:**

| Type | Source | Example |
|------|--------|---------|
| A | Machine IP from mDNS/certmesh | `stone-05.lan` → `192.168.1.15` |
| AAAA | Machine IPv6 if available | `stone-05.lan` → `fe80::1` |
| SRV | Service type + port from mDNS | `_grafana._tcp.lan` → `stone-05.lan:3000` |
| A | Friendly service alias | `grafana.lan` → `192.168.1.15` |

**What Koi DNS does NOT do:**

- No recursive resolution for the local zone — only answers from its own registry
- No caching of upstream responses (leave that to the upstream resolver)
- No DNSSEC (disproportionate for local networks)
- No zone transfer (AXFR/IXFR) — Koi is not a primary DNS server for delegation
- Never resolves a local zone name to a non-private IP address (RFC 1918 enforcement)

### 5.3 CLI Surface

```
koi dns serve                    # Start the local DNS resolver
koi dns stop                     # Stop the resolver
koi dns status                   # Registered names, upstream config, query stats
koi dns lookup <name>            # Manual query (diagnostic)
koi dns add <name> <ip>          # Manual static entry
koi dns remove <name>            # Remove a static entry
koi dns list                     # Show all resolvable names and their sources
```

Configuration flags on `koi dns serve`:

```
koi dns serve \
  --zone lan \                   # Local zone suffix (default: lan)
  --port 53 \                    # Listen port (default: 53)
  --upstream 192.168.1.1 \       # Upstream resolver (default: system resolver)
  --listen 0.0.0.0 \             # Listen address (default: LAN interfaces only)
  --service-aliases              # Generate grafana.lan from _grafana._tcp (default: on)
```

### 5.4 Name Generation Rules

When a service is discovered via mDNS or enrolled via certmesh, Koi DNS generates names automatically:

**Machine names:**
- mDNS hostname `stone-05` → `stone-05.lan`
- Certmesh enrollment with scope `lincoln-elementary.local` → `stone-05.lincoln-elementary.local` also resolves

**Service names (when `--service-aliases` is enabled):**
- mDNS service `_grafana._tcp` on `stone-05` → `grafana.lan` resolves to `stone-05`'s IP
- Multiple instances of the same service type → `grafana.lan` returns all IPs (round-robin), `grafana-stone-05.lan` and `grafana-stone-09.lan` for specific instances

**Conflict resolution:**
- Manual static entries always win
- If two machines advertise the same service type, the friendly alias returns all IPs
- If a static entry conflicts with an auto-generated name, the static entry takes precedence and a warning is logged

### 5.5 Getting Devices to Use Koi DNS

The resolver is only useful if devices send queries to it. Three approaches, in order of preference:

**DHCP integration (recommended).** If the user controls their router, they set Koi's IP as the DNS server in DHCP options. Every device on the network automatically uses Koi for DNS. This is the same pattern Pi-hole uses and is the cleanest path.

**Per-device configuration.** Each machine manually points its DNS resolver to Koi. Workable for small networks.

**mDNS DNS-SD advertisement.** Koi advertises itself as a DNS resolver via mDNS service type `_dns._udp`. Some platforms and resolvers honor this. Not universal, but free to advertise.

Koi does not modify any device's DNS configuration automatically. The user decides how DNS routing works on their network. Koi's documentation provides instructions for common routers and operating systems.

### 5.6 Integration with Certmesh

When certmesh is active, DNS gains two properties:

**Authenticated resolution.** A certmesh member can verify that `grafana.lan` resolves to a machine that is part of the mesh — the IP maps to an enrolled member with a valid certificate. This is not DNSSEC, but it is a practical trust signal: if the name resolves to a certmesh member, the connection will have valid TLS.

**SAN feedback loop.** When DNS generates a name like `grafana.lan`, and certmesh mints a certificate for the machine hosting Grafana, the SAN list should include `grafana.lan`. DNS informs certmesh of generated aliases, certmesh includes them in the next cert renewal (within 10 days on a 30-day cycle). The first request after the alias is created may not have a perfect cert match; subsequent requests will. The cert then matches every name the user might type.

### 5.7 Security Constraints

| Constraint | Rationale |
|-----------|-----------|
| Listen on LAN interfaces only by default | Prevent accidental exposure to the internet |
| RFC 1918 enforcement on local zone responses | A `.lan` name must never resolve to a public IP |
| Rate limiting on queries | Prevent Koi from being used as a DNS amplification vector |
| No open recursion | Koi forwards upstream, it does not resolve recursively itself |
| Log queries only at debug level | DNS query logs are privacy-sensitive; off by default |

---

## 6. Capability: Health

### 6.1 Purpose

"Is the thing up?" Not monitoring — health. Not "show me the p99 latency over the last six hours" but "is everything working right now, and if not, when did it stop?"

Koi already collects health data as a side effect of its other capabilities. The mDNS registry tracks last-seen timestamps. The certmesh heartbeat validates cert chains every five minutes. The DNS resolver knows which names should resolve. Health synthesizes what the other capabilities already know and presents it as a unified view.

### 6.2 Two Levels of Health

**Machine health (automatic, zero configuration).**

Derived entirely from existing Koi data:

| Signal | Source | Meaning |
|--------|--------|---------|
| mDNS presence | mDNS registry | Machine is on the network |
| Last-seen timestamp | mDNS heartbeat | How recently the machine was observed |
| Cert chain validity | Certmesh heartbeat | Trust relationship is intact |
| Cert expiry | Certmesh roster | Days until certificate expires |
| DNS resolution | DNS resolver | Machine's names resolve correctly |

No new agents, no new collectors, no new protocols. Machine health is free — Koi already has the data.

**Service health (opt-in, explicitly configured).**

One layer deeper: does the service on that machine actually respond?

| Check type | What it does | Use case |
|-----------|-------------|----------|
| HTTP | GET a URL, expect 2xx | Web apps, APIs, dashboards |
| TCP | Connect to a port, expect open | Databases, caches, message queues |

Service checks are registered explicitly:

```
koi health add grafana --http https://stone-05:3000/health
koi health add postgres --tcp stone-05:5432
koi health add redis --tcp stone-05:6379
```

Default check interval: 30 seconds. Configurable per service.

### 6.3 CLI Surface

```
koi health status                # Full health view — machines + services
koi health watch                 # Live terminal view, refreshes every 30s
koi health add <n> --http <url>     # Add HTTP service check
koi health add <n> --tcp <host:port> # Add TCP service check
koi health remove <n>         # Remove a service check
koi health log                   # State transition history
```

### 6.4 Output

```
koi health status

  Machines
  ────────
  stone-01     ✓ up    last seen: 12s ago    cert: 24d remaining
  stone-05     ✓ up    last seen: 8s ago     cert: 24d remaining
  stone-09     ✗ down  last seen: 4h ago     cert: 24d remaining

  Services
  ────────
  grafana      ✓ 200   checked: 30s ago      stone-05:3000
  postgres     ✓ open  checked: 30s ago      stone-05:5432
  nginx        ✗ 502   checked: 30s ago      stone-09:443
```

```
koi health watch
```

Live terminal view. Same layout, refreshes in place. A machine goes down, the line turns red. Comes back, turns green. Ctrl+C to exit.

### 6.5 State Transition Log

Health logs state changes — not every check, just transitions:

```
koi health log

2026-02-10 14:30:00 | stone-09   | up → down    | mDNS: not seen for 60s
2026-02-10 14:30:30 | nginx      | 200 → 502    | HTTP check failed
2026-02-10 18:45:12 | stone-09   | down → up    | mDNS: rediscovered
2026-02-10 18:45:42 | nginx      | 502 → 200    | HTTP check passed
```

Transitions only. Not every heartbeat. This keeps the log small and meaningful. For institutional profiles, this log satisfies ISO 27001 A.8.16 (monitoring activities) with zero additional infrastructure.

### 6.6 Design Boundaries

**Health is present tense only.** It answers "what is the state of my network right now?" If someone wants historical trends, graphs, dashboards, or alerting, they need a monitoring tool (Uptime Kuma, Prometheus, Grafana). Koi tells you *now*.

**No time-series storage.** The state transition log is a flat append-only file, not a database. It is not designed for querying "what was my uptime percentage last month." It is designed for "what changed since Tuesday."

**No alerting.** No email, no SMS, no webhooks, no PagerDuty. If the operator is looking at `koi health watch`, they see it in real time. If they're not looking, they see it next time they check. For a homelab, this is appropriate. For 24/7 alerting, integrate with a real monitoring stack.

**No agents.** Health checks are external probes from Koi's perspective, not self-assessment from the target machine. This answers "can I reach this service?" — the question the operator is actually asking.

### 6.7 Integration with Other Capabilities

| Capability | What health consumes | What health provides |
|-----------|---------------------|---------------------|
| mDNS | Last-seen timestamps, machine presence | Down detection for machines that stop advertising |
| Certmesh | Cert expiry, heartbeat results | Warning when certs approach expiry or chain validation fails |
| DNS | Name resolution status | Detection when a name stops resolving |
| Proxy | Backend health (proxy already probes backends) | Status of proxied services |

Health is purely a consumer of other capabilities' data for machine-level checks. Service-level checks (HTTP/TCP) are the only new network activity health introduces.

---

## 7. Capability: Proxy

### 7.1 Purpose

Certmesh mints certificates. DNS creates names. But there's a last-mile problem: how does the service actually *serve* TLS?

Services that speak TLS natively can point their config at the cert files (see §4.9). But many services — especially lightweight tools, legacy applications, and custom scripts — only speak plain HTTP. Without something to terminate TLS on their behalf, those services are unreachable over HTTPS. The operator either configures a standalone reverse proxy (Caddy, Nginx) and keeps it in sync with Koi's cert files and service registry, or gives up and uses HTTP.

Koi Proxy is a cert-aware TLS-terminating reverse proxy. It listens on a port, presents certmesh certificates to clients, and forwards plain HTTP to the backend service. It is not a general-purpose reverse proxy — it is the last piece needed so that `https://grafana.lan` works end to end.

### 7.2 What Proxy Is and Is Not

**Proxy IS:**
- A TLS terminator that uses certmesh certs automatically
- A single-purpose pipe: TLS in, HTTP out
- Aware of cert renewal (hot-reloads when certmesh overwrites cert files)
- Localhost-safe by default (backend must be on the same machine unless explicitly overridden)

**Proxy IS NOT:**
- A load balancer (no round-robin, no health-weighted routing)
- A URL rewriter (no path rewriting, no header injection)
- A WAF (no request inspection, no rate limiting on application traffic)
- A WebSocket upgrader (basic TCP proxying only — no protocol awareness)
- A virtual host router (one proxy entry = one listen address + one backend)

If someone needs Nginx features, they should use Nginx. Koi Proxy is the "I just need HTTPS on this one thing" tool.

### 7.3 CLI Surface

```
koi proxy add <name> --listen <port> --backend <url>    # Add a proxy
koi proxy remove <name>                                  # Remove a proxy
koi proxy status                                         # Show active proxies
koi proxy list                                           # List all configured proxies
```

Examples:

```
koi proxy add grafana --listen 443 --backend http://localhost:3000
koi proxy add pgadmin --listen 8443 --backend http://localhost:5050
koi proxy add homepage --listen 8080 --backend http://localhost:3001
```

Flags:

```
--listen <port>          # Port to listen on for HTTPS (required)
--backend <url>          # Backend URL to forward to (required, default: localhost only)
--backend-remote         # Allow non-localhost backend (logs warning about unencrypted hop)
--cert-path <path>       # Override cert path (default: ~/.koi/certs/<hostname>/)
```

### 7.4 How It Works

1. `koi proxy add grafana --listen 443 --backend http://localhost:3000`
2. Proxy starts an HTTPS listener on port 443 using the cert and key from `~/.koi/certs/<hostname>/`.
3. Client connects to `https://grafana.lan:443`.
4. DNS resolves `grafana.lan` to the machine's IP (see §5).
5. Proxy terminates TLS using the certmesh cert (which includes `grafana.lan` in its SANs thanks to the SAN feedback loop).
6. Proxy forwards the plain HTTP request to `http://localhost:3000`.
7. Grafana responds over HTTP. Proxy wraps the response in TLS back to the client.
8. The client sees valid HTTPS with no browser warnings.

When certmesh renews the cert, proxy hot-reloads the new files. No restart required.

### 7.5 Security Constraints

| Constraint | Rationale |
|-----------|-----------|
| Backend defaults to localhost only | The unencrypted hop should be as short as possible |
| `--backend-remote` required for non-local backends | Explicit opt-in for cross-machine unencrypted traffic, logged with warning |
| Uses certmesh certs exclusively | No self-signed certs, no manual cert management |
| Listens on specified port only | No wildcard binding, no port scanning |
| No request inspection | Proxy does not read, log, or modify HTTP payloads |

### 7.6 When to Use Proxy vs. Native TLS

| Scenario | Recommendation |
|----------|---------------|
| Service supports TLS natively (Grafana, Nginx, Postgres) | Configure service to use cert files directly (§4.9 Scenario A) |
| Docker container with TLS support | Volume-mount certs, configure service (§4.9 Scenario B) |
| Service only speaks HTTP | Use `koi proxy add` (this section) |
| Multiple services on one machine, each needs HTTPS | One proxy entry per service, different listen ports |
| Need URL rewriting, load balancing, WAF | Use Caddy/Nginx/Traefik instead — Koi Proxy is intentionally simple |

### 7.7 Integration with Other Capabilities

| Capability | How proxy uses it |
|-----------|-------------------|
| mDNS | Can discover backend services by their mDNS service type |
| Certmesh | Uses cert files from standard cert path. Hot-reloads on renewal. |
| DNS | DNS alias `grafana.lan` resolves to machine IP → proxy terminates TLS on that IP |
| Health | Proxy's backend check is a natural health signal — health can consume it |

---

## 8. Integration Model

### 8.1 How Capabilities Compose

Each capability builds on data the previous ones produce. The integration is architectural, not cosmetic:

```
Container starts on stone-05
  → mDNS announces _grafana._tcp          (discover)
    → Certmesh mints cert with SANs       (trust)
      → DNS registers grafana.lan          (name)
        → Health monitors reachability     (watch)
          → Proxy terminates TLS if needed (serve)
            → https://grafana.lan works, everywhere
```

Five capabilities. One installation. One binary. One `koi status`.

### 8.2 The End-to-End Story

A user sets up a new homelab. Here's what happens:

1. Install Koi on each machine. Run `koi certmesh create` on the first one.
2. Scan the QR code. Run `koi certmesh join` on each subsequent machine — type the TOTP code.
3. Start services. Docker Compose, systemd, whatever.

From this point forward, without any additional configuration:

- Every machine has a valid TLS certificate with all its names and IPs.
- Every service discovered via mDNS gets a `<service>.lan` DNS name.
- Every machine's health is tracked automatically.
- Services that speak TLS natively can use the cert files at `~/.koi/certs/`.
- Services that don't can be proxied with `koi proxy add`.

The user types `https://grafana.lan` in their browser. It works. No browser warnings. No cert errors. No memorizing IP addresses.

### 8.3 Communication Channels

| Channel | Protocol | Purpose |
|---------|----------|---------|
| Service discovery | mDNS `_koi._tcp` | Koi instances finding each other |
| CA discovery | mDNS `_certmesh._tcp` | Joining machines finding the CA |
| DNS advertisement | mDNS `_dns._udp` | Advertising Koi as local resolver |
| Cert enrollment | Koi REST API `/v1/certmesh/join` | TOTP-authenticated enrollment |
| Cert renewal | Koi REST API `/v1/certmesh/renew` | Push renewals, validated by existing cert chain |
| Roster sync | Koi REST API `/v1/certmesh/roster` | Standby pulls full registry + signed manifest |
| Certmesh heartbeat | Koi REST API `/v1/certmesh/health` | Periodic cert chain validation |
| DNS resolution | UDP/TCP port 53 | Local zone queries + upstream forwarding |
| Service health checks | HTTP GET / TCP connect | External probes for opt-in service monitoring |
| Proxy | HTTPS → HTTP | TLS termination for non-TLS backends |

### 8.4 Trust Store Installation

Platform-specific, vendored from mkcert's existing implementation:

| Platform | Trust Store | Method |
|----------|-------------|--------|
| Linux | `/usr/local/share/ca-certificates/` | `update-ca-certificates` |
| Windows | Certificate Manager | `certutil` |
| macOS | Keychain | Security framework |
| Firefox (NSS) | Detected separately | `certutil` (NSS variant) |

### 8.5 Mobile Device Trust

Root CA cert can be distributed to mobile devices via:

| Platform | Method |
|----------|--------|
| iOS | AirDrop the `.pem`, install in Settings > Profile Downloaded, enable full trust |
| Android | Manual install, enable user roots in development builds |

Mobile enrollment is manual and documented, not automated. Mobile devices are not mesh members — they are trust consumers.

---

## 9. Data Model

### 9.1 Roster Schema

The roster is the CA's source of truth. Synced to standby, exported in backups.

```
roster:
  metadata:
    created: 2026-02-10T14:30:15Z
    trust_profile: organization          # personal | team | organization
    operator: "Maria Santos"
    domain_scope: "lincoln-elementary.local"
    subnet_scope: "192.168.1.0/24"
    totp_secret_hash: <sha256>           # For rotation detection
    totp_rotated_at: 2026-02-10T14:30:15Z
    enrollment_state: closed             # open | closed
    enrollment_closes_at: null           # ISO timestamp or null

  members:
    - hostname: stone-01
      role: primary                      # primary | standby | member
      enrolled_at: 2026-02-10T14:30:15Z
      enrolled_by: "Maria Santos"
      cert_fingerprint: <sha256>
      cert_expires: 2026-03-12T14:30:15Z
      cert_sans: [stone-01, stone-01.lincoln-elementary.local, stone-01.local, 192.168.1.10]
      cert_path: /home/koi/.koi/certs/stone-01/
      pinned_ca_fingerprint: <sha256>
      last_seen: 2026-02-10T16:00:00Z
      status: active                     # active | revoked
      reload_hook: null                  # Optional post-renewal command

    - hostname: stone-05
      role: member
      enrolled_at: 2026-02-10T14:35:12Z
      enrolled_by: "Maria Santos"
      cert_path: /home/koi/.koi/certs/stone-05/
      reload_hook: "systemctl reload grafana-server"
      # ...

  revocation_list:
    - hostname: stone-03
      revoked_at: 2026-02-15T09:00:00Z
      revoked_by: "Maria Santos"
      reason: "device decommissioned"

  proxy_entries:
    - name: grafana
      listen_port: 443
      backend: http://localhost:3000
      backend_remote: false
      cert_source: auto                  # Uses hostname cert from standard path
```

### 9.2 Design-Time Fields

These fields must exist in the roster from day one, even if optional and usually empty. Retrofitting them later is painful:

- `trust_profile` — drives compliance summary output and default behaviors
- `operator` — attribution for audit trail
- `domain_scope`, `subnet_scope` — cert issuance constraints
- `enrollment_state`, `enrollment_closes_at` — window management
- `enrolled_by` — per-member attribution
- `totp_rotated_at` — tracks secret rotation history
- `cert_path` — where cert files live on each member
- `reload_hook` — post-renewal command
- `proxy_entries` — proxy configuration per machine

---

## 10. Security Documentation

Per ISO 27001 A.5.1, certmesh includes a single-page security model document. This page answers "how does your internal TLS work?" for anyone from a board member to an auditor.

### Certmesh Security Model (User-Facing Document)

**What's protected:** All network traffic between enrolled machines is encrypted with TLS. Every service certificate is signed by a certificate authority that you created and control.

**How enrollment works:** You scan a QR code into your authenticator app during setup. To add a new machine, type the six-digit code from your app. If approval mode is enabled, the administrator must also confirm at the CA machine.

**Where keys are stored:** The CA's signing key is encrypted on disk and requires a passphrase to unlock after reboot. On hardware with a TPM, the key is additionally sealed in hardware. The signing key exists only on the primary CA and its standby — never on regular member machines. Each machine's own service cert and key are stored at a well-known path (`~/.koi/certs/`) and are readable only by the owning user.

**How services use certificates:** Services that support TLS are configured once to point at the cert files. Services that don't support TLS can use `koi proxy` to terminate TLS on their behalf. Certificates renew automatically every 30 days — services either hot-reload the new files or are restarted by a reload hook.

**What happens during failover:** If the primary CA goes offline, the standby automatically takes over. When the original primary returns, it becomes the standby. At no point are certificates invalid — existing certs continue working regardless of CA availability.

**What you're responsible for:**
- Keep your authenticator app (it's how you authorize new machines)
- Store your backup passphrase somewhere safe and offline
- Run `koi certmesh rotate-secret` when someone with access leaves
- Run `koi certmesh backup` periodically and store the file offline

---

## 11. Build and Distribution

### 11.1 Single Binary

Koi compiles to a single binary. All capabilities are included by default.

For resource-constrained environments, Cargo feature flags allow excluding capabilities:

```bash
cargo build --no-default-features --features mdns      # mDNS only, no crypto deps
cargo build --no-default-features --features certmesh   # certmesh only
cargo build --features dns                              # add local DNS resolver
cargo build --features health                           # add health monitoring
cargo build --features proxy                            # add TLS proxy
cargo build                                             # full toolkit (default)
```

### 11.2 Supported Platforms

| Platform | mDNS | Certmesh | DNS | Health | Proxy | Trust Store |
|----------|------|----------|-----|--------|-------|-------------|
| Linux (amd64, arm64) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Windows 10/11 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| macOS (Apple Silicon, Intel) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Raspberry Pi OS | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

---

## 12. Future Capabilities (Placeholder)

The moniker system is designed to grow. Potential future capabilities:

- `koi vault` — secrets distribution across mesh members

**The boundary is the local network.** Everything that lives inside that boundary belongs in Koi. Anything that doesn't need LAN context is a different project.

---

## 13. What Not to Build

Decisions about what Koi explicitly excludes, with rationale preserved.

### Container Port Forwarding (Rejected)

**Assessment:** Trap. Docker bridge NAT, WSL2, Podman rootless, Kubernetes CNI — each different, each changing. Koi would race against container runtimes actively iterating on this problem. The real pain (reaching container services) is better solved by DNS naming + service visibility in `koi mdns status` + `koi proxy` for TLS termination.

### General-Purpose Monitoring (Rejected)

Koi health is present tense only. Time-series storage, historical graphs, alerting, webhooks, PagerDuty integration — all belong in purpose-built tools (Prometheus, Grafana, Uptime Kuma). Koi tells you *now*. If you need *then*, use a monitoring stack.

### DNSSEC (Rejected)

Disproportionate for local networks. The complexity of key management, zone signing, and chain-of-trust validation exceeds the security benefit for a `.lan` zone that never faces the public internet. Certmesh provides trust at the TLS layer instead.

### General-Purpose Reverse Proxy (Rejected)

URL rewriting, load balancing, WebSocket protocol upgrade, virtual host routing, request inspection, WAF — all belong in Caddy, Nginx, or Traefik. Koi Proxy is a cert-aware TLS pipe. If you need more, use a real reverse proxy.

---

## Appendix A: Glossary

| Term | Definition |
|------|-----------|
| CA (Certificate Authority) | The machine running the certmesh primary that signs certificates for the mesh. |
| Capability | A named functional module within Koi (mdns, certmesh, dns, health, proxy). |
| Cert path | The filesystem location where Koi writes cert and key files (`~/.koi/certs/<hostname>/`). |
| Enrollment | The process of joining a new machine to the certmesh via TOTP verification. |
| Failover dance | The deterministic process by which a standby becomes primary when the primary is unavailable. |
| Fullchain | The service certificate concatenated with the CA certificate (`fullchain.pem`). |
| Health check | An HTTP GET or TCP connect probe that verifies service reachability. |
| Hot-reload | A service detecting changed cert files and loading them without restart. |
| Local zone | The DNS zone Koi answers authoritatively for (default: `.lan`). |
| Machine health | Health status derived from mDNS, certmesh, and DNS signals — automatic, zero config. |
| Member | A machine enrolled in the certmesh with a valid service certificate. |
| Mesh | The set of all machines enrolled in certmesh that trust each other. |
| Moniker | The root-level command namespace for a capability (e.g., `koi mdns`, `koi certmesh`). |
| Operator | The human who manages the certmesh. Used for audit log attribution. |
| Pond | The certmesh trust boundary — all enrolled machines sharing a root CA. |
| Primary | The active CA that signs certificates and processes enrollments. |
| Proxy entry | A configured TLS-terminating proxy mapping a listen port to a backend URL. |
| Reload hook | A command executed after cert renewal to notify services of new cert files. |
| RFC 1918 | Private IP address ranges (10.x, 172.16-31.x, 192.168.x). Koi DNS enforces local zone names resolve only to these. |
| Roster | The CA's source of truth: all members, their certs, roles, and enrollment history. |
| SAN (Subject Alternative Name) | The list of hostnames and IPs in a certificate that the cert is valid for. |
| SAN feedback loop | DNS aliases are fed back to certmesh for inclusion in the next cert renewal. |
| Service alias | A friendly DNS name generated from an mDNS service type (e.g., `grafana.lan` from `_grafana._tcp`). |
| Service health | Health status from opt-in HTTP/TCP probes — requires explicit configuration. |
| Standby | The warm secondary CA that takes over if the primary is unavailable. |
| State transition | A change in health status (up→down, 200→502) that is logged. |
| Trust profile | The security posture setting (personal, team, organization) chosen at mesh creation. |
| Trust store | The OS-level certificate store where the root CA public cert is installed. |
| Upstream resolver | The DNS server Koi forwards non-local queries to (default: system resolver). |

---

## Appendix B: Example Sessions

### Homelab — "Just Me"

```bash
# Machine 1: Create the mesh
$ koi certmesh create
  Who's this network for? [1] Just me

  Mash your keyboard randomly... GO!
  ████████████████████ 100%
  ✓ Collected 256 bits of entropy

  ✓ Root CA created
  ✓ Scan this QR code with your authenticator:
    [QR CODE]
  ✓ Self-signed cert written to ~/.koi/certs/stone-01/
  ✓ mDNS beacon active: _certmesh._tcp

# Machine 2: Join
$ koi certmesh join
  Found certmesh CA: stone-01 (192.168.1.10)
  TOTP code: 847293
  ✓ Enrolled. Cert written to ~/.koi/certs/stone-05/

# Start DNS
$ koi dns serve
  ✓ Listening on :53, zone: .lan, upstream: 192.168.1.1
  ✓ Registered: stone-01.lan, stone-05.lan

# Service appears (Grafana started on stone-05)
$ koi mdns status
  _grafana._tcp  stone-05  192.168.1.15:3000

$ koi dns list
  grafana.lan      A    192.168.1.15   (mDNS alias)
  stone-01.lan     A    192.168.1.10   (certmesh)
  stone-05.lan     A    192.168.1.15   (certmesh)

# Grafana doesn't speak TLS — proxy it
$ koi proxy add grafana --listen 443 --backend http://localhost:3000
  ✓ Proxying https://*:443 → http://localhost:3000
  ✓ Using cert: ~/.koi/certs/stone-05/cert.pem

# Done. Open browser:
#   https://grafana.lan → works, green lock, no warnings.

$ koi status
  koi v2.0.0 — local network toolkit

    mdns       2 services discovered, 0 stale
    certmesh   2 members, all certs valid (next renewal: 20d)
    dns        3 local names, upstream: 192.168.1.1
    health     2 up, 0 down
    proxy      1 service proxied, 0 errors
```

### School — "My Organization"

```bash
# IT person creates mesh on lab server
$ koi certmesh create --operator "Maria Santos"
  Who's this network for? [3] My organization
  Domain scope: lincoln-elementary.local
  Subnet scope: 192.168.1.0/24

  [entropy collection, QR scan]

  ✓ Root CA created (organization profile)
  ✓ Enrollment: CLOSED (open with koi certmesh open-enrollment)
  ✓ Approval: REQUIRED

# Tuesday setup afternoon
$ koi certmesh open-enrollment --duration 2h
  Enrollment window open until 16:30 UTC.

# Each lab machine:
$ koi certmesh join
  TOTP code: 384721
  Waiting for approval...

# On the CA machine:
  Enrollment request from: lab-05 (192.168.1.50)
  Operator: Maria Santos
  TOTP: valid | Hostname: in scope | IP: in scope
  Approve? [y/N]: y

# Window auto-closes at 16:30

# DNS + proxy for school services
$ koi dns serve --zone lincoln-elementary.local
$ koi proxy add library-catalog --listen 443 --backend http://localhost:8080
$ koi health add library-catalog --http https://localhost:443/health

# Monthly check
$ koi certmesh compliance
  Certmesh Security Summary
  ─────────────────────────
  Created:          2026-02-10 by Maria Santos
  Profile:          organization
  Enrollment:       Closed
  Members:          15 active, 0 revoked
  Health:           All members reachable
```
