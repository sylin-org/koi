---
type: WORKING
title: "Animated explainer briefs — capability behavior, user POV"
audience: [design, docs]
status: working-draft
last_updated: 2026-06-25
---

# Animated explainer briefs

Content briefs for building **rich animated explainers** of Koi's capabilities (e.g. to
hand to a design agent). Each brief describes, **in plain steps and from the user's point
of view, what the feature does** — the experience and the behavior, not the wire
mechanism. The design work decides how to render it; these briefs are the substance.

**The one rule:** show the feature from the *user's* perspective — what it's for, what
they do, what they get. Mechanism (CSRs, mTLS, ports, byte sniffs) appears only as
something the viewer *watches happen*, never as jargon on screen.

Multi-state capabilities are broken into their **scenarios/states**. Italic *"Stays true"*
notes mark the few places the simple telling tends to over-claim — keep those honest; they
don't constrain how it looks.

> *Optional house look:* Koi's shipped UI ("Lantern/Vellum" — warm-paper glassmorphism,
> muted sage/clay/ochre/brick accents, a monospace voice, the koi-fish glyph 𓆝) is
> available as brand context in `crates/koi-dashboard/assets/`. Treat it as reference, not
> a constraint.

---

## The big picture — one binary, four things, four ways to run it

**What it is:** A LAN ships with almost nothing. Koi is one binary that gives it the four
things it lacks, wired together as a pipeline — and the same binary behaves differently
depending only on how you run it.

**The pipeline (each step feeds the next):**

1. **Discover** — a service announces itself and others find it.
2. **Name** — that service automatically gets a stable name.
3. **Trust** — that name gets a certificate your machines trust.
4. **Serve** — that certificate fronts the service over HTTPS.
5. Label a container and all four happen end-to-end, untouched.

**The four access shapes:**

- Run it with `--daemon` or install it → one full **daemon** owns the toolbox.
- Run a command normally → it **talks to the healthy local daemon** (or `--endpoint`).
- Add explicit `--standalone` with the service stopped → one local composition runs and **exits**.
- Link it into a Rust app → it runs **inside your app**.

---

## Discovery & naming

### mDNS discovery — find and announce services on the LAN

*Purpose: any machine can publish a service and any other can find it, with no config and
no central registry.*

1. On one machine, announce a service (a name, a type, a port). It's live on the LAN until
   you stop it.
2. On another machine, browse — services show up as answers arrive (it's a live stream,
   not an instant list). Ask for a type to get full host/IP/port details.
3. Resolve a single service to get its full address, port, and metadata.
4. Subscribe to watch a live feed of services appearing, resolving, and going away.
5. When a service stops, it actually disappears — no stale ghosts left behind.

*Stays true: it's LAN-scoped (doesn't cross subnets on its own), and discovery is a stream
whose answers trickle in over a few seconds.*

### The .internal zone — stable local names

*Purpose: give services real names like `grafana.internal` that resolve on your LAN,
without editing hosts files or zone files.*

1. Add a name pointing at an IP — it resolves immediately as `<name>.internal`.
2. Names also appear on their own: from discovered services and from issued certificates.
3. Anything *not* in your zone is passed through to your normal DNS — so Koi sits alongside
   your router / Pi-hole rather than replacing it.
4. The `.internal` suffix is the one private suffix a certificate authority can issue
   trusted TLS for — so the name you resolve is exactly the name your cert is signed for.

---

## Trust & serving

### Trusted HTTPS (certmesh) — your own private CA for the LAN

*Purpose: give your LAN trusted HTTPS — the green padlock, no browser warnings — without a
public certificate authority and without the internet. One machine runs a private CA;
every machine you enroll trusts it, so `https://` between your own machines just works.*

**Scenario 1 — One host stands up trust.**

1. You run a single command on one host to create a private CA.
2. That host immediately gets three things on its own: its own certificate authority, a
   certificate for itself, and trust in its own CA root.
3. To turn that into an actual green-padlock site, you point a TLS endpoint at the
   certificate (Koi's proxy, or your own app) and give the service a name.
4. Now browsing that service *from that same host* is trusted — no warning. But so far,
   only that one host trusts the CA; the rest of the LAN doesn't yet.

**Scenario 2 — A second machine joins.**

1. You install Koi on a second machine and enroll it against the first, using a single-use
   invite handed out by the CA host.
2. The new machine makes its own private key locally — the key never leaves it — and sends
   only a request to be signed.
3. The CA signs it and the machine installs the shared CA root, so it now trusts the mesh.
4. Both machines now hold CA-signed certificates and trust the same root → HTTPS between
   them is trusted, no warnings, in both directions.

**Scenario 3 — The whole LAN.**

1. Repeat the enrollment for each machine.
2. Every machine trusts the one shared root, so every machine's HTTPS is trusted by every
   other — it's one root everyone trusts, not each pair swapping certificates.
3. A machine that only needs to *view* mesh HTTPS (not serve it) doesn't fully enroll — it
   just installs the CA root.

**Scenario 4 — Renewal takes care of itself.**

1. Certificates expire (they live ~90 days). On the public internet, this is the moment a
   forgotten renewal makes a site show "your connection is not private."
2. With certmesh, each machine renews its own certificate automatically in the background,
   *before* it expires.
3. It rotates to a fresh key, swaps the certificate in place, and the service keeps
   serving — no downtime, nothing for you to do.
4. The reason public sites break here — the thing that renews and the thing that serves
   being two systems that drift out of sync — doesn't happen, because the same machine does
   both.

**Scenario 5 — A machine that was offline comes back.** *(two states)*

- **State A — back before it expired:** the machine reconnects and the background renewal
  quietly catches it up. It's healthy again with no action from you.
- **State B — offline so long its certificate actually expired:** it can no longer
  auto-renew. You bring it back by simply re-running the join — mint a fresh invite on the
  CA, run join on the machine. It makes a new local key and gets a fresh certificate. Same
  identity, key still never leaves it.

**Scenario 6 — Two edge states (optional).**

- **A revoked machine:** you can revoke a member; it can no longer renew and is locked
  out — but a certificate it already holds keeps working until it expires (there's no
  instant network-wide kill).
- **The CA host dies:** existing member certificates keep working (they have weeks of life
  left); renewals just pause until you restore the CA from a backup or promote a standby.
  Members don't have to re-enroll.

*Stays true: standing up the CA doesn't by itself make a site green — you still serve TLS
and name it, and other clients go green only once they trust the root. And the line between
"self-heals" and "must rejoin" is the certificate actually expiring, not a fixed grace
period.*

### ACME issuance — your existing cert tools, pointed at your own CA

*Purpose: let standard tools (Caddy, Traefik, lego, certbot) get certificates from your
private CA with zero Koi-specific setup — they think they're talking to a normal public
CA.*

1. Point your existing ACME client at Koi's directory URL.
2. It asks for a certificate for an in-zone name, exactly as it would from Let's Encrypt.
3. Koi proves the name and issues the cert entirely on the box — no public DNS, and none of
   the usual "wait for the record to propagate" delay (Koi is both the CA *and* the DNS for
   that name).
4. It works offline and works for wildcard names, and only issues for names inside your
   zone.

### TLS proxy — trusted HTTPS in front of any plain service

*Purpose: wrap any existing plaintext service in trusted HTTPS with one command, without
touching the service.*

1. Add a proxy: it listens on a port with HTTPS using a mesh certificate and forwards
   traffic to your plain backend.
2. Anything passes through it — WebSockets, gRPC, HTTP/2 — because it just relays bytes (but
   it doesn't route by URL path; it isn't a Caddy/Traefik replacement).
3. When the certificate renews, it serves the new one on the very next connection — no
   restart, no dropped connections.
4. Status reflects whether it's *actually* running, not a guess.

*Stays true: only the client→proxy leg is encrypted; the proxy→backend hop is plaintext
(loopback by default; reaching a remote backend is an explicit opt-in).*

### Trust doctor & posture — a trust health check that never fails silently

*Purpose: one command tells you exactly what's right or wrong about a machine's trust
state, with the fix for each.*

1. Run diagnose: it checks each facet in turn — do I have an identity, does my certificate
   chain, has it been revoked, is it expiring, is the CA root installed, is my clock sane.
2. Each check reports one line: a state plus, if needed, the exact command to fix it.
3. It rolls everything up worst-case-wins and exits with an error if anything is broken — so
   scripts and automation catch it.

**States:** **healthy** (all good) · **degraded** (a warning, e.g. expiring soon — still
passes) · **broken** (e.g. expired or doesn't chain — exits non-zero) · **open** (a machine
with no identity at all — reported as *healthy and fine*, not a failure).

---

## Operate

### Machine & service health — watch the whole LAN from one view

*Purpose: see what's up and what's down — both the services you care about and the machines
themselves.*

**Service checks (you add these):**

1. Add a check — an HTTP URL or a `host:port`.
2. Koi probes it on an interval: up if it answers, down otherwise.
3. It only logs or notifies on an actual change of state, so steady services stay quiet — no
   noise.

**Machine health (zero config):**

1. Koi automatically lists every machine it has seen (from discovery and from the cert
   roster) — you never add a machine.
2. Each machine is marked up or down by how recently Koi heard from it; stop hearing from
   one and its row goes stale and flips to down after a timeout.
3. A live watch view re-renders it all so you can see a machine drop in real time.

### UDP bridge — give a container real LAN UDP

*Purpose: a bridge-networked container can't reach raw UDP/multicast/broadcast; Koi relays
it through the host so the container only needs to speak HTTP.*

1. The host opens a real UDP socket on your behalf; the container holds no socket of its
   own.
2. **Receive:** the container subscribes to a stream and gets each incoming datagram as it
   lands.
3. **Send:** the container hands Koi a datagram and it goes out on the LAN from the host.
4. **Lease:** the binding lives as long as the container keeps checking in; stop, and the
   host reclaims the port automatically.
5. **Safety:** it stays loopback-only unless you opt in to the LAN, and dangerous
   destinations (broadcast/multicast spraying, unspecified addresses) are always refused.

### Container auto-wire — one label does everything, and undoes it on stop

*Purpose: put one label on a container and it's discoverable, named, health-checked, and
optionally TLS-served — with no agent inside the container.*

1. Start a labeled container → Koi (watching the Docker/Podman socket from outside)
   announces it on mDNS, gives it a `.internal` name, adds a health check, and — if you
   asked — fronts it with a TLS proxy. All at once.
2. While it runs, it's reachable by name and watched.
3. Stop the container → everything Koi created for it is torn down within seconds.
4. Restart → it briefly vanishes and comes right back.
5. It also reads existing Traefik/Caddy labels, so a container already labeled for those
   gets a name and proxy for free.

*Stays true: the container is passive — it just carries a label; nothing is injected, and
what Koi creates lives exactly as long as the container does.*

---

## Interfaces & embedding

### MCP agent door — give an AI agent eyes on your LAN

*Purpose: let an AI agent see and act on your network — services, names, health,
containers — and publish its own endpoint for other agents to find.*

1. The agent connects one of two ways — locally (a small spawned process) or remotely (one
   URL plus a token) — and gets the same set of tools either way.
2. It reads the LAN: an inventory, discovery, name lookups, health, running containers.
3. It can act: announce its own service and give it a name, so other agents discover it.
4. A service the agent announces stays alive on its own — Koi keeps it renewed; on a clean
   exit it's removed, and on a crash it drains by itself.
5. The daemon advertises *itself* as an MCP server, so an agent's host finds the door
   without being told where it is.

### Install + verify — one command, and proof it's genuine

*Purpose: get Koi onto a machine in one line, and be sure the binary is both intact and
authentic.*

1. Run the one-line installer: it picks the right prebuilt binary for your OS and
   architecture, downloads it, and puts it on your PATH — no compiling.
2. It proves the download is intact (checksum) before installing anything; a mismatch
   installs nothing.
3. It finishes by running `koi status` so you immediately see it working — never a blank
   prompt.
4. Optionally, one more command proves the binary is *authentic* — that it really came from
   the project's build pipeline.

**Two guarantees, kept distinct:** the checksum proves **intact** (bytes weren't
corrupted); the verify step proves **genuine** (not a swapped binary on a tampered mirror —
which would pass the checksum but fail this).

### Embed Koi — run the whole substrate inside your own Rust app

*Purpose: discovery, DNS, a private CA, and TLS serving, all in-process — no daemon, no
separate binary.*

1. Choose which capabilities you want and start it; the same engine the daemon uses runs
   inside your app.
2. Drive discovery, DNS, and certificates directly through typed handles — no HTTP
   round-trips.
3. Serve your own app on one socket that transparently switches between plain HTTP and
   trusted mTLS as the node gains or loses an identity — without restarting or dropping
   connections.
4. It fails closed: an insecure configuration is rejected before anything starts listening.
