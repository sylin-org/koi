# Getting started with Koi

Koi is one binary that gives your local network a toolbox it doesn't ship with:
discover services, name them, trust them, serve them. This tutorial takes you from
*nothing installed* to a **visible result in about a minute** — then points you at
the deeper guides.

You'll run four short steps:

1. Get the binary and confirm it runs.
2. See what's on your network — instantly, with no daemon and no config.
3. Start the daemon and open the dashboard.
4. Do one real task end to end: give a machine a friendly name.

No accounts, no cloud, nothing to sign up for. Open a terminal and follow along.

---

## 1. Get the binary

Download a prebuilt binary from
[GitHub Releases](https://github.com/sylin-org/koi/releases) and put it on your
`PATH`.

**Linux / macOS** — extract and move it onto your `PATH`:

```bash
# adjust the filename to the asset you downloaded
tar -xzf koi-*.tar.gz
sudo mv koi /usr/local/bin/
```

**Windows** — extract `koi.exe` to a folder (for example `C:\Tools\koi`), then add
that folder to your `PATH` so you can run `koi` from any terminal:

```powershell
# add C:\Tools\koi to PATH for the current user (open a new terminal afterwards)
[Environment]::SetEnvironmentVariable(
  'Path', $env:Path + ';C:\Tools\koi', 'User')
```

Prefer building it yourself? With [Rust](https://rustup.rs/) 1.92 or later:

```bash
git clone https://github.com/sylin-org/koi.git
cd koi
cargo build --release   # binary lands in target/release/
```

Confirm it works:

```bash
koi version
```

If that prints a version, you're ready.

---

## 2. The instant win — see your network

Here's the part that needs no setup at all. Ask Koi what's on the network:

```bash
koi mdns discover
```

Koi sends a multicast query, lists every service type it hears, and stops after
five seconds. On a typical home or office network you'll see something like:

```
_http._tcp
_googlecast._tcp
_spotify-connect._tcp
_airplay._tcp
```

That's mDNS discovery — printers, smart speakers, Chromecasts, and any app that
advertises itself, all surfaced from one command. **No daemon, no config, no
server.** Koi ran as a one-shot CLI tool and exited.

Want detail instead of just types? Narrow to one and Koi resolves each instance to
an address:

```bash
koi mdns discover http
```

```
My NAS     _http._tcp    192.168.1.50:8080    nas.local.
Pi-hole    _http._tcp    192.168.1.10:80      pihole.local.
```

That's your first visible result, and you're not even a minute in. Everything from
here builds on the same binary.

> Tip: Koi's CLI is built to be explored. Bare `koi` shows live status plus the full
> command catalog, `koi <domain>` (e.g. `koi dns`) shows curated examples, and any
> command followed by `?` (e.g. `koi mdns announce?`) opens a detail page with
> examples and the equivalent HTTP call.

---

## 3. Start the daemon

One-off commands like `discover` work standalone. The rest of the toolbox — a local
DNS resolver, certificates, health checks, the dashboard — lives in a long-running
**daemon**. Start one in the foreground:

```bash
koi --daemon
```

Leave that terminal running (Ctrl+C stops it) and open a second one for the
commands below. A few things to know:

- The daemon listens on **`127.0.0.1:5641`** — **loopback only by default**, so only
  processes on this machine can reach it. Exposing it to the LAN or to containers is
  a deliberate opt-in; see the [security model](../reference/security-model.md).
- Every capability (mDNS, DNS, health, proxy, and more) starts in a *ready* state
  with zero entries. Nothing is configured yet; they accept configuration whenever
  you want it.
- For a permanent setup later, `koi install` registers the daemon as a system service
  so it survives reboots — but the foreground daemon is perfect for this tutorial.

Check that it's up:

```bash
koi status
```

```
Koi v0.4.x - status

  mDNS       running    0 registrations, 0 discovered
  Certmesh   running    ready - run certmesh create
  DNS        running    0 static, 0 certmesh, 0 mdns
  Health     running    0 services up (0 total)
  Proxy      running    0 listeners
  UDP        running    0 bindings
```

---

## 4. Open the dashboard

With the daemon running, open the web dashboard:

```bash
koi launch
```

That opens `http://localhost:5641/` in your browser — a live system overview. From
there you can also reach the **mDNS network browser** at
`http://localhost:5641/mdns-browser` (the same discovery you ran in step 2, but as a
live page) and the **interactive API docs** at `http://localhost:5641/docs`.

If `koi launch` can't open a browser (a headless server, say), just visit
`http://localhost:5641/` yourself.

---

## 5. One real task: give a machine a name

Time to *use* the toolbox. Typing `myapp.lan` into a browser is a different
experience from remembering `10.0.0.42`. Koi's local DNS resolver makes that
mapping, and it's already running inside the daemon you started.

Add a static name, then resolve it:

```bash
koi dns add myapp 10.0.0.42     # use a real address on your LAN
koi dns lookup myapp
koi dns list                    # everything currently resolvable
```

`koi dns add myapp 10.0.0.42` makes `myapp.lan` resolve to that address (`.lan` is
the default zone). `koi dns lookup myapp` asks Koi's resolver and shows the answer;
`koi dns list` shows the whole zone — your static entries plus anything Koi learns
from discovery and certificates.

That's a complete cycle — **add, query, list** — and it's the same shape for every
capability: a friendly CLI verb backed by the daemon.

> Answering on the standard DNS port (53) requires elevated privileges and may
> collide with an existing resolver. For experimenting, start the daemon on a high
> port instead — `koi --daemon --dns-port 15353` — and you can query it directly with
> `dig` or `nslookup` pointed at that port. The [DNS guide](../guides/dns.md) covers
> the full picture.

### A note on writes and the daemon token

You just changed daemon state from the CLI, and it "just worked" — the CLI reads the
daemon's access token for you. If you ever call the HTTP API directly, **reads are
open on loopback but writes need a token**:

```bash
TOKEN=$(koi token show)   # prints the token (run in an interactive terminal)
curl -X POST -H "x-koi-token: $TOKEN" \
  http://localhost:5641/v1/dns/add \
  -d '{"name": "myapp", "ip": "10.0.0.42"}'
```

For containers, `koi token write /run/koi/token` writes a `0600` file you can mount
as a secret. The full mechanism is in the
[security model](../reference/security-model.md).

---

## Where to go next

You now have the whole loop: a binary, instant discovery, a running daemon, a
dashboard, and a named service. From here, follow the task that fits what you want:

- **Discover and advertise services** — leases, lifecycle events, and announcing your
  own service: the [mDNS guide](../guides/mdns.md).
- **Name everything** — static entries, automatic names from discovery and
  certificates, and running *alongside* your existing resolver (Pi-hole, AdGuard,
  dnsmasq) via conditional forwarding: the [DNS guide](../guides/dns.md) and
  [DNS coexistence guide](../guides/dns-coexistence.md).
- **Trust your LAN** — a private certificate authority with guided enrollment and OS
  trust-store install, so HTTPS works without browser warnings: the
  [certmesh guide](../guides/certmesh.md).
- **Serve over TLS** — a zero-config TLS endpoint for those certificates: the
  [proxy guide](../guides/proxy.md).
- **Containers** — label a container and the pipeline runs end to end (announced,
  named, certified, watched): [CONTAINERS.md](../../CONTAINERS.md).
- **AI agents** — hand the LAN to an agent over the Model Context Protocol: the
  [MCP guide](../guides/mcp.md).
- **Run it for real** — install as a system service, manage its lifecycle, and
  configure it: the [system guide](../guides/system.md).

For the complete picture, see the [User Guide](../../GUIDE.md), the
[CLI reference](../reference/cli.md), and the [HTTP API reference](../reference/http-api.md).
