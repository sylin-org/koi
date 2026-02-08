# Koi User Guide

Koi is a local service discovery tool. It lets you find, advertise, and monitor services on your network using mDNS/DNS-SD — the same protocol your printer and smart speaker use to announce themselves.

This guide starts with the simplest thing you can do and builds from there.

---

## Your first command

Open a terminal and run:

```
koi browse
```

Koi will scan your local network and list every service type it can find. After five seconds it stops and returns you to the prompt. You might see output like:

```
_http._tcp
_googlecast._tcp
_spotify-connect._tcp
_airplay._tcp
```

Each line is a service type that something on your network is advertising. That's mDNS discovery at work — no configuration, no server, no registry. Just devices talking to each other.

---

## Browsing for a specific service type

If you want to find all HTTP servers on your network:

```
koi browse http
```

Koi accepts the type in any form you like. These are all equivalent:

```
koi browse http
koi browse _http._tcp
koi browse _http._tcp.local.
```

The output shows each resolved instance:

```
My NAS     _http._tcp    192.168.1.50:8080    nas.local.
Pi-hole    _http._tcp    192.168.1.10:80      pihole.local.
```

Columns are tab-separated: name, type, ip:port, hostname.

---

## Controlling how long Koi listens

Browse and subscribe commands default to **5 seconds** — long enough for most devices to reply. You can change this:

```
koi browse http --timeout 15
```

To stream indefinitely until you press Ctrl+C:

```
koi browse http --timeout 0
```

---

## Resolving a specific instance

If you know the full name of a service instance, you can resolve it directly:

```
koi resolve "My NAS._http._tcp.local."
```

This returns detailed information:

```
My NAS
  Type: _http._tcp
  Host: nas.local.
  IP:   192.168.1.50
  Port: 8080
  TXT:  path=/api version=2.1
```

Resolve is a one-shot operation — it waits up to 5 seconds for the instance to respond, then exits.

---

## Registering a service

You can advertise a service on the network:

```
koi register "My App" http 8080
```

This announces an `_http._tcp` service called "My App" on port 8080. Other devices running any mDNS browser — including another instance of Koi — will see it.

The process stays alive to maintain the advertisement. Press Ctrl+C to unregister and exit.

To add TXT record metadata, append key=value pairs:

```
koi register "My App" http 8080 version=2.1 path=/api
```

By default, Koi advertises all of the machine's IP addresses. To pin the mDNS A record to a specific IP (useful on multi-homed hosts or when Docker/WSL bridges add unwanted addresses):

```
koi register "My App" http 8080 --ip 192.168.1.42
```

To register for a fixed duration (useful in scripts):

```
koi register "My App" http 8080 --timeout 60
```

### Unregistering

If you know a registration's ID (shown when you register, or via `koi admin ls`):

```
koi unregister a1b2c3d4
```

---

## Subscribing to lifecycle events

Subscribe is like browse, but it tells you *what happened*, not just what's there:

```
koi subscribe http
```

Output:

```
[found]     My NAS       _http._tcp    192.168.1.50:8080    nas.local.
[resolved]  My NAS       _http._tcp    192.168.1.50:8080    nas.local.
[removed]   My NAS       _http._tcp
```

The `[found]` → `[resolved]` → `[removed]` lifecycle is how mDNS works: a service is first *found* (we know it exists), then *resolved* (we know its address), and eventually *removed* (it's gone).

---

## JSON output

Every verb command supports `--json` for machine-readable NDJSON output:

```
koi browse http --json
```

```json
{"found":{"name":"My NAS","type":"_http._tcp","host":"nas.local.","ip":"192.168.1.50","port":8080,"txt":{"version":"2.1"}}}
```

```
koi register "My App" http 8080 --json
```

```json
{"registered":{"id":"a1b2c3d4","name":"My App","type":"_http._tcp","port":8080}}
```

```
koi resolve "My NAS._http._tcp.local." --json
```

```json
{"resolved":{"name":"My NAS","type":"_http._tcp","host":"nas.local.","ip":"192.168.1.50","port":8080,"txt":{"version":"2.1"}}}
```

The JSON flag can appear before or after the subcommand — both work:

```
koi --json browse http
koi browse http --json
```

---

## Piped JSON mode

For programmatic use, you can pipe NDJSON commands into Koi's stdin. When stdin is a pipe (not a terminal), Koi reads one JSON command per line and writes one JSON response per line:

```bash
echo '{"browse":"_http._tcp"}' | koi
echo '{"resolve":"My NAS._http._tcp.local."}' | koi
```

The request format uses verb-keyed JSON:

| Operation   | Request JSON                                                                                    |
|-------------|-------------------------------------------------------------------------------------------------|
| Browse      | `{"browse": "_http._tcp"}`                                                                      |
| Register    | `{"register": {"name": "My App", "type": "_http._tcp", "port": 8080, "ip": "1.2.3.4", "txt": {"key": "val"}}}` |
| Unregister  | `{"unregister": "a1b2c3d4"}`                                                                    |
| Resolve     | `{"resolve": "My NAS._http._tcp.local."}`                                                       |
| Subscribe   | `{"subscribe": "_http._tcp"}`                                                                    |
| Heartbeat   | `{"heartbeat": "a1b2c3d4"}`                                                                     |

Responses use the same JSON format as `--json` output. Streaming operations (browse, subscribe) emit one line per event until the source is exhausted.

This mode is designed for embedding Koi in other tools — spawn it as a child process, write commands to stdin, read results from stdout.

---

## Client mode

When a daemon is running, verb commands (`browse`, `register`, `resolve`, `subscribe`, `unregister`) automatically connect to it instead of creating a standalone mDNS engine. This means your CLI commands share the daemon's registrations and benefit from its persistent network presence.

Koi detects the daemon via a breadcrumb file written on startup. The detection is fast (<1ms when no daemon exists) and transparent — you don't need to change anything about how you use the CLI.

To force connection to a specific daemon:

```
koi browse http --endpoint http://localhost:5641
```

To force standalone mode (ignore any running daemon):

```
koi browse http --standalone
```

In client mode, `koi register` keeps the service alive by sending periodic heartbeats to the daemon. Press Ctrl+C to unregister and exit — the daemon handles the mDNS advertisement, so the process doesn't need to stay running if you use the HTTP API directly.

---

## Daemon mode

So far, everything has been one-shot: run a command, get a result, exit. Daemon mode keeps Koi running as a persistent service, exposing an HTTP API and an IPC socket that any application on the machine can use.

```
koi --daemon
```

By default, the daemon listens on:
- **HTTP**: port 5641 (all interfaces)
- **IPC**: `\\.\pipe\koi` (Windows) or `$XDG_RUNTIME_DIR/koi.sock` (Linux)

### HTTP API

The HTTP API speaks JSON over standard REST conventions.

#### Health check

```
GET /healthz
```
```json
{"ok": true}
```

#### Browse for services (SSE stream)

```
GET /v1/browse?type=_http._tcp
```

Returns a Server-Sent Events stream. Each event's `data` field contains a JSON object:

```
data: {"found":{"name":"My NAS","type":"_http._tcp","host":"nas.local.","ip":"192.168.1.50","port":8080,"txt":{}}}
```

The stream closes after 5 seconds of no new events (the network has gone quiet). To stream indefinitely, set `idle_for=0`:

```
GET /v1/browse?type=_http._tcp&idle_for=0
```

To wait longer for slow networks:

```
GET /v1/browse?type=_http._tcp&idle_for=15
```

#### Register a service

```
POST /v1/services
Content-Type: application/json

{"name": "My App", "type": "_http._tcp", "port": 8080, "txt": {"version": "2.1"}}
```

Response (201 Created):

```json
{"registered": {"id": "a1b2c3d4", "name": "My App", "type": "_http._tcp", "port": 8080, "mode": "heartbeat", "lease_secs": 90}}
```

The `mode` field tells you how the registration stays alive (see [Leases & heartbeats](#leases--heartbeats) below). The `lease_secs` field is the heartbeat interval — send a heartbeat before it expires, or the registration will begin draining.

To create a permanent registration that never expires:

```json
{"name": "My App", "type": "_http._tcp", "port": 8080, "lease_secs": 0}
```

Response:

```json
{"registered": {"id": "a1b2c3d4", "name": "My App", "type": "_http._tcp", "port": 8080, "mode": "permanent"}}
```

To set a custom heartbeat interval:

```json
{"name": "My App", "type": "_http._tcp", "port": 8080, "lease_secs": 300}
```

#### Unregister a service

```
DELETE /v1/services/a1b2c3d4
```

```json
{"unregistered": "a1b2c3d4"}
```

#### Heartbeat (renew a lease)

```
PUT /v1/services/a1b2c3d4/heartbeat
```

```json
{"renewed": {"id": "a1b2c3d4", "lease_secs": 90}}
```

Send this periodically (at half the `lease_secs` interval is a good default) to keep a heartbeat-mode registration alive. If the registration is draining, a heartbeat revives it back to alive.

Returns 404 if the registration doesn't exist (was removed or expired).

#### Resolve an instance

```
GET /v1/resolve?name=My%20NAS._http._tcp.local.
```

```json
{"resolved": {"name": "My NAS", "type": "_http._tcp", "host": "nas.local.", "ip": "192.168.1.50", "port": 8080, "txt": {"version": "2.1"}}}
```

#### Subscribe to lifecycle events (SSE stream)

```
GET /v1/events?type=_http._tcp
```

Like browse, but each event includes a lifecycle kind:

```
data: {"event":"found","service":{"name":"My NAS","type":"_http._tcp","host":"nas.local.","ip":"192.168.1.50","port":8080,"txt":{}}}
data: {"event":"resolved","service":{...}}
data: {"event":"removed","service":{"name":"My NAS","type":"_http._tcp","txt":{}}}
```

The same `idle_for` parameter applies — default 5s, `idle_for=0` for infinite streaming.

#### Error responses

Errors return the appropriate HTTP status code with a JSON body:

```json
{"error": "invalid_type", "message": "Invalid service type: ..."}
```

| Error code          | HTTP status         | When                                                  |
|---------------------|---------------------|-------------------------------------------------------|
| `invalid_type`      | 400 Bad Request     | Service type doesn't parse (bad protocol, name >15 chars) |
| `ambiguous_id`      | 400 Bad Request     | ID prefix matches multiple registrations              |
| `parse_error`       | 400 Bad Request     | Malformed JSON in request body                        |
| `not_found`         | 404 Not Found       | Registration ID doesn't exist                         |
| `already_draining`  | 409 Conflict        | Admin drain on a registration that's already draining |
| `not_draining`      | 409 Conflict        | Admin revive on a registration that isn't draining    |
| `resolve_timeout`   | 504 Gateway Timeout | mDNS resolve didn't get a response within 5 seconds   |
| `daemon_error`      | 500 Internal Error  | mDNS engine error                                     |
| `io_error`          | 500 Internal Error  | I/O failure                                           |

CORS is enabled for all origins, so browser-based clients work out of the box.

#### Admin endpoints

These endpoints manage daemon state. The `/v1/admin/` namespace is separate from `/v1/services/` for future access control.

All admin endpoints that take an `{id}` parameter support **prefix matching** — if you have a registration with ID `a1b2c3d4`, you can use `a1b`, `a1b2`, or any unambiguous prefix. If the prefix matches more than one registration, you get a 400 `ambiguous_id` error.

**Status:**

```
GET /v1/admin/status
```

```json
{"version": "0.1.0", "uptime_secs": 3600, "platform": "windows", "registrations": {"alive": 3, "draining": 0, "permanent": 1, "total": 3}}
```

**List all registrations:**

```
GET /v1/admin/registrations
```

Returns a JSON array of all registrations with full lifecycle metadata (id, name, type, port, mode, state, lease_secs, remaining_secs, grace_secs, session_id, registered_at, last_seen, txt).

**Inspect a registration:**

```
GET /v1/admin/registrations/a1b2c3d4
```

Returns the full registration detail as a single JSON object.

**Force-unregister:**

```
DELETE /v1/admin/registrations/a1b2c3d4
```

Removes the registration immediately and sends mDNS goodbye packets.

**Force-drain:**

```
POST /v1/admin/registrations/a1b2c3d4/drain
```

Puts the registration into draining state. The grace timer starts — if no heartbeat or reconnection arrives before grace expires, the registration is removed.

**Force-revive:**

```
POST /v1/admin/registrations/a1b2c3d4/revive
```

Cancels a drain and returns the registration to alive state.

### IPC (Named Pipe / Unix Socket)

The IPC interface uses the same NDJSON protocol as piped stdin, but over a persistent connection:

- **Windows**: Named Pipe at `\\.\pipe\koi`
- **Linux**: Unix Domain Socket at `$XDG_RUNTIME_DIR/koi.sock` (or `/var/run/koi.sock`)

Connect, send one JSON command per line, receive one JSON response per line. Streaming commands (browse, subscribe) send multiple response lines until the operation completes.

IPC connections have **session-based leases**: registrations made over a pipe connection are tied to that connection. When the connection drops, those registrations enter a 30-second grace period before being removed. This means a crashed process's services are automatically cleaned up.

The heartbeat verb is also available over IPC:

```json
{"heartbeat": "a1b2c3d4"}
```

```json
{"renewed": {"id": "a1b2c3d4", "lease_secs": 0}}
```

(Session-mode registrations return `lease_secs: 0` because their liveness is tracked by connection state, not heartbeats.)

This is the fastest interface — no HTTP overhead, no process spawn. Ideal for local applications that need real-time service discovery.

---

## Leases & heartbeats

Registrations made through the daemon have a **lease mode** that determines how they prove they're still alive. This prevents ghost services — if a process crashes, its services are automatically cleaned up instead of lingering on the network forever.

| Mode | Mechanism | When it's used | Default grace |
|---|---|---|---|
| **Heartbeat** | Client sends periodic `PUT /v1/services/{id}/heartbeat` | HTTP API registrations | 90s lease, 30s grace |
| **Session** | Connection open = alive. Connection drops = grace starts. | IPC (pipe/socket) and piped stdin | 30s grace (IPC), 5s grace (CLI) |
| **Permanent** | Lives until explicit removal or daemon shutdown. | `lease_secs: 0` from any transport | No expiry |

The **adapter picks the default** automatically:
- HTTP is stateless, so it defaults to heartbeat mode. Send `PUT /v1/services/{id}/heartbeat` at half the lease interval to keep the registration alive.
- IPC connections have an OS-level signal when they drop, so session mode is used. No heartbeats needed — just keep the connection open.
- Piped stdin works the same way — closing stdin triggers cleanup after a 5-second grace period.

### What happens when liveness is lost

1. **Alive** → heartbeat missed or connection dropped
2. **Draining** → grace timer running. A heartbeat or reconnection during this window returns the registration to alive with no network-visible interruption. This absorbs container restarts, rolling deploys, and transient disconnects.
3. **Expired** → grace elapsed. Koi sends mDNS goodbye packets and removes the registration.

A background reaper checks every 5 seconds. For heartbeat-mode registrations, it transitions missed-heartbeat entries to draining and removes grace-expired entries.

### Session reconnection

If a new registration arrives (same name + service type) while an existing entry is draining, Koi **reconnects** instead of creating a duplicate. The draining entry is revived with the new session, and the original registration ID is preserved. The network sees continuity — the advertisement was never withdrawn.

---

## Admin commands

Admin commands let you inspect and manage a running daemon's registrations. They always talk to the daemon (via its HTTP API) and fail with a clear message if no daemon is running.

### Status

```
koi admin status
```

Shows the daemon version, uptime, and registration counts.

### List registrations

```
koi admin ls
```

```
ID        NAME                 TYPE             PORT  STATE      MODE
a1b2c3d4  My App               _http._tcp       8080  alive      heartbeat
e5f6a7b8  My Service           _http._tcp       9090  alive      permanent
```

### Inspect a registration

```
koi admin inspect a1b2
```

Shows full detail including lease timing, session info, and TXT records. Supports prefix matching — use any unambiguous prefix of the registration ID.

### Drain, revive, and force-unregister

```
koi admin drain a1b2        # start grace timer (alive → draining)
koi admin revive a1b2       # cancel drain (draining → alive)
koi admin unregister a1b2   # remove immediately, send goodbye packets
```

All admin commands support `--json` for machine-readable output.

---

## Daemon configuration

All daemon settings can be set via CLI flags or environment variables:

| Flag            | Env var          | Default              | Description                      |
|-----------------|------------------|----------------------|----------------------------------|
| `--port`        | `KOI_PORT`       | `5641`               | HTTP API port                    |
| `--pipe`        | `KOI_PIPE`       | platform-specific    | IPC socket/pipe path             |
| `--log-level`   | `KOI_LOG`        | `info`               | Log level (error/warn/info/debug/trace) |
| `-v`, `--verbose` |                | off                  | Increase verbosity (`-v` = debug, `-vv` = trace) |
| `--log-file`    | `KOI_LOG_FILE`   | _(none)_             | Write logs to file (in addition to stderr) |
| `--no-http`     | `KOI_NO_HTTP`    | `false`              | Disable the HTTP adapter         |
| `--no-ipc`      | `KOI_NO_IPC`     | `false`              | Disable the IPC adapter          |

When `-v` is used, it takes precedence over `--log-level`. So `-v --log-level warn` results in `debug`, not `warn` — because you're explicitly asking for more output.

When `--log-file` is set, Koi writes logs to that file **in addition to** stderr. Both outputs respect the same verbosity level. The file is opened in append mode.

Examples:

```bash
# Custom port, debug logging
koi --daemon --port 8053 -v

# Trace-level with persistent log file
koi --daemon -vv --log-file /var/log/koi.log

# IPC only, no HTTP
koi --daemon --no-http

# All via environment
KOI_PORT=9090 KOI_LOG=trace KOI_LOG_FILE=./koi.log koi --daemon
```

---

## Windows service

On Windows, Koi can run as a system service:

```
koi install
```

This registers Koi with the Service Control Manager and starts it. To stop or restart:

```
sc stop koi
sc start koi
```

To remove the service:

```
koi uninstall
```

On Linux, use a systemd unit file instead.

---

## How modes are chosen

Koi decides what to do based on how you invoke it:

1. **Subcommand present** (`koi browse`, `koi register`, etc.):
   - **`admin` subcommand** → always talks to the daemon (fails if none running).
   - **`--standalone`** → runs a local mDNS engine, no daemon needed.
   - **`--endpoint URL`** → connects to the specified daemon.
   - **Otherwise** → checks for a running daemon (via breadcrumb file + health probe). If found, uses client mode. If not, uses standalone mode.
2. **Stdin is a pipe** (`echo '...' | koi`) → reads NDJSON from stdin, writes to stdout.
3. **`--daemon` flag** → starts HTTP + IPC adapters, runs until shutdown.
4. **None of the above** (Windows) → attempts to run as a Windows Service.

The daemon detection is fast (<1ms when no daemon exists) — it reads a breadcrumb file written on daemon startup. Only when the breadcrumb exists does Koi make a quick health probe (200ms timeout).

---

## Service type shorthand

Koi normalizes service types liberally. You can use whatever form is convenient:

| Input                    | Resolved to               |
|--------------------------|---------------------------|
| `http`                   | `_http._tcp.local.`       |
| `_http`                  | `_http._tcp.local.`       |
| `_http._tcp`             | `_http._tcp.local.`       |
| `_http._tcp.`            | `_http._tcp.local.`       |
| `_http._tcp.local.`      | `_http._tcp.local.`       |
| `_dns._udp`              | `_dns._udp.local.`        |

If you omit the protocol, TCP is assumed. The only constraint: service names must be 1-15 characters, and the protocol must be `tcp` or `udp`.

---

## Quick reference

```
koi browse [TYPE]                              # discover services (5s default)
koi browse                                     # discover all service types
koi register NAME TYPE PORT [KEY=VALUE ...]     # advertise a service
koi unregister ID                               # stop advertising
koi resolve INSTANCE                            # look up a specific instance
koi subscribe TYPE                              # stream lifecycle events

koi admin status                                # daemon version + registration counts
koi admin ls                                    # list all registrations
koi admin inspect ID                            # detailed view (prefix matching)
koi admin drain ID                              # start grace timer
koi admin revive ID                             # cancel drain
koi admin unregister ID                         # force-remove + goodbye packets

koi --daemon                                    # start persistent daemon
koi install                                     # install Windows service
koi uninstall                                   # remove Windows service

Flags (work with any subcommand):
  --json              JSON output instead of human-readable
  --timeout SECONDS   override auto-exit (0 = run forever)
  --endpoint URL      connect to a specific daemon
  --standalone        skip daemon detection, use local mDNS
  -v, -vv             increase verbosity (debug, trace)
  --log-level LEVEL   error, warn, info, debug, trace
  --log-file PATH     write logs to file (in addition to stderr)
```
