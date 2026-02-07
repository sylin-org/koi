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

To register for a fixed duration (useful in scripts):

```
koi register "My App" http 8080 --timeout 60
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
| Register    | `{"register": {"name": "My App", "type": "_http._tcp", "port": 8080, "txt": {"key": "val"}}}` |
| Unregister  | `{"unregister": "a1b2c3d4"}`                                                                    |
| Resolve     | `{"resolve": "My NAS._http._tcp.local."}`                                                       |
| Subscribe   | `{"subscribe": "_http._tcp"}`                                                                    |

Responses use the same JSON format as `--json` output. Streaming operations (browse, subscribe) emit one line per event until the source is exhausted.

This mode is designed for embedding Koi in other tools — spawn it as a child process, write commands to stdin, read results from stdout.

---

## Daemon mode

So far, everything has been one-shot: run a command, get a result, exit. Daemon mode keeps Koi running as a persistent service, exposing an HTTP API and an IPC socket that any application on the machine can use.

```
koi --daemon
```

By default, the daemon listens on:
- **HTTP**: port 5353 (all interfaces)
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

The stream stays open until the client disconnects.

#### Register a service

```
POST /v1/services
Content-Type: application/json

{"name": "My App", "type": "_http._tcp", "port": 8080, "txt": {"version": "2.1"}}
```

Response (201 Created):

```json
{"registered": {"id": "a1b2c3d4", "name": "My App", "type": "_http._tcp", "port": 8080}}
```

The service remains advertised as long as the daemon is running.

#### Unregister a service

```
DELETE /v1/services/a1b2c3d4
```

```json
{"unregistered": "a1b2c3d4"}
```

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

#### Error responses

Errors return the appropriate HTTP status code with a JSON body:

```json
{"error": "invalid_type", "message": "Invalid service type: ..."}
```

| Error code        | HTTP status         |
|-------------------|---------------------|
| `invalid_type`    | 400 Bad Request     |
| `not_found`       | 404 Not Found       |
| `resolve_timeout` | 504 Gateway Timeout |
| `daemon_error`    | 500 Internal Error  |
| `io_error`        | 500 Internal Error  |

CORS is enabled for all origins, so browser-based clients work out of the box.

### IPC (Named Pipe / Unix Socket)

The IPC interface uses the same NDJSON protocol as piped stdin, but over a persistent connection:

- **Windows**: Named Pipe at `\\.\pipe\koi`
- **Linux**: Unix Domain Socket at `$XDG_RUNTIME_DIR/koi.sock` (or `/var/run/koi.sock`)

Connect, send one JSON command per line, receive one JSON response per line. Streaming commands (browse, subscribe) send multiple response lines until the operation completes.

This is the fastest interface — no HTTP overhead, no process spawn. Ideal for local applications that need real-time service discovery.

---

## Daemon configuration

All daemon settings can be set via CLI flags or environment variables:

| Flag            | Env var        | Default              | Description                      |
|-----------------|----------------|----------------------|----------------------------------|
| `--port`        | `KOI_PORT`     | `5353`               | HTTP API port                    |
| `--pipe`        | `KOI_PIPE`     | platform-specific    | IPC socket/pipe path             |
| `--log-level`   | `KOI_LOG`      | `info`               | Log level (error/warn/info/debug/trace) |
| `--no-http`     | `KOI_NO_HTTP`  | `false`              | Disable the HTTP adapter         |
| `--no-ipc`      | `KOI_NO_IPC`   | `false`              | Disable the IPC adapter          |

Examples:

```bash
# Custom port, debug logging
koi --daemon --port 8053 --log-level debug

# IPC only, no HTTP
koi --daemon --no-http

# All via environment
KOI_PORT=9090 KOI_LOG=trace koi --daemon
```

---

## Windows service

On Windows, Koi can run as a system service:

```
koi install
```

This registers Koi with the Service Control Manager. Start it with:

```
net start koi
```

To remove the service:

```
koi uninstall
```

On Linux, use a systemd unit file instead.

---

## How modes are chosen

Koi decides what to do based on how you invoke it:

1. **Subcommand present** (`koi browse`, `koi register`, etc.) → runs the verb, exits.
2. **Stdin is a pipe** (`echo '...' | koi`) → reads NDJSON from stdin, writes to stdout.
3. **`--daemon` flag** → starts HTTP + IPC adapters, runs until shutdown.
4. **None of the above** (Windows) → attempts to run as a Windows Service.

You never need to think about this. Just use the interface that fits your use case.

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

koi --daemon                                    # start persistent daemon
koi install                                     # install Windows service
koi uninstall                                   # remove Windows service

Flags (work with any subcommand):
  --json              JSON output instead of human-readable
  --timeout SECONDS   override auto-exit (0 = run forever)
  --log-level LEVEL   error, warn, info, debug, trace
```
