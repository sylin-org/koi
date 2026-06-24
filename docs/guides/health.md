# Health - Endpoint Monitoring

Monitoring is observability's simplest form: is the service up, or not? Before you invest in metrics pipelines, distributed tracing, and log aggregation, you need to answer this one question for each service on your network. Koi's health capability gives you that answer with minimal setup.

The design philosophy is intentionally narrow. Koi doesn't try to replace Prometheus or Datadog - it handles the "is it reachable?" layer so you can see at a glance which services are healthy without deploying a full observability stack. For a homelab or a small team environment, this is often all you need.

**When to use health checks**: You have services running on your LAN and you want to know immediately when one goes down. You want a live terminal dashboard showing service state. You want transition history - not just whether something is down _now_, but when it went down and when it came back.

All CLI commands use the `koi health` prefix. All HTTP endpoints live under `/v1/health/`. Health commands require a running daemon - use `koi install` or `koi --daemon` first.

---

## Two check types

Koi supports two kinds of health checks, each suited to a different situation:

| Type     | Flag                | What it does                                            | When to use                                                     |
| -------- | ------------------- | ------------------------------------------------------- | --------------------------------------------------------------- |
| **HTTP** | `--http <url>`      | Sends a `GET` request; healthy if the response is 2xx   | Web services, APIs, anything with a health endpoint             |
| **TCP**  | `--tcp <host:port>` | Opens a TCP connection; healthy if the connect succeeds | Databases, message queues, any service that accepts connections |

HTTP checks are the most common - most modern services expose a `/health` or `/healthz` endpoint. TCP checks are useful when the service doesn't speak HTTP but accepts connections (think PostgreSQL, Redis, MQTT brokers).

Both types run at the daemon's configured polling interval. Koi fires a state-transition event when the result changes - not on every poll. This means your event stream and audit log show meaningful transitions, not a noisy heartbeat.

---

## Getting started

Add a few checks:

```
koi health add api --http https://localhost:3000/health
koi health add db --tcp 127.0.0.1:5432
```

See the current state:

```
koi health status
```

That's it. Three lines to register, one to inspect. Koi starts polling immediately.

---

## Live monitoring

The real power is `health watch` - a live-updating terminal view that shows all checks and refreshes automatically:

```
koi health watch
```

```
 SERVICE   STATE     SINCE              REASON
 api       healthy   2026-01-15 08:42   HTTP 200
 db        healthy   2026-01-15 08:42   TCP connect OK
```

This is your at-a-glance dashboard. Leave it running in a terminal tab while you work. The default refresh is every 2 seconds; for a calmer view:

```
koi health watch --interval 5
```

Press Ctrl+C to exit.

---

## Transition history

Every time a check changes state - healthy to unhealthy, or back - Koi logs the transition:

```
koi health log
```

This is your incident timeline. When you come back Monday morning and a service is down, the log tells you exactly when it went unhealthy and whether it's been flapping. The distinction between "went down once at 3 AM Saturday" and "has been bouncing every 20 minutes since Friday" changes how you respond.

---

## Machine health

Alongside the service checks you register, the snapshot also reports **machine health** - one row per machine Koi has seen on the LAN. You don't configure these; they're derived automatically from the mDNS tracker (hosts currently advertising on the network) and, when certmesh is running, the CA roster (enrolled members). Both `koi health status` and `GET /v1/health/status` return machines alongside services.

Each machine carries:

| Field          | Meaning                                                                  |
| -------------- | ----------------------------------------------------------------------- |
| `hostname`     | The machine's name                                                       |
| `status`       | `up`, `down`, or `unknown`                                               |
| `sources`      | Where Koi learned about it - `mdns`, `certmesh`, or both                 |
| `last_seen_secs` | Seconds since the machine was last observed (absent if never seen)     |
| `cert_expires` | When this member's certmesh certificate expires (certmesh members only) |
| `dns_resolves` | Whether the local DNS zone resolves this hostname (when DNS is running)  |
| `warnings`     | Notable conditions worth attention (see below)                          |

**Status and staleness.** A machine is `up` when it was last seen within the staleness threshold (60 seconds by default). Past that, it goes `down`; a machine known only from the roster but never observed reports `unknown`. The status, not a warning, is what tells you a machine has gone quiet.

**Warnings.** The warnings list flags certificate-trust conditions:

- `cert_expiring` - the member's certmesh certificate expires within 7 days
- `cert_expired` - the certificate has already lapsed

A machine that has gone stale shows up as a `down` (or `unknown`) status rather than a warning, so scan the status column for "is it reachable?" and the warnings for "is its trust about to break?".

---

## CLI commands

```
koi health status                               # Current state of all checks
koi health watch [--interval SECS]              # Live dashboard
koi health add NAME --http URL                  # Register an HTTP check
koi health add NAME --tcp HOST:PORT             # Register a TCP check
koi health remove NAME                          # Remove a check
koi health log                                  # Transition history
```

Adding a check with a duplicate name updates the existing check. This lets you change the endpoint or type without removing and re-adding.

---

## HTTP API

When the daemon is running, health endpoints live under `/v1/health/`:

| Method   | Path                       | Purpose                              |
| -------- | -------------------------- | ------------------------------------ |
| `GET`    | `/v1/health/status`        | Snapshot of all checks               |
| `GET`    | `/v1/health/list`          | List registered checks (config only) |
| `POST`   | `/v1/health/add`           | Register a check                     |
| `DELETE` | `/v1/health/remove/{name}` | Remove a check                       |

### Add example

```
POST /v1/health/add
Content-Type: application/json
x-koi-token: <daemon access token>

{"name": "api", "kind": "http", "target": "https://localhost:3000/health"}
```

The body fields are `name`, `kind` (`"http"` or `"tcp"`), `target` (the URL or `host:port`), plus optional `interval_secs` and `timeout_secs`. For a TCP check, use `{"name": "db", "kind": "tcp", "target": "127.0.0.1:5432"}`.

Mutating endpoints (`POST /v1/health/add`, `DELETE /v1/health/remove/{name}`) require the daemon access token in the `x-koi-token` header — see the [security model](../reference/security-model.md) for how to read it from the breadcrumb. `GET` reads (status, list) are unauthenticated.

---

## Troubleshooting

### Check shows unhealthy immediately

The most likely cause: the service isn't reachable from the machine running Koi. Verify manually:

```
curl https://localhost:3000/health          # HTTP check
Test-NetConnection -ComputerName 127.0.0.1 -Port 5432   # TCP check (PowerShell)
```

For HTTP checks, remember that "healthy" means a 2xx response. A 301 redirect, a 401 unauthorized, or a 500 error all count as unhealthy. Make sure you're pointing at the right health endpoint.

### No checks listed

Checks are registered with a running daemon. If you're running Koi in daemon mode, make sure you're targeting it:

```
koi health add api --http https://localhost:3000/health --endpoint http://localhost:5641
```

### SSE events not arriving

Health state transitions are pushed via SSE on the daemon's event stream. Make sure you're connected to the correct SSE endpoint and that the daemon is running. Transitions only fire when state _changes_ - a service that stays healthy won't generate events.
