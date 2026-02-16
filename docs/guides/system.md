# System - Daemon Lifecycle

Koi is a single binary that wears two hats. When you type `koi mdns discover`, it's a short-lived CLI tool - it does its job and exits. But most of Koi's power comes from the **daemon**: a long-running process that holds mDNS registrations, serves the HTTP API, runs health checks, and keeps certificates alive. The system commands are how you manage that daemon's lifecycle.

Understanding this duality matters. Some commands (like `koi version`) work anywhere - they don't need the daemon. Others (like `koi mdns admin ls`) only make sense when a daemon is running. The system module bridges the two worlds.

---

## Installing the daemon

The daemon should run as a system service so it survives reboots, can bind privileged ports, and starts before your applications need it.

```
koi install
```

This is a one-time setup. On each platform, Koi registers itself with the native service manager:

- **Windows**: Creates a Windows Service via the Service Control Manager with automatic startup and a recovery policy (restart after 5s, then 10s, then stop).
- **Linux**: Writes and enables a systemd unit file.
- **macOS**: Creates a launchd plist.

The daemon listens on port 5641 by default and exposes both the HTTP API (for any language) and the IPC pipe (for the CLI). Once installed, every other Koi command can talk to the daemon automatically.

**All five modules are enabled by default.** On a fresh install the daemon starts every module, even if you haven't configured it yet:

- **mDNS** begins discovering peers immediately.
- **DNS**, **Health**, and **Proxy** start in a _ready_ state with zero entries/routes - they accept configuration at any time.
- **CertMesh** reports _ready - run certmesh create_ until you initialise a CA.

This is by design. A freshly-installed Koi is healthy; unused modules carry no overhead and can be activated whenever you need them. Use `koi status` to see each module's current state.

If you just want to experiment without installing anything, run the daemon in the foreground instead:

```
koi --daemon
```

It behaves identically - same API, same IPC - but stops when you close the terminal.

---

## Checking on things

Two commands tell you what's happening:

```
koi version          # what binary is running
koi status           # what all the subsystems are doing
```

`status` is the more useful one. It gives you a single-glance dashboard. On a fresh install it looks like this:

```
Koi v0.2.x - status

  mDNS       running    0 registrations, 0 discovered
  Certmesh   running    ready - run certmesh create
  DNS        running    0 static, 0 certmesh, 0 mdns
  Health     running    0 services up (0 total)
  Proxy      running    0 listeners
```

Once you've been using Koi for a while, the numbers fill in:

```
Koi v0.2.x - status

  mDNS       running    3 registrations, 12 discovered
  Certmesh   running    CA active, 4 members, enrollment open
  DNS        running    8 local names, upstream 8.8.8.8
  Health     running    5 checks (4 healthy, 1 unhealthy)
  Proxy      running    2 listeners
```

Both support `--json` for scripting and monitoring integrations.

---

## Uninstalling

```
koi uninstall
```

This is intentionally conservative. It stops the daemon, removes the service registration, and cleans up firewall rules - but it **preserves all your data**. Your CA keys, certificates, DNS records, and configuration files remain on disk. If you reinstall later, everything picks up where it left off.

This design is deliberate. Uninstalling a service shouldn't destroy the state it managed. That's what factory reset is for.

---

## Factory reset

Sometimes you need a clean slate. A corrupted roster, a CA key you've lost the passphrase for, or just a test environment you want to wipe and start over.

```
koi factory-reset
```

This destroys the entire program data folder and recreates it from scratch, then restarts the service. Everything is gone:

- mDNS registrations
- CA private keys and every certificate ever issued
- DNS records
- Health-check configurations
- Proxy routes
- config.toml

Log files are preserved by default (they're useful for post-mortem diagnosis). Use `--include-logs` to remove those too.

**This is irreversible.** If this node is the certmesh CA root, every certificate it issued becomes unverifiable - every member of the mesh loses trust. Koi will ask you to type `RESET` to confirm you understand.

---

## HTTP API

The daemon exposes a few system-level endpoints that aren't tied to any specific module:

| Method | Path                 | Purpose                                                                                                                  |
| ------ | -------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `GET`  | `/healthz`           | Liveness probe - returns 200 if the daemon is alive. Use this in load balancer health checks or container orchestrators. |
| `GET`  | `/v1/status`         | Unified status of all capabilities, the same data as `koi status --json`.                                                |
| `POST` | `/v1/admin/shutdown` | Graceful shutdown - the daemon finishes in-flight requests, sends mDNS goodbye packets, and exits.                       |

The `/healthz` endpoint is intentionally minimal and cheap. It doesn't check subsystem health - it just confirms the process is responding. If you need deeper checks, use `/v1/status` or the health module.

---

## Configuration

Koi is configured through flags and environment variables. The daemon reads these at startup:

| Flag         | Env var        | Default | Description                    |
| ------------ | -------------- | ------- | ------------------------------ |
| `--port`     | `KOI_PORT`     | `5641`  | HTTP API port                  |
| `--daemon`   | -              | `false` | Run in foreground daemon mode  |
| `--log-file` | `KOI_LOG_FILE` | -       | Write logs to file             |
| `--json`     | -              | `false` | JSON output for status/version |

Each module has its own configuration documented in its respective guide. The system-level flags control the daemon itself - where it listens and how it logs.

---

## When things go wrong

### The service won't start

Check the platform-native logs first. The daemon writes structured logs that usually explain the failure:

```powershell
# Windows - Event Viewer (Application log)
Get-EventLog -LogName Application -Source koi -Newest 10

# Linux
journalctl -u koi --no-pager -n 20
```

The most common cause is a port conflict - another process already holds port 5641. Override it:

```
koi --port 5642 install
```

### The CLI can't reach the daemon

Koi writes a breadcrumb file when the daemon starts, telling the CLI where to connect. If the daemon was killed ungracefully (power loss, `taskkill /F`), the breadcrumb may be stale. Restarting the daemon fixes it.

### Something is deeply broken

That's what `factory-reset` is for. It's the nuclear option - but sometimes nuclear is what you need.
