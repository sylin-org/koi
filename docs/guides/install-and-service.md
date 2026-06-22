# Install Koi as a service

You ran `koi --daemon` to try it, and it works — but it dies when you close the terminal. To get the daemon that survives reboots, starts before your apps need it, and runs without a console attached, install Koi as a native OS service. This guide is the consolidated service-ops reference: install, manage, and uninstall cleanly on each platform, plus where the data and logs live and how to change the port or bind for the installed service.

> **Lifecycle context.** This page is about the *service* — how the OS keeps the daemon running. For what the daemon *does* once it's up (status, dashboard, the module model, factory reset), see [system: daemon lifecycle](./system.md).

---

## Get the binary

`koi install` assumes the `koi` binary is already on your `PATH`. The fastest way to get it is the one-line installer — it downloads the latest release archive for your OS/arch, verifies its checksum, and puts the binary on your `PATH`. It never compiles anything and doesn't need root for the default per-user location.

```sh
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/sylin-org/koi/main/install.sh | sh
```

```powershell
# Windows
irm https://raw.githubusercontent.com/sylin-org/koi/main/install.ps1 | iex
```

Both installers honor the same knobs as environment variables: `KOI_VERSION` (pin a release tag, e.g. `v0.4.2`), `KOI_INSTALL_DIR` (install location), and `KOI_NO_MODIFY_PATH` (skip the PATH change).

Prefer a container? The image runs the daemon via its default command — no install needed:

```sh
docker run -d --name koi -p 5641:5641 ghcr.io/sylin-org/koi:latest
```

Just trying Koi out, or want the full first-run walkthrough? Start with the [getting-started tutorial](../tutorials/getting-started.md) — it goes from nothing installed to a visible result in about a minute. Come back here when you're ready to run Koi as a service that survives reboots.

---

## Install

```
koi install
```

That's the whole command on every platform. It requires elevation — Koi refuses to install otherwise:

- **Windows**: run from an Administrator terminal (right-click → *Run as administrator*). Koi checks for elevation via `net session` and bails with a clear message if you're not elevated.
- **Linux / macOS**: run with `sudo`.

`koi install` is idempotent and upgrade-aware. If a service is already registered it stops the old one, replaces the binary/registration, and restarts — so re-running it after a `koi` upgrade is the supported way to update the installed service.

On success you'll see the modules-enabled summary and `the local waters are calm`. All capabilities are enabled by default; disable any with `--no-<name>` at install time (see [Changing the port or bind](#changing-the-port-or-bind) — the same mechanism applies to capability flags).

### What `koi install` does, per OS

| OS | Service manager | Name / label | Registration |
| -- | --------------- | ------------ | ------------ |
| **Windows** | Service Control Manager (`sc.exe`) | service `koi` (display name *Koi Network Toolkit*) | Own-process service, **AutoStart**, recovery policy: restart after 5s, then 10s, then stop (failure count resets after 24h) |
| **Linux** | systemd (`systemctl`) | unit `koi.service` | Copies the binary to `/usr/local/bin/koi`, writes `/etc/systemd/system/koi.service` (`Type=notify`, `Restart=on-failure`, `RestartSec=5s`), runs `daemon-reload`, `enable` (start on boot), and `start` |
| **macOS** | launchd (`launchctl`) | LaunchDaemon `org.sylin.koi` | Copies the binary to `/usr/local/bin/koi` (root:wheel, 755), writes `/Library/LaunchDaemons/org.sylin.koi.plist` (root:wheel, 644), bootstraps it into the `system` domain. `RunAtLoad` + `KeepAlive` on non-success exit |

All three register the service to **start on boot** and start it immediately. The service runs the binary as `<binary> --daemon`.

> **macOS note:** Koi installs a system-wide **LaunchDaemon** (under `/Library/LaunchDaemons`, loaded into the `system` domain), not a per-user LaunchAgent. It runs at boot before any user logs in.

---

## Verify it's running

```
koi status            # what each module is doing
koi launch            # open the web dashboard in your browser
```

You can also ask the native service manager directly:

```powershell
# Windows
sc query koi
```

```sh
# Linux
systemctl status koi

# macOS
sudo launchctl list | grep org.sylin.koi
```

---

## Manage the service

Use the native manager for start/stop/restart. `koi` doesn't wrap these — once installed, the service belongs to the OS.

### Windows (SCM)

```powershell
sc start koi
sc stop koi
sc query koi          # current state + last exit code
```

`net start koi` / `net stop koi` work too. The recovery policy auto-restarts the service if it crashes (5s, then 10s, then gives up until you intervene).

### Linux (systemd)

```sh
sudo systemctl start koi
sudo systemctl stop koi
sudo systemctl restart koi
sudo systemctl status koi
```

The unit is `Restart=on-failure`, so systemd restarts the daemon if it exits with an error.

### macOS (launchd)

```sh
sudo launchctl kickstart -k system/org.sylin.koi   # restart
sudo launchctl bootout system/org.sylin.koi        # stop/unload
sudo launchctl bootstrap system /Library/LaunchDaemons/org.sylin.koi.plist   # start/load
```

`KeepAlive` (on non-success exit) means launchd restarts the daemon if it crashes.

---

## Logs and data locations

### Data directory (per OS)

All Koi data is machine-scoped — CA keys, certs, DNS records, health/proxy config, state, and logs live here, not in a user profile.

| OS | Data directory |
| -- | -------------- |
| **Windows** | `%ProgramData%\koi\` (typically `C:\ProgramData\koi`) |
| **Linux** | `/var/lib/koi/` |
| **macOS** | `/Library/Application Support/koi/` |

Inside that directory: `certs/`, `state/`, and `logs/`. Override the root for testing with the `KOI_DATA_DIR` environment variable.

### Logs

| OS | Service logs |
| -- | ------------ |
| **Windows** | `%ProgramData%\koi\logs\koi.log` |
| **Linux** | `journalctl -u koi` (the systemd journal) |
| **macOS** | `/var/log/koi.log` (stdout) and `/var/log/koi.err` (stderr) |

```powershell
# Windows — tail the service log
Get-Content "$env:ProgramData\koi\logs\koi.log" -Tail 40 -Wait
```

```sh
# Linux — follow the journal
journalctl -u koi -f

# macOS — follow the log
tail -f /var/log/koi.log
```

The log level defaults to `info`; set `KOI_LOG` (e.g. `KOI_LOG=debug`) to change it (see [Changing the port or bind](#changing-the-port-or-bind) for where to set environment for the service).

---

## The Windows firewall rule

On Windows, `koi install` manages inbound firewall rules with `netsh advfirewall` (best-effort — install never aborts if a rule fails). Rules are opened **only for ports that are actually reachable from off-box**:

- **mDNS** (UDP 5353) and **DNS** (when the DNS capability is enabled) — these bind broadly, so they get rules.
- **The HTTP API port — only when it's exposed.** By default the HTTP API binds loopback (`127.0.0.1`), and loopback traffic never crosses the firewall, so **no HTTP rule is created**. A rule is added only when you bind it off-loopback (`--http-bind bridge`, a specific NIC IP, or `0.0.0.0`).

`koi uninstall` removes the rules it created (and cleans up rules from older versions). Linux and macOS don't auto-manage the firewall — open ports with your distro's firewall tooling if you expose the daemon.

> Exposing the HTTP port does **not** relax authentication. Mutating requests still require the daemon access token regardless of bind address — see the [security model](../reference/security-model.md).

---

## Changing the port or bind

`koi install` has no flags of its own — the service inherits the daemon's configuration the same way the foreground daemon does, via global flags and environment variables read at startup.

### At install time, with global flags

Put the daemon flags **before** the subcommand:

```powershell
# Windows: install on a custom port (Administrator)
koi --port 5642 install
```

```sh
# Linux/macOS: expose the HTTP API to the LAN, custom port
sudo koi --port 5642 --http-bind 0.0.0.0 install
```

The relevant knobs:

| Flag | Env var | Default | Effect |
| ---- | ------- | ------- | ------ |
| `--port <n>` | `KOI_PORT` | `5641` | HTTP API port |
| `--http-bind <v>` | `KOI_HTTP_BIND` | `loopback` | `loopback` / `bridge` / `<ip>` / `0.0.0.0` — where the HTTP API binds |
| `--log-level <l>` | `KOI_LOG` | `info` | Log verbosity |
| `--no-<name>` | `KOI_NO_<NAME>` | off | Disable a capability (e.g. `--no-udp`, `--no-proxy`) |

`--http-bind` values and their exposure trade-offs are documented in the [security model](../reference/security-model.md#listeners). Non-loopback binds also surface in `koi status` (the `Bind:` line) and trigger the Windows HTTP firewall rule above.

> **Persistence caveat — Linux/macOS:** flags baked into the unit/plist at install time persist because the install writes `ExecStart=… --daemon` / `ProgramArguments` to disk. On Linux, command-line flags you pass to `koi install` are **not** copied into the generated unit — the cleanest way to make settings stick is environment (below) or editing the unit. Re-running `koi --port … install` rewrites the registration, so it's also a valid way to change the installed configuration.

### After install, with environment

The daemon reads its environment variables at startup, so setting them for the service makes the change permanent across restarts.

**Linux (systemd):**

```sh
sudo systemctl edit koi
```

Add an override:

```ini
[Service]
Environment=KOI_PORT=5642
Environment=KOI_HTTP_BIND=0.0.0.0
```

Then `sudo systemctl daemon-reload && sudo systemctl restart koi`.

**Windows:** set a machine-scoped environment variable and restart the service:

```powershell
[Environment]::SetEnvironmentVariable('KOI_PORT', '5642', 'Machine')
sc stop koi; sc start koi
```

**macOS:** add the variables to the plist under an `EnvironmentVariables` dict (edit `/Library/LaunchDaemons/org.sylin.koi.plist`), then `bootout` + `bootstrap` to reload.

After changing the port, the breadcrumb the CLI uses for auto-discovery is rewritten on restart, so `koi status` and the other commands follow automatically.

---

## Uninstall

```
koi uninstall
```

Requires elevation (Administrator / `sudo`), same as install. It checks whether a service is actually registered *before* asking for elevation, so running it on a machine with no service just reports *nothing to uninstall*.

Uninstall is intentionally **conservative**:

1. Sends a graceful shutdown to the running daemon (so it sends mDNS goodbyes and finishes in-flight work), then stops it via the service manager.
2. Removes the service registration:
   - Windows: deletes the SCM service and the firewall rules Koi created.
   - Linux: `stop` → `disable` → removes `/etc/systemd/system/koi.service` → `daemon-reload`.
   - macOS: `bootout` the LaunchDaemon → removes the plist; deletes the log files only if they're empty.
3. Removes the discovery breadcrumb.
4. **Preserves all your data.** CA keys, certificates, DNS records, health/proxy config, and audit logs stay in the data directory. The installed binary at `/usr/local/bin/koi` is preserved on Linux/macOS.

So reinstalling later picks up exactly where you left off. Removing the service does **not** remove what the service managed.

> To actually wipe state — CA keys, certs, every record — that's [`koi factory-reset`](./system.md#factory-reset), not uninstall. It's irreversible and prompts for confirmation.

---

## Troubleshooting

### "requires Administrator privileges" / permission denied

`koi install` and `koi uninstall` need elevation. On Windows, start the terminal with *Run as administrator*; on Linux/macOS prefix with `sudo`.

### The service won't start

Check the platform logs (above) — the daemon logs the reason. The most common cause is a **port conflict**: another process already holds 5641. Reinstall on a different port:

```
koi --port 5642 install
```

On Windows, if `sc query koi` shows a non-zero exit code, also check **Event Viewer → Windows Logs → System** for SCM-level errors.

### The CLI can't reach the daemon after a port change

The CLI finds the daemon via a breadcrumb file written at startup. After changing the port, restart the service so the breadcrumb is rewritten:

```sh
sudo systemctl restart koi          # Linux
```
```powershell
sc stop koi; sc start koi           # Windows
```

If the daemon was killed ungracefully (power loss, `taskkill /F`), the breadcrumb can go stale — restarting the service fixes it.

---

## See also

- [Getting started](../tutorials/getting-started.md) — install and a first visible result in about a minute.
- [System: daemon lifecycle](./system.md) — status, dashboard, modules, factory reset.
- [Security model](../reference/security-model.md) — bind addresses, the daemon access token, what's exposed when you bind off-loopback.
- [CLI reference](../reference/cli.md) — every flag and environment variable.
- [certmesh](./certmesh.md) — initialize the CA after the service is up.
- [Documentation index](../index.md).
