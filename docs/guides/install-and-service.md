# Install and operate the host service

Koi's container/LAN task needs a host daemon with engine access. Installing a
binary, starting a daemon and proving second-machine application access are
separate steps. This guide covers the first two; the
[container walkthrough](../../CONTAINERS.md) covers the outcome.

[Release readiness](../launch/README.md) names supported artifacts and scenarios.
The first target matrix is Windows x64/Docker Desktop and Linux glibc x64/Docker
Engine with native clients. A target is not an already accepted preview. Other
platform recipes remain available with their own verification requirements.

## Choose the binary

| Line | Version | Meaning |
| --- | --- | --- |
| Stable | 0.9.0 | Published stable artifact; use matching release docs |
| Prerelease | 1.0.0-rc.2 | Published explicitly pinned prerelease |
| Source | 1.0.0-dev.0 | Development; no new public preview implied |

A pinned archive from [GitHub Releases](https://github.com/sylin-org/koi/releases)
makes the selected bytes clear. Verify its SHA-256 against the release sidecar
before extraction. On Windows use Get-FileHash; on Linux use sha256sum; on macOS
use shasum -a 256. Check the supplied filename and digest, not just that hashing
succeeds.

Release assets with GitHub provenance can additionally be checked using
gh attestation verify against sylin-org/koi. A checksum detects altered bytes
relative to the source you trust; it is not independent publisher authentication.

The bootstrap scripts download a matching archive and verify its checksum:

```sh
curl -fsSL https://raw.githubusercontent.com/sylin-org/koi/main/install.sh | sh
```

```powershell
irm https://raw.githubusercontent.com/sylin-org/koi/main/install.ps1 | iex
```

Without an override they select the latest stable release, not current development
source. Select a published prerelease explicitly:

```sh
curl -fsSL https://raw.githubusercontent.com/sylin-org/koi/main/install.sh | KOI_VERSION=v1.0.0-rc.2 sh
```

```powershell
$env:KOI_VERSION = 'v1.0.0-rc.2'
irm https://raw.githubusercontent.com/sylin-org/koi/main/install.ps1 | iex
Remove-Item Env:KOI_VERSION
```

KOI_INSTALL_DIR selects the binary location. KOI_NO_MODIFY_PATH skips the script's
PATH changes/guidance. The default per-user installation does not need root.
Open a fresh terminal if PATH changed, then run koi version.

npm is not an available public installation path. Package-manager scaffolds are
not published channels. Rust users can source-build the published koi-net crate;
cargo install requires a toolchain. A Koi image behind a bridge is not a substitute
for a daemon on the LAN host merely because its HTTP port is published.

## Evaluate in the foreground

When no local Koi service already exists:

```sh
koi --daemon
```

In another terminal:

```sh
koi status
curl -fsS http://127.0.0.1:5641/v1/runtime/status
```

Bare koi displays status and help. It does not start a daemon. An explicit
standalone discovery session is available only when no local service owns it.

## Install for persistent use

Use an Administrator terminal on Windows:

```powershell
koi install
```

On Linux/macOS:

```sh
sudo koi install
```

For a direct-root or package installation, name the intended local operator:

```sh
sudo koi install --operator alice
```

Replace alice with the actual account. On supported systemd hosts, a user service
can use koi install --user; do not assume that option works under every init system.

| Platform | Native service | Operational distinction |
| --- | --- | --- |
| Windows | SCM service koi | Stages the executable under Program Files; use sc.exe in PowerShell |
| Linux/systemd | koi.service | Machine service; account/environment can differ from an interactive shell |
| Linux/OpenRC | koi with supervise-daemon | Respects native package ownership; recipe requires its declared logging dependencies |
| macOS | launchd org.sylin.koi | System LaunchDaemon, not a login LaunchAgent |

A successful recipe enables startup and verifies the installed daemon.
Transactional Windows and Linux recipes preserve prior executable, registration,
configuration and owned policy during a failed replacement. An interrupted
install recovers through the supported installer path; do not delete its
checkpoint/backup files manually.

Platform support and installed lifecycle acceptance remain separate. Check the
actual generated service identity, binary and configuration.

## Verify the installed process

```sh
koi version
koi status
curl -fsS http://127.0.0.1:5641/v1/runtime/status
```

Also inspect the native manager:

```powershell
sc.exe query koi
sc.exe qc koi
```

```sh
systemctl status koi
systemctl cat koi
```

Use rc-service koi status on OpenRC or launchctl print system/org.sylin.koi on
macOS. The shell's koi version identifies that CLI binary; compare it with the
installed service's executable/version. Runtime socket access must work for the
service account, including after login or reboot as applicable.

Then perform the real [container trial](../../CONTAINERS.md). Healthz or service
manager success does not prove application access from another machine.

## Logs and data

| Platform | Default data root | Service logs |
| --- | --- | --- |
| Windows | %ProgramData%\koi | %ProgramData%\koi\logs\koi.log |
| Linux | /var/lib/koi | systemd journal or OpenRC /var/log/koi/daemon.log |
| macOS | /Library/Application Support/koi | /var/log/koi.log and /var/log/koi.err |

A configured KOI_DATA_DIR changes the data root; inspect the actual service
configuration. Certificate material, persistent state, operator policy and
configuration outside the data root all matter during recovery.

```powershell
Get-Content "$env:ProgramData\koi\logs\koi.log" -Tail 40
```

```sh
journalctl -u koi -n 40
```

Use debug logging for a bounded investigation and avoid sharing secrets or
private network inventories in logs.

## Ports, bind and engine access

Management HTTP defaults to loopback. For a participating container on native
Linux, configure the existing service with a deliberate bridge bind. Off-loopback
exposure does not relax authentication and HTTP is still plaintext.
[API authentication](api-authentication.md) and [security](../reference/security-model.md)
state the exact route rules.

Common daemon options are --port / KOI_PORT, --http-bind / KOI_HTTP_BIND,
--dns-port / KOI_DNS_PORT and --runtime / KOI_RUNTIME. Capabilities can be disabled
with their --no-* options. Apply settings through the recipe's durable configuration
or native service environment, then inspect what the restarted service actually uses.
A variable set only in your terminal does not configure an existing service.

On systemd, use a unit override when appropriate, inspect it with systemctl cat,
reload the manager and restart the named service. On Windows/macOS use the native
service configuration. Preserve existing overrides instead of assuming defaults.

Windows installation manages Koi-owned firewall rules. Inspect actual rules and
listener reachability; a rule does not prove that a socket or an application is
available. Linux/macOS firewall policy remains operator-owned. Engine/socket
permissions are separate from firewall permissions.

## Upgrade, stop or uninstall

Read [upgrading](upgrading.md) before replacing an existing binary or state.
Use the selected artifact's install recipe; service paths should not point to
a temporary checkout or package cache.

Stop/start through the native manager. In PowerShell use sc.exe, not the sc alias.
On OpenRC use rc-service; on systemd use systemctl.

```sh
koi uninstall
```

Uninstall removes the service and Koi-owned registration/policy according to the
recipe while preserving application data for reinstallation. It is not a factory
reset and does not intentionally destroy a CA. Review
[system lifecycle](system.md) before destructive cleanup.

## If setup fails

Capture the exact artifact, native manager error, service log, generated
configuration and failing stage. Do not report an unavailable engine as an empty
network or rerun a failed installation without inspecting its restoration result.
[Troubleshooting](troubleshooting.md) provides the investigation path.
