# Upgrade & migration

You want to move a running Koi to a newer build without losing your certificate mesh,
DNS records, or proxy config — and without getting surprised by a breaking change. Koi
is **pre-1.0** (the workspace is `0.x`), so "newer build" is not automatically "drop-in
safe": breaking changes can ship in *any* release until 1.0, including patch releases.
This guide is the safe upgrade procedure and what to check before you run it.

The short version: **read the [CHANGELOG](../../CHANGELOG.md) first, back up if anything
looks risky, then upgrade.** The rest of this page is the detail.

---

## The pre-1.0 reality (read this before every upgrade)

While Koi is `0.x`, SemVer permits breaking changes at any version bump — and Koi uses
that latitude. A bump from `0.4.1` to `0.4.2` looks like a patch, but it can carry
breaking changes to on-disk state, the wire protocol, or the CLI surface.

So the rule is simple and it has no exceptions:

> **Always read the [CHANGELOG](../../CHANGELOG.md) for every version between the one
> you're running and the one you're upgrading to — before you upgrade.**

Look specifically for:

- A **`Removed (breaking)`** or **`Breaking`** section.
- Any mention of **on-disk state**, the **roster**, **certmesh**, or **data directory**
  formats.
- Changes to **CLI commands or flags** you script against.

Check what you're running now:

```
koi version
```

If a release between you and your target says nothing about breaking changes, the
upgrade is a binary swap (below) and you're done. If it *does*, [back up](#back-up-before-a-risky-upgrade)
first and read the specific migration note.

---

## How to upgrade

There are two shapes of install: a binary you run by hand, and the daemon installed as
an OS service. The service case is the common one.

### If Koi is installed as a service

`koi install` is the upgrade command. Running it again against a newer binary **stops
the existing service, swaps in the new binary, rewrites the service definition, and
restarts** — on every platform. You don't have to do the stop/swap/start dance by hand;
`install` does it for you.

```
# from the directory containing the new koi binary
# (run as root on Linux/macOS, as Administrator on Windows)
koi install
```

On Linux this stops the `koi` systemd unit, copies the binary into place, reloads
systemd, and restarts the service. Windows and macOS mirror the same UX through the
Service Control Manager and launchd respectively. See
[system.md](./system.md#installing-the-daemon) for what `install` registers on each OS.

If you want to do it explicitly — for example, to run a few `koi status` checks while
the daemon is down — the manual sequence per OS is:

```bash
# Linux (systemd)
sudo systemctl stop koi
sudo cp ./koi /usr/local/bin/koi      # replace the installed binary
sudo systemctl start koi
```

```powershell
# Windows (PowerShell as Administrator)
Stop-Service koi
# replace the installed koi.exe, then:
Start-Service koi
```

```bash
# macOS (launchd) — re-running install is the supported path:
sudo koi install
```

In all cases, running `koi install` from the new binary is the supported, least
error-prone route — prefer it unless you have a reason to step through manually.

> **Custom port?** If you originally installed on a non-default port (e.g.
> `koi --port 5642 install`), re-run `install` with the same flag so the rewritten
> service definition keeps it.

### If you run the binary by hand

If you launch the daemon yourself (`koi --daemon`) or only use the CLI, upgrading is
just replacing the binary on your `PATH` (or rebuilding from source) and restarting any
foreground daemon:

```
# foreground daemon: stop it (Ctrl+C), replace the binary, start it again
koi --daemon
```

To rebuild from source:

```
cargo install --path crates/koi      # or: cargo build --release
```

Verify afterwards:

```
koi version
koi status
```

`koi uninstall` is **not** part of upgrading — it removes the service registration but
preserves your data, and you'd only use it if you wanted to stop running Koi as a
service entirely. See [system.md](./system.md#uninstalling).

---

## Back up before a risky upgrade

When the CHANGELOG flags breaking changes that touch on-disk state, back up first. The
single most valuable thing to protect is the **certificate mesh** — losing the CA key
is unrecoverable.

**Back up certmesh with the built-in command** (it produces an encrypted, restorable
bundle — far better than copying files by hand):

```
koi certmesh backup mesh-pre-upgrade.koi
```

This bundles the CA keypair, CA certificate, enrollment auth credential, the full
roster, and the audit log. Store it off the host and remember the backup passphrase —
the full procedure, what's *not* in the bundle, and how to restore is in
[certmesh-ha-recovery.md](./certmesh-ha-recovery.md). (`backup`/`restore` are mutating
HTTP operations: over the API they need the `x-koi-token` header — see
[the security model](../reference/security-model.md).)

**Back up the rest of the on-disk state** by copying the data directory while the daemon
is stopped. Everything Koi persists lives under one machine-scoped root:

| Platform | Data directory |
| -------- | -------------- |
| Linux | `/var/lib/koi/` |
| macOS | `/Library/Application Support/koi/` |
| Windows | `%ProgramData%\koi\` |

(Override with `KOI_DATA_DIR` — if you set it, back up *that* path instead.) The
subtrees that matter for a risky upgrade:

- **`certmesh/`** — the certificate mesh: `certmesh/ca/` (CA key, cert, enrollment auth),
  `certmesh/roster.json` (the member roster), and the audit log. This is the part the
  `koi certmesh backup` bundle covers; the raw directory is a belt-and-braces copy.
- **`certs/`** — issued/installed certificates, including each member's
  `certs/<hostname>/` cert and key.
- **`state/`** — runtime state (DNS records, health checks, proxy entries, etc.).
- **`logs/`** — diagnostic logs (not needed to restore, but cheap to keep).

A simple recursive copy of the data directory, taken with the daemon stopped, captures
all of it.

---

## The 0.4.2 upgrade (specific caveat)

**0.4.2 carries breaking changes despite the patch version.** The
[CHANGELOG](../../CHANGELOG.md) calls this out directly — it's a large lean-and-reach
release, and its `Removed (breaking)` / `Changed` sections apply even though the version
only ticked from `0.4.1` to `0.4.2`.

The one to plan around if you run a certificate mesh:

> Existing certmesh **`roster.json`** files written by an older version **may need a
> `koi certmesh create` re-run.**

Be cautious here. `koi certmesh create` initializes a CA — so before you go anywhere near
it on an existing mesh, **take a backup**:

```
koi certmesh backup mesh-pre-0.4.2.koi
```

Then upgrade, and check whether the mesh still reads its roster cleanly:

```
koi certmesh status
```

If the roster loads and the members are present, you're done — nothing to migrate. Only
if the older `roster.json` doesn't read correctly should you follow the CHANGELOG's
note and re-run `koi certmesh create`; with the backup in hand you can
[restore](./certmesh-ha-recovery.md#2b-restore-from-backup-onto-a-fresh-ca-host) if the
re-run isn't what you wanted. The CHANGELOG states this as a *may* — it does not list a
mechanical field-by-field migration, so treat the backup as mandatory rather than
optional.

Other 0.4.2 breaking changes that may affect scripts rather than on-disk state (read the
CHANGELOG for the full list):

- **FIDO2 enrollment is removed** (the `AuthAdapter` re-entry path stays).
- **Automatic CA failover is gone** — manual `koi certmesh promote` remains the only
  promotion path (see [certmesh-ha-recovery.md](./certmesh-ha-recovery.md)).
- **Enrollment deadline / CIDR-domain scope** (`set-policy`) and the **certmesh
  compliance** endpoint/CLI are removed.
- **`--runtime k8s`** (and other stub backends) is now a parse error instead of a silent
  fallback.

---

## After upgrading

```
koi version      # confirms the new binary is the one running
koi status       # all capabilities report their state
```

If you run a mesh, also confirm the CA is healthy:

```
koi certmesh status
```

If something is wrong after a service upgrade, the platform-native logs usually explain
it — see [system.md](./system.md#when-things-go-wrong) for where to look on each OS.

---

## See also

- [system.md](./system.md) — installing, running, and uninstalling the daemon as a
  service; status and logs.
- [certmesh-ha-recovery.md](./certmesh-ha-recovery.md) — `backup`/`restore`/`promote` in
  full, and the disaster-recovery runbook.
- [certmesh.md](./certmesh.md) — creating, joining, and unlocking the CA.
- [../reference/security-model.md](../reference/security-model.md) — the daemon access
  token for mutating HTTP calls, bind addresses, and data locations.
- [../index.md](../index.md) — all guides and reference docs.
