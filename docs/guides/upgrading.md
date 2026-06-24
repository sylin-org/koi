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
> `koi --port 5651 install`), re-run `install` with the same flag so the rewritten
> service definition keeps it. (Avoid 5642/5643 for `--port` — those are the
> certmesh mTLS and ACME ports.)

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

## The 0.8.0 upgrade

**0.8.0 is a drop-in — no breaking changes.** Nothing on disk, on the CLI, at the network
edge, or in the JSON / Rust API changes incompatibly. Swap the binary and you're done.

The release is cert-lifecycle reliability — trust that maintains itself on a long-lived node:

- A continuously-up CA now renews **its own** leaf on the timer (it used to refresh only at
  restart), and the inter-node mTLS (5642) + ACME (5643) listeners **hot-reload** the renewed
  leaf with no restart and no dropped connections.
- The certmesh background renewal loop runs a pass **immediately at startup**, so a node that
  boots with an already-overdue leaf refreshes at once instead of serving a stale cert.
- A malformed `CertPolicy` (`renew_threshold_days >= leaf_lifetime_days`, or a zero
  lifetime/threshold) is rejected back to the default on load instead of churning re-issues.

No certmesh re-create, roster migration, or data-directory change is required for 0.8.0. If
you **embed Koi** and run `Builder::certmesh_background(true)`, you now get CA self-renewal
and listener hot-reload for free — drop any hand-rolled CA-leaf renewal and any startup
`ensure_identity()` ritual.

---

## The 0.7.0 upgrade

**0.7.0 is a near-drop-in — one narrow breaking change, only for Rust embedders that
exhaustively match the `Assurance` verdict.** Nothing on disk, on the CLI, at the network
edge, or in the JSON wire shapes changes incompatibly. Swap the binary and you're done.

Review this if you **embed Koi** and `match` on `Assurance`:

- **`Assurance::Rejected` gained a field:** `Rejected { reason, signer_cn: Option<String> }`.
  An exhaustive match on the old shape no longer compiles — add `, ..` (or read the new
  field):
  ```rust
  // before: Assurance::Rejected { reason } => …
  Assurance::Rejected { reason, .. } => …
  ```
  `signer_cn` is the **authoritative** signer CN when the rejected leaf chained to the
  pinned CA but is stale (`Expired` / `Revoked`) — useful for audit and a "your identity
  expired — rejoin" prompt — and `None` otherwise. The JSON shape is unchanged for the
  common case (the field is omitted when absent), so **non-Rust readers need no change**.

Everything else in 0.7.0 is additive:

- **`Assurance::identity_for(env, expected)`** — the request-bound identity door. The safe
  way to authorize a request from an envelope (closes a silent-impersonation footgun where
  `identity().is_some()` would accept a captured envelope replayed against a different
  request). Existing `identity()` callers are unaffected.
- **`leaf_not_after_utc(pem)` / `leaf_cn(pem)`** — new public stateless leaf readers.
- **`RenewResponse.policy`** — the renew response now carries the CA's `CertPolicy`
  (`#[serde(default)]`, so a 0.7.0 member still parses an older CA's response).

No certmesh re-create, roster migration, or data-directory change is required for 0.7.0.

## The 0.6.0 upgrade

**0.6.0 is a clean drop-in — no breaking changes.** Despite the minor bump, nothing on
disk, on the CLI, at the network edge, or in the embedded API changes incompatibly. Swap
the binary and you're done; no certmesh re-create, roster migration, or data-directory
change is required.

Everything in 0.6.0 is additive or an internal refactor:

- **`CertmeshCore::renew_member(authenticated_cn, csr_pem)`** (ADR-021) — new CA-side
  domain method for transport-agnostic member renewal. The `/renew` mTLS endpoint is
  unchanged on the wire; it now delegates to this method internally.
- **`KoiHandle::sign()` / `verify()`** and **`CertmeshCore::member_cert_expiry()`** — new
  additive embedded conveniences. Existing `certmesh().sign()/verify()` calls keep working.
- **Network-browser type labels** and the **first-run getting-started hint** are
  presentation-only.

One behavioral fix worth noting: a `/renew` request from a **non-active** member now
returns **403** instead of a 500 (the request was always refused; only the status code
was wrong). No client that handled the refusal needs to change.

## The 0.5.1 upgrade

**0.5.1 is a binary swap for operators — nothing on disk, on the CLI, or at the network
edge changes.** Despite the patch version it carries two breaking changes, but both are
narrow: they affect **embedders** (the `koi-embedded` crate) and **cross-implementation
readers** of the trust wire contract, not a normal daemon/CLI deployment. If you run Koi
as a service and drive it from the CLI, upgrade and you're done.

Review these if you **embed Koi** or implement the trust protocol in another language:

- **`CertmeshHandle::posture()` is now `async`.** An embedder calling
  `handle.certmesh()?.posture()` must add `.await`:
  ```rust
  // before: let p = handle.certmesh()?.posture()?;
  let p = handle.certmesh()?.posture().await?;
  ```
  It now also works in **remote (client) mode** — it queries `GET /v1/certmesh/posture`,
  which is DAT-gated, so a remote handle must carry a token (set `Builder::service_token(..)`,
  or let it adopt the local breadcrumb token automatically when the endpoint matches).
- **Three `RejectReason` values are gone:** `no_signature`, `clock_skew`, `name_mismatch`.
  The verifier never produced them — an unsigned envelope is `anonymous`, an out-of-window
  timestamp is `authenticated { freshness: "stale" }`. Rust code that `match`ed those
  variants won't compile (delete the arms); a non-Rust reader of the published
  `RejectReason` set should drop them from its enum
  ([trust-protocol.md §2](../reference/trust-protocol.md)).

Everything else in 0.5.1 is additive (the `GET /v1/events` SSE stream, `GET /v1/certmesh/posture`,
the cert-lifecycle events, `require_auth_with`, `reqwest_client_for`, `try_serve`,
`on_posture`, `service_token`) — no action needed to keep an existing integration working.

No certmesh re-create, roster migration, or data-directory change is required for 0.5.1.

---

## The 0.5.0 upgrade

**0.5.0 changes behavior at the network edge — nothing on disk needs migrating.** The
breaking changes are about *who can call what* once the daemon is exposed off-loopback, and
about embedding. If you run Koi loopback-only and drive it from the CLI, you're unaffected.
Review these if you expose the daemon (`--http-bind`), script against it from another host,
or embed it:

- **Some GET reads now need the token from a remote peer.** `GET /v1/certmesh/diagnose` and
  `/v1/dns/{list,zone,entries}` stay token-free on loopback, but a **non-loopback** caller
  must send `-H "x-koi-token: $TOKEN"` (read it with `koi token show`). A remote script that
  polled `…/v1/dns/zone` unauthenticated now gets a `401` — add the header.
  `/v1/certmesh/status` and `/v1/certmesh/trust-bundle` stay open (enrollment depends on them).
- **The audit log and the UDP surface are token-gated on every method.** `GET /v1/certmesh/log`,
  `GET /v1/udp/status`, and `GET /v1/udp/recv/{id}` now require the token.
- **UDP binds loopback by default.** `koi udp bind` (and `send` to a non-loopback destination)
  now needs `--allow-remote`. A binding that used to listen on `0.0.0.0` must pass it explicitly.
- **Embedding is secure-by-default.** If you build with `announce_http()`, you must now also set
  `http_token(..)` or `start()` returns `KoiError::InsecureConfig` (it used to warn and continue).
  Loopback-only embedders are unaffected.

No certmesh re-create or roster migration is required for 0.5.0 (that was a 0.4.2 caveat, below).

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
