# Trust — Distribute and Trust CA Roots

Here's the problem: TLS verification only works if the verifier already trusts the
issuing root. You have a CA — Koi's own certmesh root, or step-ca, mkcert, Caddy's
internal issuer, a corporate root — and you need a machine to trust everything that
root signs, without per-app `--cacert` flags or hand-editing the OS certificate store.

`koi trust` is that one command. It installs a PEM CA root into the operating
system's trust store (so browsers, `curl`, and language runtimes all pick it up),
tracks the roots **it** installed so you can list and undo them later, and exports
the certmesh root so non-member clients can be bootstrapped. Every door has an exit:
`koi trust remove` untrusts what you installed, and nothing else in your OS store is
ever touched.

This is the last mile of trusted HTTPS. The [Trusted-HTTPS
tutorial](../tutorials/trusted-https.md) walks the full journey (CA → enroll → proxy
→ trust); this guide is the reference for the `trust` command group itself.

> **Local, not daemon-mediated.** `koi trust` talks to the OS certificate store
> directly — it does **not** go through the daemon and needs no running daemon or
> access token. Because it mutates the system trust store, `install` and `remove`
> **require elevated privileges** (Administrator on Windows, `sudo`/root on
> Linux/macOS). `list` and `export` do not.

---

## Trust an arbitrary CA root

`koi trust install` takes a path to a PEM-encoded CA certificate and adds it to the
OS trust store:

```sh
# Trust a step-ca root system-wide (browsers, curl, language runtimes).
sudo koi trust install ./step-ca-root.pem
```

```console
Installed CA "koi-step-ca-root" (sha256: 9f86d081884c7d65...)
The OS trust store now trusts certificates signed by this root.
```

It validates the input before touching the store: the file must be a real X.509
certificate **and** carry the CA basic constraint. A server/leaf certificate is
rejected so you can't accidentally install the wrong PEM as a root:

```console
$ koi trust install ./server-leaf.pem
Error: invalid CA certificate: invalid certificate: not a CA certificate (no CA basic constraint)
```

### The installed name is derived from the filename

You don't pass a name to `install` — Koi derives one from the PEM file's stem,
sanitized and prefixed with `koi-`:

| PEM file | Installed name |
| -------- | -------------- |
| `step-ca-root.pem` | `koi-step-ca-root` |
| `rootCA.pem` | `koi-rootCA` |
| `koi-root.pem` | `koi-koi-root` |

That derived name is what you pass to `koi trust remove`, and what `koi trust list`
shows. (The `koi-root.pem` → `koi-koi-root` case is not a typo: the `koi-` prefix is
always added, even when the file already starts with `koi`.)

Re-installing the same filename updates the tracked entry in place rather than
duplicating it.

---

## List what Koi installed

```sh
koi trust list
```

```console
NAME                          INSTALLED             FINGERPRINT (sha256)
koi-step-ca-root              2026-06-15T09:12:04Z  9f86d081884c7d65...
koi-koi-root                  2026-06-15T09:30:18Z  e3b0c44298fc1c14...
```

This lists **only the roots Koi installed** — tracked in `state/trust.json` inside
the [data directory](../reference/security-model.md). It is deliberately *not* a
dump of your whole OS trust store; Koi never enumerates the roots it didn't put
there. Add `--json` for machine-readable output:

```sh
koi trust list --json
```

---

## Remove a Koi-installed root

Pass the name shown by `koi trust list`:

```sh
sudo koi trust remove koi-step-ca-root
```

```console
Removed CA "koi-step-ca-root" from the OS trust store.
```

`remove` only acts on roots tracked in `state/trust.json`. Ask it to remove a name
it doesn't know and it refuses rather than guessing:

```console
$ koi trust remove some-other-root
Error: no Koi-installed CA root named "some-other-root" (run `koi trust list` to see them)
```

Roots Koi did not install are never enumerated or modified.

---

## Export the certmesh root (bootstrap a client)

```sh
koi trust export --ca > koi-root.pem
```

This prints the **certmesh root CA** (PEM) to stdout — nothing else. It reads the CA
certificate from the certmesh data directory, so the CA must already exist (run `koi
certmesh create` first); otherwise it errors with the path it tried to read.

`--ca` is required and currently the only export target:

```console
$ koi trust export
Error: specify what to export: `koi trust export --ca` prints the certmesh root CA
```

Use the exported root to bootstrap trust on clients that **won't** read the OS store
— for example seeding an ACME client's CA bundle, or a container's trust roots — and
to teach non-member machines to trust your mesh. See the recipes below.

---

## Real use cases

### Trust the certmesh root on a non-member client

A machine that is **not** a certmesh member has nothing in its trust store about your
CA. (Members trust the root automatically; certmesh installs it during `create`/`join`.)
This is the common case for a laptop that just needs to open a mesh-served HTTPS URL
without a warning.

On the CA host, export the root and copy it over (scp, USB, paste — whatever you'd
normally use):

```sh
# On the CA host:
koi trust export --ca > koi-root.pem
```

On the client, install it:

```sh
# On the client (note the derived name from `koi-root.pem`):
sudo koi trust install ./koi-root.pem
koi trust list
sudo koi trust remove koi-koi-root      # untrust later — every door has an exit
```

That single step is what removes the certificate warning — TLS validation is doing
exactly its job. This is Step 4 of the [Trusted-HTTPS
tutorial](../tutorials/trusted-https.md#step-4--on-laptop-c-trust-the-ca-root); the
[certmesh guide](./certmesh.md) covers postures, enrollment, and renewal.

> **`koi trust` needs the Koi binary on that client, but the client never joins the
> mesh.** Installing Koi just to run one `trust install` is the easy path. If you
> can't put Koi there at all, trust `koi-root.pem` by hand through the OS's normal
> "add a trusted root" flow (`update-ca-certificates`, the Windows cert store, or
> Keychain Access) — `koi trust` is the convenience, not a requirement.

### Trust step-ca / mkcert / Caddy internal roots

`koi trust install` works with any CA root, not just Koi's. It makes the whole
machine trust certs the tool issues — no per-app `--cacert`:

- **step-ca** — `step ca root root.pem` writes the root; then `sudo koi trust install
  root.pem`. Anything step-ca issues is now trusted system-wide.
- **mkcert** — `mkcert -install` already trusts its root on the local machine. To push
  that same root to *other* machines, copy `$(mkcert -CAROOT)/rootCA.pem` over and run
  `sudo koi trust install rootCA.pem` there.
- **Caddy** — Caddy's automatic-HTTPS internal issuer writes a root at
  `$XDG_DATA_HOME/caddy/pki/authorities/local/root.crt`. Install it with `sudo koi
  trust install root.crt` to trust Caddy-issued local certs.

### Bootstrap an ACME client

If you run Koi's [ACME server](./acme.md), standard clients (Caddy, Traefik, `lego`)
need to trust the CA root once before they will accept the leaf certs Koi issues.
Hand them the root with `koi trust export --ca` — either install it into the client
machine's OS store with `koi trust install`, or feed the PEM directly into the
client's CA-bundle setting. The [ACME guide](./acme.md) shows where this fits the
one-time bootstrap recipe.

---

## Per-platform behavior

`install`, `list`, and `remove` use each OS's native trust mechanism. The PEM and
derived name are identical across platforms; only the underlying store differs.

| Platform | Install | Remove | List source |
| -------- | ------- | ------ | ----------- |
| **Linux** | Writes `/usr/local/share/ca-certificates/<name>.crt`, then runs `update-ca-certificates` | Deletes that file, then `update-ca-certificates --fresh` | `state/trust.json` |
| **Windows** | `certutil -addstore Root` into the machine Root store | `certutil -delstore Root <name>` | `state/trust.json` |
| **macOS** | `security add-trusted-cert` with `trustRoot` into the System keychain | `security delete-certificate -c <name>` from the System keychain | `state/trust.json` |

On all platforms, `koi trust list`/`remove` work off Koi's own `state/trust.json`
record — they never scrape the OS store. The OS store is the source of truth for
*trust*; `state/trust.json` is the source of truth for *what Koi added*.

> **macOS caveat.** macOS `remove` matches by certificate **common name** via
> `security delete-certificate -c <name>`. The name Koi tracks is the
> filename-derived name, not necessarily the certificate's CN, so removal on macOS
> can fail to find the cert if the two differ. If `koi trust remove` reports a
> `security` error on macOS, remove the root from **Keychain Access → System** by
> hand, then `koi trust remove` clears the stale `state/trust.json` entry.

---

## Command reference

```sh
koi trust install <pem-path>   # Install a CA root (elevation required); name derived from filename
koi trust list [--json]        # List the roots Koi installed (from state/trust.json)
koi trust remove <name>        # Remove a Koi-installed root by its derived name (elevation required)
koi trust export --ca          # Print the certmesh root CA (PEM) to stdout
```

There is no HTTP API for `koi trust`: these are CLI-only, local operations on the OS
trust store. They are not part of `/openapi.json`.

---

## Troubleshooting

### `not a CA certificate`

The PEM you passed is a server/leaf certificate, not a CA root. `koi trust install`
only installs roots (certs with the CA basic constraint). Find the actual root —
e.g. `step ca root`, `$(mkcert -CAROOT)/rootCA.pem`, `koi trust export --ca` for
Koi's own — and install that instead.

### Permission denied / `certutil`/`update-ca-certificates` exit code

Installing or removing a trusted root mutates the system store, which needs
elevation. Re-run with `sudo` (Linux/macOS) or from an **Administrator** shell
(Windows).

### `no Koi-installed CA root named "…"`

`koi trust remove` only manages roots tracked in `state/trust.json`. Run `koi trust
list` to see the exact derived names. (Remember the `koi-` prefix and the
filename-stem derivation — `koi-root.pem` lists as `koi-koi-root`.)

### `reading certmesh CA certificate at … (run koi certmesh create first)`

`koi trust export --ca` reads the certmesh root, which doesn't exist until you've
created a CA. Run `koi certmesh create` first (see the [certmesh
guide](./certmesh.md)).

---

## See also

- [Trusted-HTTPS tutorial](../tutorials/trusted-https.md) — the end-to-end journey;
  `koi trust` is the last-mile step that makes a non-member client trust the root.
- [certmesh guide](./certmesh.md) — the private CA whose root `koi trust export --ca`
  hands out; postures, enrollment, renewal.
- [ACME guide](./acme.md) — issue certs to Caddy/Traefik/`lego`; bootstrap their trust
  with the exported root.
- [integrations guide](./integrations.md) — Prometheus and Traefik/Caddy label
  interop (the `koi trust` material now lives here, in `trust.md`).
- [security model](../reference/security-model.md) — the daemon access token, bind
  addresses, and the data directory where `state/trust.json` lives.
