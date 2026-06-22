# Certmesh - Certificate Mesh

TLS is the foundation of trust on the internet. But on a local network, getting TLS right is surprisingly hard. Let's Encrypt doesn't issue certificates for `.local` names or private IPs. Self-signed certs trigger browser warnings and break API clients. Manually copying PEM files between machines is fragile and doesn't scale past two hosts. Corporate PKI requires infrastructure most teams don't have.

Koi's certmesh solves this by running a private Certificate Authority directly on your LAN. Two machines can establish mutual TLS trust in under a minute, with no external infrastructure, no manual certificate copying, and no self-signed warnings. The CA handles enrollment, issuance, renewal, and revocation automatically.

**When to use certmesh**: You have multiple machines on a LAN that need to communicate over TLS. A homelab where services should trust each other. A development team that needs HTTPS without public DNS. A staging environment that mirrors production's TLS requirements. If you need real certificates but don't have (or want) a public CA, certmesh is the answer.

All CLI commands use the `koi certmesh` prefix. All HTTP endpoints live under `/v1/certmesh/`. Certmesh commands require a running daemon - use `koi install` or `koi --daemon` first.

The full member exchange - create, invite, cross-machine join over the DAT-gated HTTP API, member-pull rotate-key renewal over mTLS, revocation, and boot-time clone refusal - is exercised end to end by an automated cross-participant integration suite (two-daemon, docker-compose cross-host, and Windows↔Linux cross-platform), so the behavior described here is validated, not just intended.

---

## Creating a certificate mesh

The first step is initializing a CA on the machine that will be the primary authority. This is a deliberate act - you're creating a root of trust for your network:

```
koi certmesh create
```

This launches an interactive **ceremony** - a server-driven wizard where all branching, validation, and content decisions happen in the domain logic, not the CLI. The terminal is a "dumb render loop" that displays prompts, collects input, and sends it back. This means identical creation logic whether you use the CLI or the HTTP API.

The ceremony walks through these steps:

1. **Choose a posture** - who is this mesh for? Pick one of three named presets (**Just Me**, **My Team**, **My Organization**) or **Custom** to set the underlying knobs yourself. The presets are just UX labels; what gets stored is two booleans (see "Choosing a posture" below)
2. **Operator name** - prompted when the posture requires approval (My Team, My Organization, or a Custom posture with approval on)
3. **Entropy collection** - the server generates 32 bytes of entropy; you contribute more by mashing keys on the keyboard. Both are combined via SHA-256 to seed passphrase generation
4. **Set the CA passphrase** - three options:
   - **Keep the suggestion** (default) - an EFF-wordlist passphrase is generated from the combined entropy
   - **Generate another** - re-derives a new passphrase from fresh entropy
   - **Type my own** - enter and confirm a passphrase of your choice (minimum 8 characters)
5. **Unlock method** (Custom only) - choose how the CA can be unlocked on boot:
   - `auto` - CA unlocks automatically on daemon start (single-user homelabs)
   - `token` - requires a TOTP code to unlock
   - `passphrase` - requires the CA passphrase to unlock
   - (The three presets pick this for you: Just Me and My Team auto-unlock; My Organization requires manual unlock.)
6. **Enrollment auth setup** - TOTP. Shows a QR code for your authenticator app. You must enter a valid code to verify your setup. After two failed attempts, you can regenerate the secret.
7. **Unlock token registration** (if unlock method = `token`) - registers a separate TOTP secret for CA unlock (distinct from enrollment auth)

After the ceremony completes, Koi:

1. Generates an ECDSA P-256 CA keypair
2. Encrypts the private key using **envelope encryption**: a random 256-bit master key encrypts the CA key, and the master key is wrapped by each unlock slot (passphrase, auto-unlock, and/or TOTP)
3. Creates a roster with this host as the primary member
4. Issues a certificate for the local hostname (self-enrollment)
5. Starts certmesh audit logging
6. Installs the CA certificate in the system trust store

The ceremony design means every step can be replayed or revised before finalization. Press **ESC** at any time to cancel without making changes.

TOTP supports any authenticator app (Google Authenticator, Authy, 1Password, etc.). You'll need a valid TOTP code to enroll new members.

### Choosing a posture

There is no `TrustProfile` type and nothing about a "profile" is persisted. A mesh's security posture is **two booleans** stored in the roster:

- `enrollment_open` - whether new nodes can join right now
- `requires_approval` - whether a join needs an operator to approve it (and, separately, whether the daemon auto-unlocks the CA on boot)

The wizard offers three **named presets** plus **Custom**. The names are purely UX - each preset just sets those booleans (and the boot-unlock decision) for you:

| Preset              | `--profile`    | enrollment_open | requires_approval | Boot unlock | Best for                                                |
| ------------------- | -------------- | --------------- | ----------------- | ----------- | ------------------------------------------------------- |
| **Just Me**         | `just-me`      | open            | no                | auto        | Personal homelab - you control all machines             |
| **My Team**         | `team`         | open            | yes               | auto        | Small office or lab - trust but verify                  |
| **My Organization** | `organization` | closed          | yes               | manual      | Strict environments - explicit approval for each member |
| **Custom**          | _(wizard only)_| you choose      | you choose        | you choose  | Any posture the presets don't cover                     |

```
koi certmesh create --profile just-me
koi certmesh create --profile team --operator "Alice"
koi certmesh create --profile organization --operator "Security Team"
```

The operator field is a human-readable label for audit trails and is required whenever `requires_approval` is on. In the Just Me preset, you are the operator by default.

### Interactive wizard + flags

By default, `koi certmesh create` runs the interactive ceremony described above. The ceremony engine handles all branching and validation - the CLI is a generic render loop that works with any ceremony type.

If you choose **Custom** in the posture step, the wizard prompts you for each knob directly:

- Enrollment at creation: `open` or `closed` (sets `enrollment_open`)
- Join approval: `required` or `not required` (sets `requires_approval`)
- Unlock method: `auto`, `token`, or `passphrase`

After creation, the ceremony displays the TOTP enrollment auth setup: a QR code and manual key. Scan it with your authenticator app and enter a code to verify. If verification fails twice, you can regenerate the secret.

For non-interactive use (automation), provide flags:

```
koi certmesh create --profile just-me --enrollment open --require-approval false --passphrase "my-secret"
```

The CLI accepts these `create` flags (the JSON/non-interactive path requires `--profile` and `--passphrase`):

- `--profile <just-me|team|organization>` - select a preset and skip the posture step. **Custom is wizard-only** - there is no `--profile custom`; set the booleans directly with `--enrollment` / `--require-approval` instead.
- `--operator <name>` - operator label (required when the resulting `requires_approval` is true).
- `--enrollment <open|closed>` - override the preset's `enrollment_open`.
- `--require-approval <true|false>` - override the preset's `requires_approval`.
- `--passphrase <value>` - supply the CA passphrase and skip the passphrase step.

---

## Inviting a host

The recommended way to add a member is for the operator to mint a single-use **invite** on the CA host, then hand it to the joining machine out of band:

```
koi certmesh invite node-02 --ttl 60
```

```
Invite minted for node-02 (single-use, expires 2026-02-11T11:05:00Z):

  9f3a…d7c1.a1b2c3d4…

On node-02, run:
  koi certmesh join <ca-endpoint> --invite 9f3a…d7c1.a1b2c3d4…
```

An invite is a code of the form `<secret>.<ca_fingerprint>`. It is **bound to the named hostname**, single-use, and time-limited (`--ttl` minutes, default 60). The trailing `<ca_fingerprint>` half is what makes invite-based joins safer than a bare TOTP code: the joining host pins that fingerprint and refuses to enroll against a CA that advertises a different one (see "Joining the mesh"). Minting an invite is an operator action - the endpoint is DAT-gated, so it runs against the local daemon (or an explicit `--endpoint` with its `--token`).

## Joining the mesh

From a second machine, joining is a single command. The preferred form passes the CA endpoint **positionally** and supplies the invite from the step above - fully non-interactive:

```
koi certmesh join http://node-01:5641 --invite 9f3a…d7c1.a1b2c3d4…
```

Without an invite, Koi falls back to a TOTP join: with no endpoint it browses the LAN for a `_certmesh._tcp` CA via mDNS (see "Finding the CA"); if it can't find exactly one, it asks you to pass the endpoint directly, then prompts for the mesh TOTP code:

```
koi certmesh join
```

```
Searching for certmesh CA on the local network...
Found CA: node-01 Certmesh CA at http://192.168.1.10:5641
Enter the TOTP code from your authenticator app:
123456
Enrolled as: node-02
Key + certificate stored locally: /var/lib/koi/certs/node-02
```

The positional `<ca-endpoint>` (or the mDNS-discovered address) is always the **remote CA**. The joining host's own running daemon - resolved locally via the breadcrumb - keeps custody of the new member's private key: it generates the keypair and CSR, the CA signs only the CSR (it never sees or returns a private key), and the local daemon installs the signed certificate next to the key. The CA's global `--endpoint`/`--token` are *not* how you point `join` at the CA; the positional argument is.

The flow is intentionally simple because the hard part - proving you're authorized - is handled by the credential: an invite (fingerprint-pinned, non-interactive) or a TOTP code. The CA verifies the credential, signs the CSR, and enrolls the new member in the roster. No out-of-band private-key exchange, no manual approval queues (unless the mesh has `requires_approval` set, as the My Organization preset does).

When the invite carries a CA fingerprint, the joining host **preflights** the CA's self-reported fingerprint and aborts on a mismatch *before* transmitting its CSR - so a LAN man-in-the-middle of plain-HTTP discovery is rejected up front. The install step then hard-fails if the returned certificate doesn't match the pinned fingerprint. The bare-TOTP path has no out-of-band fingerprint to pin and stays trust-on-first-use.

If multiple CAs are found on the network, or the machines aren't on the same broadcast domain, specify the endpoint positionally as shown above.

---

## Unlocking the CA

The CA private key is encrypted at rest - always. When the daemon starts (or restarts), it loads the roster but the CA is **locked**. It can serve status queries, but it can't issue certificates or process enrollments until you unlock it:

```
koi certmesh unlock
```

Koi supports multiple unlock methods via **envelope encryption**. Each method is stored as a slot in `unlock-slots.json`. The unlock ceremony detects which methods are available and prompts accordingly:

- **Passphrase** - always available (the original CA passphrase)
- **Auto-unlock** - if enabled during creation, the CA unlocks automatically on daemon start. No manual intervention needed. Best for single-user homelabs (the **Just Me** and **My Team** presets enable this by default)
- **TOTP** - enter a 6-digit code from your authenticator app (if a TOTP unlock slot was registered during creation)

If only one method is available, it's used directly. If multiple unlock slots exist, the ceremony prompts you to choose.

This is a deliberate security boundary. A machine reboot shouldn't automatically grant certificate-issuing power - unless you've explicitly enabled auto-unlock (the **Just Me** / **My Team** presets do). While locked, enrollment requests receive a `503 CA locked` response, which is a clear, non-ambiguous signal to waiting clients.

---

## Monitoring the mesh

```
koi certmesh status
```

```
Certificate mesh: active
  CA locked:  false
  Enrollment: open (no approval)
  Members:    1
    node-01 (primary) - active
```

This is your at-a-glance view: whether the CA is locked, whether enrollment is open or closed (and whether joins need approval), and who's in the mesh. The posture line reflects the two stored booleans (`enrollment_open` + `requires_approval`) - there is no "profile" field to display, because none is persisted. JSON output (`--json`) is available for monitoring integrations.

### Audit log

Every significant action - creation, enrollment, renewal, revocation - is appended to an immutable audit log:

```
koi certmesh log
```

```
2026-02-11T10:00:00Z ca_initialized enrollment_open=open requires_approval=no operator=none
2026-02-11T10:05:00Z member_joined hostname=node-02 fingerprint=b2c3d4e5... role=member
```

This is your paper trail. When something goes wrong three months from now, the log tells you what happened and when.

---

## Certificate renewal and hooks

Koi renews certificates automatically before they expire. Leaf certificates live for **90 days**; a member renews when fewer than **30 days** remain, and a CA-held policy allows a **14-day** post-expiry grace window before a member must re-enroll. Renewal is **member-pull**: each enrolled host's daemon runs a background loop that rotates its key and pulls a fresh leaf from the CA over mTLS (port 5642) before expiry - the member, not the CA, drives the rotation. The CA's *own* leaf renews when the daemon restarts.

But your applications need to know when a cert changes - a web server can't use a new certificate without reloading. That's what hooks are for:

```
koi certmesh set-hook --reload "systemctl restart nginx"
```

The hook is stored in the roster and runs after each successful certificate renewal. This closes the loop: Koi rotates the cert, writes it to disk, and kicks your application to pick it up. No cron jobs, no manual rotation.

---

## Network architecture

The daemon listens on two ports with different security postures:

| Port | Default | Bind address | Auth | Purpose |
|------|---------|-------------|------|---------|
| **5641** | `--port` | `127.0.0.1` (loopback) | DAT header (`x-koi-token`, enforced on all non-GET requests except `/v1/certmesh/join`) | Local CLI, dashboard, management API |
| **5642** | `--mtls-port` | `0.0.0.0` (all interfaces) | mTLS client certificate | Inter-node communication (promote, health heartbeat, set-hook, renew) |
| **5643** | `--acme-port` | `0.0.0.0` (all interfaces) | JWS (server-auth TLS) | [ACME (RFC 8555) facade](acme.md) — standard ACME clients get certs from the CA |

The mTLS port only starts when the CA is initialized and the daemon has self-enrolled. Client certificates must be signed by the certmesh CA. The authenticated Common Name (CN) from the client certificate is used for per-caller authorization — a member can only set hooks for its own hostname, report its own health, and receive its own renewals.

If certmesh is disabled (`--no-certmesh`), the mTLS port is not opened. The ACME port (5643) starts on the same self-enrollment, gated by `--no-acme` / `KOI_NO_ACME`; it lets any standard ACME client (Caddy, Traefik, lego) obtain certs from the CA without Koi-specific config — see the [ACME guide](acme.md).

---

## HTTP API

All certmesh endpoints are mounted at `/v1/certmesh/` on the daemon.

### Core endpoints

| Method | Path                            | Purpose                               |
| ------ | ------------------------------- | ------------------------------------- |
| `POST` | `/v1/certmesh/create`           | Initialize a new CA                   |
| `POST` | `/v1/certmesh/invite`           | Mint a single-use, hostname-bound invite |
| `POST` | `/v1/certmesh/join`             | Enroll in an existing mesh            |
| `GET`  | `/v1/certmesh/status`           | Mesh status, members, CA state        |
| `POST` | `/v1/certmesh/unlock`           | Decrypt the CA key                    |
| `PUT`  | `/v1/certmesh/set-hook`         | Configure renewal hook                |
| `POST` | `/v1/certmesh/promote`          | Promote a member to standby CA        |
| `POST` | `/v1/certmesh/renew`            | Force certificate renewal             |
| `POST` | `/v1/certmesh/health`           | Mesh health check                     |
| `POST` | `/v1/certmesh/rotate-auth`      | Rotate the enrollment auth credential |
| `GET`  | `/v1/certmesh/log`              | Audit log (requires the daemon token) |
| `POST` | `/v1/certmesh/open-enrollment`  | Re-open enrollment                    |
| `POST` | `/v1/certmesh/close-enrollment` | Close enrollment                      |
| `POST` | `/v1/certmesh/backup`           | Create an encrypted backup bundle     |
| `POST` | `/v1/certmesh/restore`          | Restore from a backup bundle          |
| `POST` | `/v1/certmesh/revoke`           | Revoke a member's certificate         |
| `POST` | `/v1/certmesh/destroy`          | Destroy the CA and all state          |

### Join example

The joining host generates its own key + CSR locally and sends only the CSR to the CA, alongside a credential - an `invite_token` (the secret half of an invite code) or an `auth` block (TOTP). This is the one mutation exempt from the `x-koi-token` header, since a joining node can't know the CA host's local token.

```
POST /v1/certmesh/join
Content-Type: application/json

{"hostname": "node-02", "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...", "invite_token": "9f3a…d7c1"}
```

The CA signs the CSR and returns the certificate chain - never a private key (the key stays on the joining host):

```json
{
  "hostname": "node-02",
  "ca_cert": "-----BEGIN CERTIFICATE-----\n...",
  "service_cert": "-----BEGIN CERTIFICATE-----\n...",
  "ca_fingerprint": "a1b2c3d4...",
  "policy": { "leaf_lifetime_days": 90, "renew_threshold_days": 30, "grace_days": 14 }
}
```

### Error responses

| Error code           | HTTP status | Meaning                                              |
| -------------------- | ----------- | ---------------------------------------------------- |
| `ca_not_initialized` | 503         | No CA has been created yet                           |
| `ca_locked`          | 503         | CA key hasn't been decrypted                         |
| `invalid_auth`       | 401         | Wrong auth credential (TOTP code)                    |
| `rate_limited`       | 429         | Too many failed auth attempts                        |
| `enrollment_closed`  | 403         | Enrollment is closed                                 |
| `conflict`           | 409         | Hostname already enrolled                            |

---

## Certificate details

Understanding what certmesh produces helps when debugging TLS issues:

- **Algorithm**: ECDSA P-256 (fast, widely supported, small keys)
- **CA validity**: 10 years
- **Leaf cert lifetime**: 90 days (auto-renewed at 30 days remaining, 14-day grace - the CA-held `CertPolicy`)
- **CA self-enrollment SANs**: hostname, localhost, 127.0.0.1, ::1
- **Member cert SANs**: hostname, hostname.local
- **Trust store**: CA cert is installed in the system trust store at creation time

### File layout

Certificates are written to the Koi data directory:

| Platform | Base path                           |
| -------- | ----------------------------------- |
| Windows  | `%ProgramData%\koi\`                |
| macOS    | `/Library/Application Support/koi/` |
| Linux    | `/var/lib/koi/`                     |

Per-member certificate files:

```
certs/<hostname>/
  cert.pem        # service certificate
  key.pem         # service private key
  ca.pem          # CA certificate
  fullchain.pem   # cert + CA chain
```

CA state (on the primary):

```
certmesh/ca/
  ca-key.enc          # master-key-encrypted CA private key
  ca-cert.pem         # CA certificate (public)
  unlock-slots.json   # unlock slot table (passphrase, auto-unlock, TOTP)
  auth.json           # enrollment auth credential (encrypted TOTP secret)
certmesh/roster.json  # mesh membership roster
```

The `unlock-slots.json` file holds the envelope encryption slots. Each slot wraps the same master key using a different method (passphrase, auto-unlock, or TOTP). Legacy deployments without `unlock-slots.json` are auto-migrated on first load.

The `fullchain.pem` is what most applications want - it includes both the service certificate and the CA certificate, which is what `nginx`, `traefik`, and `curl --cacert` expect.

---

## Finding the CA

`koi certmesh join` and `koi certmesh promote` both take an optional **positional** CA endpoint. When you omit it, they browse the LAN for `_certmesh._tcp` over mDNS for a few seconds and use the single CA they find:

```
koi certmesh join                       # browse for the CA
koi certmesh join http://node-01:5641  # or point at it directly
```

When you join with an invite, the CA's advertised `fp=` TXT record is cross-checked against the invite's pinned fingerprint, so a discovered CA from the wrong mesh is dropped before it can be used (the authoritative pin check is still the preflight in "Joining the mesh").

The CA does **not** run a background self-announce / absence-watch loop - that machinery was removed along with automatic failover. The daemon's own management endpoint is still recorded locally in the breadcrumb file (`koi.endpoint`), which is how local CLI commands reach the running daemon. For cross-machine `join`/`promote`, passing the positional endpoint explicitly is the most reliable path; the mDNS browse is a convenience that depends on the CA being reachable and advertised on the same broadcast domain.

---

## Revoking a member

If a machine is compromised, decommissioned, or simply no longer trusted, revoke its certificate:

```
koi certmesh revoke node-02 --reason "decommissioned"
```

This marks the member as revoked in the roster and records the event in the audit log. The revoked host's certificate remains on disk and will no longer be renewed - so it stops working once it expires (within the 90-day leaf lifetime). Revocation also takes effect immediately at the CA boundary: a revoked member's `/renew` and `/health` calls over mTLS are rejected with `403`, so it can neither pull a fresh leaf nor report healthy. Revocation is otherwise **roster state**, not a network-wide CRL or OCSP push: there is no revocation list distributed to other members, and an already-issued, still-valid leaf keeps working against third parties until it expires. The leaf lifetime is the bound on that residual access (see "What certmesh deliberately does not do").

---

## High availability and promotion

Certmesh has one continuity primitive: **manual promotion**. You promote a member to a standby CA, which transfers an encrypted copy of the CA signing key so that node can issue certificates if the original CA goes away:

```
koi certmesh promote http://node-01:5641
```

As with `join`, the positional `<ca-endpoint>` (or mDNS) is the **remote CA** being promoted from, while the standby's own running daemon is resolved locally via the breadcrumb. The CA signing key is transferred encrypted via Diffie-Hellman - the passphrase never goes on the wire.

Promotion is a **deliberate operator action**, not an automatic election. There is no absence-watch loop, no lexicographic tiebreaker, and no background roster sync - that machinery was removed. Promotion only happens when you run the command.

Manual is fine here because of how certmesh degrades. Member certificates live for 90 days and are renewed well before expiry. If the CA goes offline, **renewals pause - they do not fail closed**. Existing certificates keep working until they near expiry, which gives you weeks of runway to either bring the original CA back or promote a standby on your own schedule. A dead CA is a maintenance task, not an outage, so the complexity and failure modes of automatic failover are not justified.

---

## Backup and restore

The CA state - private key, certificates, roster, auth credential, and audit log - should be backed up. Certmesh creates encrypted backup bundles:

```
koi certmesh backup ./mesh-backup.tar.enc
```

To restore on a new machine (or after data loss):

```
koi certmesh restore ./mesh-backup.tar.enc
```

`backup` prompts for the **CA passphrase** (to read the current state) and a **separate
backup passphrase** (to encrypt the bundle); `restore` prompts for that backup passphrase
and a new CA passphrase to re-protect the restored key. Keep the backup passphrase with
the bundle — it is what decrypts it, independent of the CA passphrase. See the
[HA & recovery runbook](certmesh-ha-recovery.md) for the full backup/restore + standby-promote procedure.

---

## Destroying the mesh

To permanently delete all certmesh state - CA keys, certificates, enrollments, and audit logs:

```
koi certmesh destroy
```

This is a destructive, irreversible operation. In interactive mode, you must type `DESTROY` to confirm. If this node is the root CA, all mesh members will lose their ability to renew certificates.

In `--json` mode (scripting), the confirmation is skipped:

```
koi certmesh destroy --json
```

```json
{ "destroyed": true }
```

---

## What certmesh deliberately does not do

Certmesh is intentionally small. Knowing what it does *not* do is as important as knowing what it does:

- **No network-wide revocation (CRL/OCSP).** Revocation takes effect at the CA boundary (a revoked member's `/renew` and `/health` get `403`) and in roster state, but already-issued, still-valid certificates are **not** actively revoked across the network - peers do not consult a distributed revocation list. The 90-day leaf lifetime is the bound on a revoked member's residual access to third parties.
- **No automatic failover.** Continuity is the manual `koi certmesh promote`. There is no absence-watch, no automatic election, and no tiebreaker. A dead CA pauses renewals (weeks of runway), it does not cause an outage.
- **No enterprise compliance or audit-export endpoint.** There is no compliance summary and no policy/scope engine. The audit trail is the append-only log (`koi certmesh log`) and the live view is `koi certmesh status` - use those.
- **No FIDO2 / hardware-key auth.** Enrollment and unlock use TOTP and passphrase only. The extension point is the `AuthAdapter` trait in `koi-crypto` (`adapter_by_name`): a future hardware-key method would re-enter through there rather than as special-cased code.

---

## Embedding certmesh in a Rust app

To run certmesh as a library — in-process, no daemon, the full `CertmeshCore` plus the network adapters you compose for your role (a mesh member or the CA host) — see [Embedding certmesh](certmesh-embedded.md).
