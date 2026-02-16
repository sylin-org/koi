# Certmesh - Certificate Mesh

TLS is the foundation of trust on the internet. But on a local network, getting TLS right is surprisingly hard. Let's Encrypt doesn't issue certificates for `.local` names or private IPs. Self-signed certs trigger browser warnings and break API clients. Manually copying PEM files between machines is fragile and doesn't scale past two hosts. Corporate PKI requires infrastructure most teams don't have.

Koi's certmesh solves this by running a private Certificate Authority directly on your LAN. Two machines can establish mutual TLS trust in under a minute, with no external infrastructure, no manual certificate copying, and no self-signed warnings. The CA handles enrollment, issuance, renewal, and revocation automatically.

**When to use certmesh**: You have multiple machines on a LAN that need to communicate over TLS. A homelab where services should trust each other. A development team that needs HTTPS without public DNS. A staging environment that mirrors production's TLS requirements. If you need real certificates but don't have (or want) a public CA, certmesh is the answer.

All CLI commands use the `koi certmesh` prefix. All HTTP endpoints live under `/v1/certmesh/`. Certmesh commands require a running daemon - use `koi install` or `koi --daemon` first.

---

## Creating a certificate mesh

The first step is initializing a CA on the machine that will be the primary authority. This is a deliberate act - you're creating a root of trust for your network:

```
koi certmesh create
```

This launches an interactive **ceremony** - a server-driven wizard where all branching, validation, and content decisions happen in the domain logic, not the CLI. The terminal is a "dumb render loop" that displays prompts, collects input, and sends it back. This means identical creation logic whether you use the CLI or the HTTP API.

The ceremony walks through these steps:

1. **Choose a trust profile** - who is this mesh for? (Just Me, My Team, My Organization, or Custom)
2. **Operator name** - prompted when the profile requires approval (team, organization, custom)
3. **Entropy collection** - the server generates 32 bytes of entropy; you contribute more by mashing keys on the keyboard. Both are combined via SHA-256 to seed passphrase generation
4. **Set the CA passphrase** - three options:
   - **Keep the suggestion** (default) - an EFF-wordlist passphrase is generated from the combined entropy
   - **Generate another** - re-derives a new passphrase from fresh entropy
   - **Type my own** - enter and confirm a passphrase of your choice (minimum 8 characters)
5. **Unlock method** (custom profile only) - choose how the CA can be unlocked on boot:
   - `auto` - CA unlocks automatically on daemon start (single-user homelabs)
   - `token` - requires a TOTP code or FIDO2 tap to unlock
   - `passphrase` - requires the CA passphrase to unlock (default for team/org)
6. **Enrollment auth setup** - TOTP by default. Shows a QR code for your authenticator app. You must enter a valid code to verify your setup. After two failed attempts, you can regenerate the secret. FIDO2 support (USB security keys) is also available.
7. **Unlock token registration** (if unlock method = `token`) - registers a separate TOTP secret or FIDO2 key for CA unlock (distinct from enrollment auth)

After the ceremony completes, Koi:

1. Generates an ECDSA P-256 CA keypair
2. Encrypts the private key using **envelope encryption**: a random 256-bit master key encrypts the CA key, and the master key is wrapped by each unlock slot (passphrase, auto-unlock, TOTP, and/or FIDO2)
3. Creates a roster with this host as the primary member
4. Issues a certificate for the local hostname (self-enrollment)
5. Starts certmesh audit logging
6. Installs the CA certificate in the system trust store

The ceremony design means every step can be replayed or revised before finalization. Press **ESC** at any time to cancel without making changes.

TOTP supports any authenticator app (Google Authenticator, Authy, 1Password, etc.). FIDO2 supports USB security keys (YubiKey, SoloKey, Nitrokey, etc.). You'll need the chosen auth method to enroll new members.

### Choosing a trust profile

The profile determines how much ceremony is required to join the mesh. Pick the one that matches your threat model:

| Profile             | Flag value     | Enrollment default | Operator required | Best for                                                |
| ------------------- | -------------- | ------------------ | ----------------- | ------------------------------------------------------- |
| **Just Me**         | `just-me`      | Open               | No                | Personal homelab - you control all machines             |
| **My Team**         | `team`         | Open               | Yes               | Small office or lab - trust but verify                  |
| **My Organization** | `organization` | Closed             | Yes               | Strict environments - explicit approval for each member |

```
koi certmesh create --profile just-me
koi certmesh create --profile team --operator "Alice"
koi certmesh create --profile organization --operator "Security Team"
```

The operator field is a human-readable label for audit trails. In the "just-me" profile, you are the operator by default.

### Interactive wizard + flags

By default, `koi certmesh create` runs the interactive ceremony described above. The ceremony engine handles all branching and validation - the CLI is a generic render loop that works with any ceremony type.

If you choose **Custom** in the profile step, you can explicitly set:

- Enrollment at creation: `open` or `closed`
- Join approval: `required` or `not required`
- Unlock method: `auto`, `token`, or `passphrase`

Standard profiles (Just Me, My Team, My Organization) use sensible defaults:

- **Just Me**: open enrollment, no approval, auto-unlock
- **My Team**: open enrollment, approval required, passphrase unlock
- **My Organization**: closed enrollment, approval required, passphrase unlock

After creation, the ceremony displays authentication setup for enrollment. For TOTP (default), this is a QR code and manual key - scan it with your authenticator app and enter a code to verify. For FIDO2, you'll register your hardware security key. If TOTP verification fails twice, you can regenerate the secret.

For non-interactive use (automation), provide flags:

```
koi certmesh create --profile just-me --enrollment open --require-approval false --passphrase "my-secret"
```

`--profile` skips the profile step. `--enrollment` and `--require-approval` override policy defaults. `--passphrase` skips the passphrase step. With `--json`, all required fields must be provided.

---

## Joining the mesh

From a second machine, joining is a single command. Koi discovers the CA automatically via mDNS - the same discovery protocol the rest of Koi uses:

```
koi certmesh join
```

```
Searching for certmesh CA on the local network...
Found CA: stone-01 Certmesh CA at http://192.168.1.10:5641
Authenticate to join (TOTP code or tap security key):
123456
Enrolled as: stone-02
Certificates written to: /var/lib/koi/certs/stone-02
```

The flow is intentionally simple because the hard part - proving you're authorized - is handled by the enrollment auth (TOTP code or FIDO2 key tap). The CA verifies the credential, issues a certificate, and enrolls the new member in the roster. No certificate signing requests, no out-of-band key exchange, no manual approval queues (unless you chose the organization profile).

If multiple CAs are found on the network, or the machines aren't on the same broadcast domain, specify the endpoint directly:

```
koi certmesh join http://stone-01:5641
```

---

## Unlocking the CA

The CA private key is encrypted at rest - always. When the daemon starts (or restarts), it loads the roster but the CA is **locked**. It can serve status queries, but it can't issue certificates or process enrollments until you unlock it:

```
koi certmesh unlock
```

Koi supports multiple unlock methods via **envelope encryption**. Each method is stored as a slot in `unlock-slots.json`. The unlock ceremony detects which methods are available and prompts accordingly:

- **Passphrase** - always available (the original CA passphrase)
- **Auto-unlock** - if enabled during creation, the CA unlocks automatically on daemon start. No manual intervention needed. Best for single-user homelabs (the "Just Me" profile enables this by default)
- **TOTP** - enter a 6-digit code from your authenticator app (if a TOTP unlock slot was registered during creation)
- **FIDO2** - tap your hardware security key (if a FIDO2 unlock slot was registered)

If only one method is available, it's used directly. If multiple unlock slots exist, the ceremony prompts you to choose.

This is a deliberate security boundary. A machine reboot shouldn't automatically grant certificate-issuing power - unless you've explicitly configured auto-unlock for a single-user profile. While locked, enrollment requests receive a `503 CA locked` response, which is a clear, non-ambiguous signal to waiting clients.

---

## Monitoring the mesh

```
koi certmesh status
```

```
Certificate Mesh Status
  Profile:    Just Me
  Enrollment: Open
  Members:    1 active

  stone-01 (primary, active)
    Fingerprint: a1b2c3d4...
    Expires:     2026-03-13
    Cert path:   %ProgramData%\koi\certs\stone-01
```

This is your at-a-glance view: who's in the mesh, whether enrollment is open or closed, and when certificates expire. JSON output (`--json`) is available for monitoring integrations.

### Audit log

Every significant action - creation, enrollment, renewal, revocation - is appended to an immutable audit log:

```
koi certmesh log
```

```
2026-02-11T10:00:00Z pond_initialized profile=just_me operator=self hostname=stone-01
2026-02-11T10:05:00Z member_joined hostname=stone-02 fingerprint=b2c3d4e5... role=member
```

This is your paper trail. When something goes wrong three months from now, the log tells you what happened and when.

---

## Certificate renewal and hooks

Koi renews certificates automatically before they expire. But your applications need to know about it - a web server can't use a new certificate without reloading. That's what hooks are for:

```
koi certmesh set-hook --reload "systemctl restart nginx"
```

The hook is stored in the roster and runs after each successful certificate renewal. This closes the loop: Koi issues the cert, writes it to disk, and kicks your application to pick it up. No cron jobs, no manual rotation.

---

## HTTP API

All certmesh endpoints are mounted at `/v1/certmesh/` on the daemon.

### Core endpoints

| Method | Path                            | Purpose                               |
| ------ | ------------------------------- | ------------------------------------- |
| `POST` | `/v1/certmesh/create`           | Initialize a new CA                   |
| `POST` | `/v1/certmesh/join`             | Enroll in an existing mesh            |
| `GET`  | `/v1/certmesh/status`           | Mesh status, members, CA state        |
| `POST` | `/v1/certmesh/unlock`           | Decrypt the CA key                    |
| `PUT`  | `/v1/certmesh/set-hook`         | Configure renewal hook                |
| `POST` | `/v1/certmesh/promote`          | Promote a member to primary           |
| `POST` | `/v1/certmesh/renew`            | Force certificate renewal             |
| `GET`  | `/v1/certmesh/roster`           | Full membership roster                |
| `POST` | `/v1/certmesh/health`           | Mesh health check                     |
| `POST` | `/v1/certmesh/rotate-auth`      | Rotate the enrollment auth credential |
| `GET`  | `/v1/certmesh/log`              | Audit log                             |
| `POST` | `/v1/certmesh/open-enrollment`  | Re-open enrollment                    |
| `POST` | `/v1/certmesh/close-enrollment` | Close enrollment                      |
| `PUT`  | `/v1/certmesh/set-policy`       | Update trust policy                   |
| `POST` | `/v1/certmesh/backup`           | Create an encrypted backup bundle     |
| `POST` | `/v1/certmesh/restore`          | Restore from a backup bundle          |
| `POST` | `/v1/certmesh/revoke`           | Revoke a member's certificate         |
| `GET`  | `/v1/certmesh/compliance`       | Compliance summary                    |
| `POST` | `/v1/certmesh/destroy`          | Destroy the CA and all state          |

### Join example

```
POST /v1/certmesh/join
Content-Type: application/json

{"hostname": "stone-02", "auth": {"method": "totp", "code": "123456"}}
```

Response:

```json
{
  "hostname": "stone-02",
  "ca_cert": "-----BEGIN CERTIFICATE-----\n...",
  "service_cert": "-----BEGIN CERTIFICATE-----\n...",
  "service_key": "-----BEGIN PRIVATE KEY-----\n...",
  "ca_fingerprint": "a1b2c3d4...",
  "cert_path": "/var/lib/koi/certs/stone-02"
}
```

### Error responses

| Error code           | HTTP status | Meaning                                              |
| -------------------- | ----------- | ---------------------------------------------------- |
| `ca_not_initialized` | 503         | No CA has been created yet                           |
| `ca_locked`          | 503         | CA key hasn't been decrypted                         |
| `invalid_auth`       | 401         | Wrong auth credential (TOTP code or FIDO2 signature) |
| `rate_limited`       | 429         | Too many failed auth attempts                        |
| `enrollment_closed`  | 403         | Enrollment is closed                                 |
| `conflict`           | 409         | Hostname already enrolled                            |

---

## Certificate details

Understanding what certmesh produces helps when debugging TLS issues:

- **Algorithm**: ECDSA P-256 (fast, widely supported, small keys)
- **CA validity**: 10 years
- **Service cert lifetime**: 30 days (auto-renewed)
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
  unlock-slots.json   # unlock slot table (passphrase, auto-unlock, TOTP, FIDO2)
  auth.json           # enrollment auth credential (encrypted TOTP secret or FIDO2 public key)
certmesh/roster.json  # mesh membership roster
```

The `unlock-slots.json` file holds the envelope encryption slots. Each slot wraps the same master key using a different method (passphrase, TOTP, FIDO2, or auto-unlock). Legacy deployments without `unlock-slots.json` are auto-migrated on first load.

The `fullchain.pem` is what most applications want - it includes both the service certificate and the CA certificate, which is what `nginx`, `traefik`, and `curl --cacert` expect.

---

## mDNS self-announcement

When the daemon starts with both mDNS and certmesh enabled, Koi automatically announces the CA via mDNS as `_certmesh._tcp`. This is how `koi certmesh join` discovers the CA automatically - it's mDNS all the way down.

The announcement includes TXT records:

- `role=primary`
- `fingerprint=<CA fingerprint>`
- `profile=<trust profile>`

This means you can also discover certmesh CAs with `koi mdns discover certmesh` - a nice way to check what's advertising before you join.

---

## Revoking a member

If a machine is compromised, decommissioned, or simply no longer trusted, revoke its certificate:

```
koi certmesh revoke stone-02 --reason "decommissioned"
```

This marks the member as revoked in the roster and records the event in the audit log. The revoked host's certificate remains on disk but will no longer be renewed, and other members can check revocation status.

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

The backup is encrypted with the CA passphrase, so the same passphrase is required to restore.

---

## Compliance

For environments that need to demonstrate certificate management compliance:

```
koi certmesh compliance
```

This shows a summary of the mesh's security posture: key algorithm, cert lifetimes, enrollment policy, revocation state, and audit log integrity. Use `--json` for integration with compliance tooling.

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
