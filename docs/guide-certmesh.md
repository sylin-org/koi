# Certmesh — Certificate Mesh Guide

Koi's certmesh capability provides a private Certificate Authority (CA) with TOTP-based enrollment. Two machines on the same LAN can establish mutual TLS trust without external infrastructure — no Let's Encrypt, no self-signed cert warnings, no manual copying of PEM files.

All CLI commands use the `koi certmesh` moniker. All HTTP endpoints live under `/v1/certmesh/`.

Certmesh commands require a running daemon. Use `koi install` or run `koi --daemon` first.

---

## Creating a certificate mesh

Initialize a new CA on the machine that will be the primary:

```
koi certmesh create --profile just-me --entropy manual --passphrase "my-secret"
```

```
Certificate mesh created!
  Profile:      Just Me
  CA fingerprint: a1b2c3d4e5f6...
  Primary host: stone-01
  Certificates: %ProgramData%\koi\certs\stone-01

Scan this QR code with your authenticator app:
█████████████████████████████
█ ▄▄▄▄▄ █ ▄ ▄ ██▀██ ▄▄▄▄▄ █
...
```

This does several things:
1. Generates an ECDSA P-256 CA keypair
2. Encrypts the private key with your passphrase
3. Issues the first service certificate for this host
4. Creates a roster with this host as the primary member
5. Generates a TOTP secret and shows a QR code for your authenticator app
6. Installs the CA certificate in the system trust store

### Trust profiles

Choose a profile that matches your environment:

| Profile | Flag value | Enrollment default | Operator required | Use case |
|---|---|---|---|---|
| **Just Me** | `just-me` | Open | No | Personal homelab |
| **My Team** | `team` | Open | Yes | Small office or lab |
| **My Organization** | `organization` | Closed | Yes | Institution with strict controls |

```
koi certmesh create --profile just-me
koi certmesh create --profile team --operator "Alice"
koi certmesh create --profile organization --operator "Security Team"
```

### Entropy modes

The CA keypair needs entropy. Three modes:

| Mode | Flag | Description |
|---|---|---|
| Auto passphrase | `--entropy passphrase` (default) | Generates a random passphrase, prompts for CA passphrase |
| Keyboard | `--entropy keyboard` | Interactive key-mashing for entropy |
| Manual | `--entropy manual --passphrase "..."` | You provide the passphrase directly |

For scripting, use `--entropy manual --passphrase "..."`.

---

## Checking status

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

JSON output:

```
koi certmesh status --json
```

```json
{
  "ca_initialized": true,
  "profile": "just_me",
  "enrollment_state": "open",
  "member_count": 1,
  "members": [
    {
      "hostname": "stone-01",
      "role": "primary",
      "status": "active",
      "cert_fingerprint": "a1b2c3d4...",
      "cert_expires": "2026-03-13T00:00:00Z"
    }
  ]
}
```

---

## Joining a mesh

From a second machine, join the mesh. Koi discovers the CA automatically via mDNS:

```
koi certmesh join
```

```
Searching for certmesh CA on the local network...
Found CA: stone-01 Certmesh CA at http://192.168.1.10:5641
Enter the TOTP code from your authenticator app:
123456
Enrolled as: stone-02
Certificates written to: /var/lib/koi/certs/stone-02
```

If multiple CAs are found, or if the machines aren't on the same broadcast domain, specify the endpoint directly:

```
koi certmesh join http://stone-01:5641
```

The TOTP code comes from the authenticator app you set up when creating the mesh. The primary CA verifies the code, issues a certificate, and enrolls the new member in the roster.

---

## Unlocking the CA

The CA private key is encrypted at rest. When the daemon starts, it loads the roster but the CA is **locked** — it can't issue certificates or process enrollments until unlocked.

```
koi certmesh unlock
```

```
Enter the CA passphrase:
CA unlocked successfully.
```

While locked, the daemon still serves status queries but enrollment requests return `503 CA locked`.

---

## Audit log

Every significant action is appended to an audit log:

```
koi certmesh log
```

```
2026-02-11T10:00:00Z pond_initialized profile=just_me operator=self hostname=stone-01
2026-02-11T10:05:00Z member_joined hostname=stone-02 fingerprint=b2c3d4e5... role=member
```

---

## Setting a reload hook

Koi periodically renews certificates and pushes updated material to members. Each member can configure a shell command to run after receiving a new certificate — for example, to restart a web server:

```
koi certmesh set-hook --reload "systemctl restart nginx"
```

The hook is stored in the roster and will be executed after each successful certificate renewal. This command requires a running daemon.

JSON output:

```
koi certmesh set-hook --reload "systemctl restart nginx" --json
```

```json
{"hostname": "stone-01", "reload": "systemctl restart nginx"}
```

---

## HTTP API

All certmesh endpoints are mounted at `/v1/certmesh/` on the daemon.

### Endpoint summary

- `POST /v1/certmesh/create`
- `POST /v1/certmesh/join`
- `GET /v1/certmesh/status`
- `POST /v1/certmesh/unlock`
- `PUT /v1/certmesh/hook`
- `POST /v1/certmesh/promote`
- `POST /v1/certmesh/renew`
- `GET /v1/certmesh/roster`
- `POST /v1/certmesh/health`
- `POST /v1/certmesh/rotate-totp`
- `GET /v1/certmesh/log`
- `POST /v1/certmesh/enrollment/open`
- `POST /v1/certmesh/enrollment/close`
- `PUT /v1/certmesh/policy`
- `POST /v1/certmesh/destroy`

### Join the mesh

```
POST /v1/certmesh/join
Content-Type: application/json

{"totp_code": "123456"}
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

### Status

```
GET /v1/certmesh/status
```

Returns mesh status including CA state, profile, enrollment state, and member list.

### Set reload hook

```
PUT /v1/certmesh/hook
Content-Type: application/json

{"hostname": "stone-01", "reload": "systemctl restart nginx"}
```

Response:

```json
{"hostname": "stone-01", "reload": "systemctl restart nginx"}
```

### Error responses

| Error code | HTTP status | When |
|---|---|---|
| `ca_not_initialized` | 503 | CA hasn't been created yet |
| `ca_locked` | 503 | CA key not decrypted |
| `invalid_totp` | 401 | Wrong TOTP code |
| `rate_limited` | 429 | Too many failed TOTP attempts |
| `enrollment_closed` | 403 | Enrollment is closed (organization profile) |
| `conflict` | 409 | Hostname already enrolled |

---

## Certificate details

- **Algorithm**: ECDSA P-256
- **CA validity**: 10 years
- **Service cert lifetime**: 30 days
- **SANs**: hostname, hostname.local
- **Trust store**: CA cert is installed in the system trust store at creation time

### File layout

Certificates are written to the Koi data directory:

| Platform | Base path |
|---|---|
| Windows | `%ProgramData%\koi\` |
| macOS | `/Library/Application Support/koi/` |
| Linux | `/var/lib/koi/` |

Per-member certificate files:

```
certs/<hostname>/
  cert.pem        # service certificate
  key.pem         # service private key
  ca.pem          # CA certificate
  fullchain.pem   # cert + CA chain
```

CA state:

```
certmesh/ca/
  ca-key.enc      # encrypted CA private key
  ca-cert.pem     # CA certificate (public)
  totp-secret.enc # encrypted TOTP secret
certmesh/roster.json  # mesh membership roster
```

---

## mDNS self-announcement

When the daemon starts with both mDNS and certmesh enabled, Koi automatically announces the CA via mDNS as `_certmesh._tcp`. This is what `koi certmesh join` uses to discover the CA when no endpoint is specified.

The announcement includes TXT records:
- `role=primary`
- `fingerprint=<CA fingerprint>`
- `profile=<trust profile>`
