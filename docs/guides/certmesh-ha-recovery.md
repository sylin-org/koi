# Certmesh HA & disaster recovery

Your certmesh CA host is one machine. When it dies — disk failure, a reinstall, a
laptop left at the office — the mesh does **not** go down with it. Member
certificates live for 30 days and renew well before expiry, so a dead CA *pauses*
renewals; it does not break TLS that already works. That buys you days, not minutes.
This is a runbook for using that runway: how to prepare before the failure, and the
ordered steps to recover after one.

There is **no automatic failover** in certmesh — no election, no absence-watch, no
self-healing. Every continuity action here is a deliberate command you run. That is
the design (see [certmesh.md](./certmesh.md), "High availability and promotion"), and
it is why preparation matters: the recovery is only as good as the standby you
promoted or the backup you took *before* the disaster.

All commands use the `koi certmesh` prefix and require a running daemon
(`koi install` or `koi --daemon`). Mutating HTTP calls need the daemon access token
in an `x-koi-token` header — see [the security model](../reference/security-model.md).

---

## Three continuity primitives

Certmesh gives you exactly three tools. This runbook walks all three:

| Primitive | Command | What it buys you |
| --- | --- | --- |
| **Standby** | `koi certmesh promote` | A second machine that already holds the CA key, ready to issue certs the moment you need it. |
| **Backup** | `koi certmesh backup <path>` | An encrypted bundle (CA key, cert, enrollment auth, roster, audit log) you can restore anywhere. |
| **Restore** | `koi certmesh restore <path>` | Rebuild the CA on a fresh machine from that bundle. |

A standby is *warm* continuity (already populated, promote-and-go). A backup is *cold*
continuity (a file on another disk). Run both — they cover different failures.

---

## Before disaster: what to back up, and how often

This is the part you do today, while everything works. Two preparations, in order of
importance.

### 1. Stand up a standby (warm)

On a second always-on machine that is already a mesh member (it ran
`koi certmesh join`), promote it. Point it at the current CA:

```
koi certmesh promote http://ca-host:5641
```

Omit the endpoint to discover the CA over mDNS instead:

```
koi certmesh promote
```

Promotion prompts for two secrets:

1. **The enrollment TOTP code** — proves you are authorized.
2. **A CA passphrase** — used to *re-encrypt* the CA key locally on the standby.

Under the hood the standby generates an ephemeral X25519 keypair and the CA key is
transferred over a Diffie-Hellman-agreed channel — **the passphrase you type is never
sent over the wire**. The standby decrypts the key, re-encrypts it at rest with the
passphrase you just entered, writes the CA cert, auth credential, and roster to its own
data directory, and flips its roster role to `Standby`. From that point it holds
everything needed to become the CA.

Confirm it took:

```
koi certmesh status
```

The standby should appear in the member list. (`koi certmesh promote` is idempotent in
practice — re-running it refreshes the standby's copy of the key and roster.)

> A standby is **warm, not automatic**. It does not detect the CA going away and it does
> not take over on its own. When the primary dies you still run the promote/recovery
> steps below. The standby's value is that the CA key is already on a second disk, so
> you skip the backup-restore round-trip.

### 2. Take an encrypted backup (cold)

Even with a standby, take backups — a standby protects against one host dying, a backup
protects against losing *both*, against operator error, and against a corrupted data
directory.

```
koi certmesh backup mesh.koi
```

You will be prompted for:

1. **The CA passphrase** — to read the CA key out of its envelope.
2. **A backup passphrase** (entered twice) — this encrypts the bundle. It is a
   **separate secret** from the CA passphrase; choose and store it deliberately.

The `.koi` bundle contains the CA keypair, the CA certificate, the enrollment auth
(TOTP) credential, the full roster, and the audit log. It does **not** contain the
per-member service certs/keys (those live at `certs/<hostname>/` on each member and are
re-issued by the CA, not from the bundle).

Date-stamp and store backups off the CA host:

```
koi certmesh backup /mnt/backup/mesh-$(date +%F).koi
```

**Verify the backup is restorable** — an untested backup is a hope, not a plan. On a
throwaway machine or a scratch data directory (`KOI_DATA_DIR=/tmp/koi-test`), run
`koi certmesh restore` against the bundle with the backup passphrase. If it restores and
`koi certmesh status` shows the expected members, the bundle is good. Do this at least
once after creating the mesh, and after any roster change you care about.

**How often:** take a fresh backup whenever the roster changes (a member joins, is
revoked, or you rotate the enrollment auth). For a stable mesh, a periodic backup
(weekly, or on a cron'd `koi certmesh backup /mnt/backup/mesh-$(date +%F).koi`) is
plenty — the CA key itself does not change, so old backups still restore a working CA;
they just carry an older roster.

**Where to keep secrets:** the CA passphrase and the backup passphrase are the keys to
the whole mesh. Store them in a password manager, not next to the `.koi` file. Anyone
with the bundle *and* its passphrase can stand up a CA that every member trusts.

---

## After disaster: the recovery checklist

The CA host is gone. Member certs still work (they have days left). Work through this in
order — stop as soon as the mesh is issuing certificates again.

### 0. Confirm it is actually down

From any member, check whether the CA is genuinely unreachable (not just locked after a
reboot):

```
koi certmesh status --endpoint http://ca-host:5641
```

If the CA answers but reports `CA locked: true`, you do **not** have a disaster — just
unlock it (`koi certmesh unlock`) and you are done. Only proceed if the host is truly
gone.

### 1. Pick a recovery path

- **You have a standby** → go to step 2A. Fastest path; the key is already there.
- **No standby, but you have a backup** → go to step 2B.
- **No standby and no backup** → there is no recovery. The CA key is unrecoverable; you
  must recreate the mesh from scratch (`koi certmesh create`) and have every member
  `koi certmesh join` again. This is the outcome the two preparations above exist to
  prevent.

### 2A. Promote the standby (if you have one)

The standby already holds the CA key — it just needs to start acting as the CA.

If you promoted the standby *before* the disaster (recommended), the CA key is already
on its disk. Make sure its daemon is running and the CA is unlocked:

```
koi certmesh unlock      # on the standby host
koi certmesh status
```

Once unlocked, that node can issue and renew certificates. If you had *not* promoted
ahead of time and the original CA is already gone, you cannot promote now (promotion
pulls the key *from* the live CA) — fall through to **2B** and restore from a backup
instead.

### 2B. Restore from backup onto a fresh CA host

On the new (or rebuilt) machine, with the daemon running:

```
koi certmesh restore mesh.koi
```

You will be prompted for:

1. **The backup passphrase** — to decrypt the bundle.
2. **A new CA passphrase** (entered twice) — restore re-encrypts the CA key at rest with
   this. It can be the same as the old one or a new one; it is what you will use to
   `koi certmesh unlock` from now on.

Restore writes the CA key, CA cert, enrollment auth, roster, and audit log into this
host's data directory and brings the CA online (unlocked) in place. **Restore overwrites
any certmesh state already on this node** — only run it on a machine you intend to be the
CA.

### 3. Verify the restored/promoted CA

```
koi certmesh status
```

Check:

- **CA locked: false** — the CA can issue. (If it shows locked, run `koi certmesh unlock`.)
- **Members** — the roster matches what you expect. The members from the backup/standby
  are present, with their roles.
- **Audit log** is intact:

  ```
  koi certmesh log
  ```

  You should see the historical entries plus a `backup_restored` (or `promoted_to_standby`)
  line marking this recovery.

### 4. Are members still valid? Do they need to re-enroll?

This is the question that decides how much work remains.

- **The CA key is the same** (a standby and a backup both carry the *original* CA key),
  so every member certificate already issued is **still trusted** — clients verifying
  against the CA root keep working with no change. Members do **not** need to re-enroll
  just because the CA host moved.
- **Renewals resume automatically** once the CA is back and unlocked. Any member whose
  cert drifted close to expiry while the CA was down will renew on the next cycle.
- **A member only needs to `koi certmesh join` again if it was missing from the restored
  roster** — e.g. it enrolled *after* the backup you restored. Check `koi certmesh status`;
  if an expected member is absent, have it re-join (you may need `koi certmesh
  open-enrollment` first).
- **If the CA's endpoint/IP changed**, update wherever members reach it (the `endpoint`
  you pass to `join`/`promote`, any DNS name pointing at the old CA host). mDNS discovery
  will find the CA at its new address on the same broadcast domain.

### 5. Re-establish redundancy

You just spent your safety margin. Rebuild it before the next failure:

- Promote a **new standby** on a different always-on host (step 1 of "Before disaster").
- Take a **fresh backup** from the recovered CA (`koi certmesh backup`) and store it off
  the host.

---

## Honest scope — what this does *not* cover

Knowing the limits keeps the runbook from over-promising under pressure:

- **No automatic failover.** Nothing detects a dead CA or elects a replacement. Every
  step above is a manual command. The 30-day cert lifetime is the cushion that makes
  manual recovery acceptable — a dead CA is a maintenance task, not an outage.
- **Revocation is roster-only — there is no CRL/OCSP.** `koi certmesh revoke <hostname>`
  marks a member revoked in the roster and stops Koi from renewing its cert, so it dies
  at its (≤30-day) expiry. Already-issued, still-valid certificates are **not** actively
  invalidated across the network. After a restore, the restored roster's revocations
  apply going forward; a cert revoked before the backup is still on the revoked member's
  disk and valid to TLS verifiers until it expires. If you need a member gone *now*,
  revocation alone is not enough — the bound is the cert lifetime. See
  [the security model](../reference/security-model.md).
- **A backup is only as fresh as its roster.** Restoring an old bundle brings back an old
  roster. Members that joined or were revoked since are not reflected until you re-join /
  re-revoke them. This is why backup cadence tracks roster changes.
- **Secrets are not recoverable from Koi.** Lose the CA passphrase *and* every backup
  passphrase and there is no backdoor — the CA key is gone. Store those passphrases the
  way you would store the key itself.

---

## See also

- [certmesh.md](./certmesh.md) — creating, joining, unlocking, and the promotion model in full.
- [acme.md](./acme.md) — the RFC 8555 facade; ACME-issued certs are reissued the same way after recovery.
- [proxy.md](./proxy.md) — the TLS proxy picks up the recovered member cert automatically once it lands on disk.
- [../reference/security-model.md](../reference/security-model.md) — the daemon access token, bind addresses, and the revocation trade-off.
