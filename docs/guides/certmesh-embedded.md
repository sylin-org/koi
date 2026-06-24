# Embedding certmesh

`koi-embedded` gives you the **certmesh engine** as a library — the same `CertmeshCore` the
daemon runs, in your process, with no `koi` binary and no IPC. This guide is for Rust
applications that want to **be a mesh participant** (get and keep a CA-signed cert) or
**be the mesh's CA** (issue and revoke), rather than shelling out to the daemon.

The mental model: `koi-embedded` hands you the **complete certmesh domain** (every
operation), plus the **plain-HTTP routes**. The *network adapters* a full daemon also runs
— the mTLS inter-node listener, the lifecycle background loops, ACME, the DAT token gate —
are **yours to compose**, because an embedded host wires exactly the role it plays. This is
deliberate: the binary is batteries-included; the library is composable. For the daemon's
end-to-end behavior and the protocol, see [certmesh.md](certmesh.md); for the general
embedded API, [embedded.md](embedded.md); one-screen map: the
[certmesh-invite card](../reference/cards/certmesh-invite.md).

---

## What you get, and what you wire

| Surface | In embedded? | How |
| --- | --- | --- |
| **The whole `CertmeshCore`** — create, unlock, `mint_invite`, `enroll`, `prepare_member_csr`, `install_member_cert`, `revoke_member`, `renew_self_if_due` (member-side), `renew_member` (CA-side, transport-agnostic — ADR-021), `member_cert_expiry`, `pull_trust_bundle`, `self_enroll`, open/close-enrollment, `certmesh_status`, audit log, destroy | **Yes — automatic** | `handle.certmesh()?.core()?` → `Arc<CertmeshCore>` |
| **Plain-HTTP routes** (`/v1/certmesh/{create,status,join,trust-bundle,revoke,member-csr,member-cert,invite,…}`) | **Yes** when `.http(true)` | Mounted at `/v1/certmesh`. **No DAT token gate** — see [Authentication](#authentication) |
| **mTLS inter-node listener** (`/renew`, `/promote`, `/health`, `/set-hook` — how a CA serves member renewals) | **You wire it** | `koi_certmesh::mtls::serve(core.inter_node_routes(), …)` |
| **Lifecycle background loop** (auto-renewal + trust-bundle pull: policy refresh + revocation detection) | **Opt-in** | `.certmesh_background(true)` |
| **ACME (RFC 8555) facade** | **No** | Binary-only adapter |
| **mDNS `_certmesh._tcp` `fp=` CA advertise** | **No** (auto) | Register via the mDNS core if you want discovery |

The pieces the CLI *assembles* (the join client, promotion) are public modules you call
directly: `koi_certmesh::{csr, invite, mtls, bundle, member, failover}`. Anything the
`koi certmesh …` CLI does, an embedded app can do in-process — the CLI is just HTTP
orchestration over these same primitives.

> Working references: the integration suite drives the full exchange through exactly this
> surface — [`crates/koi-embedded/tests/whole_story.rs`](../../crates/koi-embedded/tests/whole_story.rs)
> (two embedded daemons: create → join → mTLS renewal → revoke) and
> [`crates/koi/tests/two_daemon_certmesh.rs`](../../crates/koi/tests/two_daemon_certmesh.rs).

---

## Embed a member

The common case: your app wants a CA-signed leaf from an existing mesh and keeps the
private key local (the key custody invariant — the key never leaves your process).

```rust
use koi_embedded::Builder;
use koi_certmesh::{invite, protocol::{JoinRequest, JoinResponse}};
use koi_crypto::pinning::fingerprints_match;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A certmesh-enabled embedded daemon. `data_dir` isolates this member's certs/keys.
    let koi = Builder::new()
        .data_dir("/var/lib/myapp/koi")
        .mdns(false).dns_enabled(false)   // a leaf member needs neither
        .certmesh(true)
        .build()?;
    let handle = koi.start().await?;
    let core = handle.certmesh()?.core()?;          // the full CertmeshCore

    // The operator handed you an invite code out of band: `<secret>.<ca_fingerprint>`.
    let code = std::env::var("KOI_INVITE")?;
    let (secret, pinned_fp) = invite::decode_code(&code);
    let pinned_fp = pinned_fp.ok_or("invite carries no CA fingerprint")?;

    let host = hostname::get()?.to_string_lossy().into_owned();
    let ca = "http://ca-host:5641";
    let http = reqwest::Client::new();

    // 1. Preflight + PIN: confirm the CA you reached is the one the invite names,
    //    BEFORE sending a CSR (defeats a LAN MITM of discovery).
    let status: serde_json::Value =
        http.get(format!("{ca}/v1/certmesh/status")).send().await?.json().await?;
    let advertised = status["ca_fingerprint"].as_str().unwrap_or_default();
    if !fingerprints_match(advertised, pinned_fp) {
        return Err("CA fingerprint mismatch — refusing to join".into());
    }

    // 2. Your LOCAL daemon generates the keypair + CSR; the private key stays here.
    let sans = vec![host.clone()];
    let csr = core.prepare_member_csr(&host, &sans).await?;

    // 3. Send only the CSR + the secret to the remote CA. `/join` is the one
    //    DAT-token-exempt mutation (the invite/CSR are the credential).
    let join: JoinResponse = http
        .post(format!("{ca}/v1/certmesh/join"))
        .json(&JoinRequest {
            hostname: host.clone(),
            auth: None,
            invite_token: Some(secret.to_string()),
            csr: Some(csr),
            sans: sans.clone(),
        })
        .send().await?.json().await?;   // response carries NO private key

    // 4. Install the signed leaf next to the local key, pinned to the out-of-band
    //    fingerprint (install hard-fails if the returned CA cert doesn't match).
    core.install_member_cert(
        &host, &join.service_cert, &join.ca_cert,
        Some(ca), Some(pinned_fp), &sans, Some(join.policy.clone()),
    ).await?;

    // Cert + key are now at <data_dir>/certs/<host>/. handle.shutdown().await? when done.
    Ok(())
}
```

That is the exact three-call flow `koi certmesh join` performs — assembled in-process. The
member's key custody (`member-csr`/`member-cert`) stays on **your** core; only the CSR
crosses the wire to the CA.

---

## Keep the member's cert fresh

A leaf is short-lived (default 90-day, renew at 30 remaining). Two ways to renew:

**Opt into the background loop** — the same role loops the daemon runs:

```rust
let koi = Builder::new()
    .data_dir("/var/lib/myapp/koi")
    .certmesh(true)
    .certmesh_background(true)   // hourly: pull trust bundle + renew-if-due over mTLS
    .build()?;
```

**Or drive it yourself** — call `renew_self_if_due()` on your schedule (it reads the
`member.json` the install wrote, rotates the key, and pulls a fresh leaf from the CA's mTLS
`/renew`, verifying the pinned fingerprint):

```rust
match core.renew_self_if_due().await? {
    koi_certmesh::RenewOutcome::Renewed { .. } => { /* reload your TLS config */ }
    koi_certmesh::RenewOutcome::NotDue { .. } | koi_certmesh::RenewOutcome::NotApplicable => {}
}
let _ = core.pull_trust_bundle().await?;   // refresh policy + detect self-revocation
```

Renewal dials the CA's **mTLS** port (5642 by default). The CA must be serving that
listener — see below.

---

## Embed a CA host

If your app *is* the mesh authority, create the CA in-process, then stand up the mTLS
listener so members can renew. The CA's `inter_node_routes()` (renew/promote/health) are
served **only** over mTLS, and `koi-embedded` does not start that listener for you — wire
it with the public primitive (the binary's `adapters::mtls` is a thin wrapper over the
same calls):

```rust
use axum::Router;
use koi_certmesh::{mtls, protocol::CreateCaRequest};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

let koi = Builder::new()
    .data_dir("/var/lib/myapp/koi")
    .certmesh(true)
    .http(true).http_port(5641)   // serves /v1/certmesh/{create,status,join,trust-bundle,…}
    .build()?;
let handle = koi.start().await?;
let core = handle.certmesh()?.core()?;

// Create the CA non-interactively (just-me posture => auto-unlock, boots unlocked).
core.create(CreateCaRequest {
    passphrase: std::env::var("KOI_CA_PASSPHRASE")?,
    entropy_hex: "…64 hex chars (32 bytes)…".into(),
    operator: Some("ops".into()),
    enrollment_open: true,
    requires_approval: false,
    auto_unlock: true,
    totp_secret_hex: None,
}).await?;

// Serve the mTLS inter-node listener so members can renew (CA self-leaf for the TLS id).
let leaf = core.self_enroll().await?;
let tls = mtls::build_server_config(&leaf.cert_pem, &leaf.key_pem, &leaf.ca_cert_pem)?;
let listener = TcpListener::bind(("0.0.0.0", 5642)).await?;
let cancel = CancellationToken::new();
let app = Router::new().nest("/v1/certmesh", core.inter_node_routes());
tokio::spawn(mtls::serve(app, listener, tls, cancel.clone()));

// Mint invites for members (the code carries the CA fingerprint — F3 pin):
let invite = core.mint_invite("web-01", 60).await?;   // invite.token = <secret>.<ca_fp>
// Hand `invite.token` to web-01 out of band. Revoke later with core.revoke_member(...).
```

> The mTLS listener must come up *after* the CA exists and is unlocked (so `self_enroll`
> can produce the server leaf) — that's why the daemon only starts it at boot when a CA is
> present. In-process, create (or auto-unlock) the CA first, then spawn `serve`.

### Sign renewals over your own transport (no mTLS listener)

If your CA runs **EmbeddedOnly** — no HTTP/mTLS stack at all — you don't have to stand up
the mTLS listener to renew members. `CertmeshCore::renew_member(authenticated_cn, csr_pem)`
([ADR-021](../adr/021-embedded-completion.md)) is the same CA-side renewal the `/renew`
handler runs, exposed as a domain method so any transport reaches it:

```rust
// `authenticated_cn` is a TRUSTED, pre-authenticated identity — your transport proves it
// (an mTLS ClientCn, or `Assurance::identity()` after handle.verify(envelope)). The method
// never re-authenticates; it enforces the CA-side invariants: the member must be active +
// not revoked, the CSR's SANs cannot expand beyond the enrollment record (a renewal that
// tries to is rejected `InvalidPayload`), then it signs, updates the roster, audits, and
// emits CertRenewed.
let resp = core.renew_member(&authenticated_cn, &csr_pem).await?;
// resp.service_cert = the renewed leaf; resp.ca_cert / resp.ca_fingerprint for the member's pin.
```

The member side stays `renew_self_if_due()` (it generates the rotated CSR and presents its
current identity); `renew_member` is what the *CA* runs to answer it — over mTLS via the
built-in handler, or over the envelope plane / a custom transport via this call.

Enrollment approval, if `requires_approval: true`: the embedded background loop
**auto-denies** (there's no interactive console). A CA host that needs operator approval
should keep approval in its own UI and call `enroll` after approving, or run open
enrollment gated by invites.

---

## Authentication

The standalone daemon gates every certmesh mutation with the `x-koi-token` Daemon Access
Token (`/v1/certmesh/join` is the one exemption). **The embedded HTTP adapter applies no
token middleware** — its routes are open to whoever can reach the port. That's fine for
in-process or trusted-loopback use; if you expose the embedded HTTP surface beyond that,
**you own the auth** (bind to loopback, put it behind your app's authn, or front it with
your own middleware). See [api-authentication.md](api-authentication.md) for the token
model the binary uses.

---

## Lean builds and certmesh

Two `koi-embedded` Cargo features change certmesh behavior at *compile* time (see
[embedded.md → Cargo features](embedded.md#cargo-features-lean-builds)):

- **`keyring` off** — CA-key sealing and TOTP unlock slots fall back to **passphrase**
  unlock instead of the OS keychain. (In a container with no machine-id, auto-unlock can't
  seal anyway — boot with a passphrase or a mounted key.)
- **`qr` off** — `mint_invite`/create return the `otpauth://` URI as text instead of a
  rendered QR (still scannable). Invites don't use QR; this only affects the TOTP setup.

Everything else (the whole `CertmeshCore`, the routes, mTLS) is always compiled.

---

## Validated end to end

This embedded surface is exercised by the ADR-018 cross-participant suite, so the flows
above are tested, not just intended:
[`whole_story.rs`](../../crates/koi-embedded/tests/whole_story.rs) (two embedded daemons:
create → invite → join over HTTP → key-rotating mTLS renewal → trust-bundle → revoke →
403 boundary, plus the F3/F7/F11 boot invariants) and the real-binary, cross-host, and
cross-platform tiers ([certmesh.md → testing](certmesh.md), ADR-018).

---

## See also

- [certmesh.md](certmesh.md) — the full daemon flow, protocol, and lifecycle.
- [embedded.md](embedded.md) — the general `koi-embedded` API, builder, and lean builds.
- [certmesh-invite card](../reference/cards/certmesh-invite.md) — one-screen enrollment map.
- [api-authentication.md](api-authentication.md) — the DAT token model.
- [ADR-015](../adr/015-certmesh-enrollment-hardening.md) (key custody + invites),
  [ADR-017](../adr/017-certmesh-trust-lifecycle.md) (renewal/trust-bundle/revocation),
  [ADR-018](../adr/018-certmesh-integration-test-suite.md) (the test suite).
