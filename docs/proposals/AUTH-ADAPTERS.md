# Proposal: Auth Adapter Architecture

**Status:** In Progress  
**Date:** 2026-02-13  
**Author:** Design collaboration (operator + AI)

## Summary

Replace the hard-wired TOTP authentication in certmesh with a pluggable
adapter system. One flow, N auth methods. TOTP and FIDO2 ship as the
first two adapters. Adding a third method means writing a new adapter —
no flow changes, no protocol rework.

## Motivation

- TOTP is the right default for most deployments (containers, VMs, cloud)
- Hardware security keys (YubiKey, Titan, SoloKey) offer phishing-resistant
  auth with better UX: "insert key, tap, done" — no phone, no codes
- Operators should **choose** their auth method at CA creation time, and
  be able to **change** it on a live CA
- The system should treat auth methods as configuration, not functional gates

## Design Principles

1. **One flow, N configs** — The enrollment/promote/rotate flow is identical
   regardless of auth method. Callers never branch on method.
2. **Adapters, not conditionals** — Each auth method is a struct behind a
   trait. The flow calls `adapter.verify()`. Period.
3. **Default flag** — Each adapter declares `is_default()`. The CLI uses this
   to pre-select in the menu. TOTP is the default.
4. **Method is mutable** — The operator can rotate the auth method on a live
   CA via `koi certmesh auth rotate`. Already-enrolled nodes are unaffected.
5. **USB stays in the CLI** — Only the CLI binary (`koi`) talks to physical
   FIDO2 keys via `ctap-hid-fido2`. The daemon (`koi-certmesh`) does pure
   signature verification using `p256` (already a dependency).

## Architecture

### Trait

```rust
pub trait AuthAdapter: Send + Sync {
    fn method_name(&self) -> &'static str;
    fn is_default(&self) -> bool;
    fn challenge(&self, credential: &AuthCredential) -> Result<AuthChallenge, AuthError>;
    fn verify(
        &self,
        credential: &AuthCredential,
        challenge: &AuthChallenge,
        response: &AuthResponse,
    ) -> Result<bool, AuthError>;
}
```

### Enums (serde-tagged, method-agnostic transport)

```rust
#[serde(tag = "method")]
pub enum AuthCredential {
    Totp { encrypted_secret: EncryptedKey },
    Fido2 { credential_id: Vec<u8>, public_key: Vec<u8>, rp_id: String, sign_count: u32 },
}

#[serde(tag = "method")]
pub enum AuthChallenge {
    Totp,
    Fido2 { challenge: Vec<u8>, credential_id: Vec<u8>, rp_id: String },
}

#[serde(tag = "method")]
pub enum AuthResponse {
    Totp { code: String },
    Fido2 { authenticator_data: Vec<u8>, signature: Vec<u8>, client_data_hash: Vec<u8> },
}
```

### Adapter Resolution

```rust
pub fn adapter_for(credential: &AuthCredential) -> Box<dyn AuthAdapter>;
pub fn available_adapters() -> Vec<Box<dyn AuthAdapter>>;
```

### Call Pattern (every auth-gated endpoint)

```rust
let adapter = auth::adapter_for(&credential);
let valid = adapter.verify(&credential, &challenge, &request.auth)?;
rate_limiter.check_and_record(valid)?;
```

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /auth/challenge` | Returns `AuthChallenge` based on CA's configured method |
| `GET /auth/methods` | Discovery: list available methods + default flag |
| `POST /auth/rotate` | Swap auth method on live CA (passphrase required) |

Existing endpoints (`/join`, `/promote`) accept `AuthResponse` instead of
a raw TOTP code.

## CLI UX

### Create
```
$ koi certmesh create
  Passphrase: ••••••••
  Authentication method:
  [1] TOTP — authenticator app  (default)
  [2] FIDO2 — hardware security key
  Press Enter for default, or choose: 
```

### Join (auto-discovers method)
```
$ koi certmesh join stone-01.local
  Contacting CA... auth method: FIDO2
  Insert your security key and tap now...
  ✓ Enrolled.
```

### Rotate
```
$ koi certmesh auth rotate
  Current method: TOTP
  Passphrase: ••••••••
  New method:
  [1] TOTP — authenticator app  (default)
  [2] FIDO2 — hardware security key
  > 2
  Insert your security key and tap now...
  ✓ Auth method changed to FIDO2.
```

## Dependency Impact

| Crate | New Dep | Why |
|---|---|---|
| `koi-crypto` | None (uses existing `p256`, `sha2`) | FIDO2 verification is ECDSA signature check |
| `koi` (CLI) | `ctap-hid-fido2` (MIT, 5K SLoC) | USB HID communication with physical keys |

## Adding a Future Method

1. Add variant to `AuthCredential`, `AuthChallenge`, `AuthResponse`
2. Write `NewAdapter` implementing `AuthAdapter`
3. Add arm to `adapter_for()`
4. Add arm to CLI `resolve_auth()`

No flow changes. No daemon changes. No protocol rework.

## Platform Notes

- **Windows**: `ctap-hid-fido2` requires admin privileges for USB HID access
- **macOS/Linux**: Works without elevation
- **Containers**: No USB → TOTP is the only option (and the default)

## Files Changed

| File | Change |
|---|---|
| `koi-crypto/src/auth/` | New module: trait, enums, TOTP adapter, FIDO2 adapter |
| `koi-crypto/src/totp.rs` | Unchanged — wrapped by TotpAdapter |
| `koi-certmesh/src/protocol.rs` | `totp_code` → `auth: AuthResponse` |
| `koi-certmesh/src/lib.rs` | `totp_secret` → `auth: Mutex<Option<AuthCredential>>` |
| `koi-certmesh/src/http.rs` | challenge handler, rotate handler, existing handlers use adapter |
| `koi-certmesh/src/enrollment.rs` | `verify_code()` → `adapter.verify()` |
| `koi-certmesh/src/failover.rs` | Transfer `AuthCredential` instead of encrypted TOTP |
| `koi-certmesh/src/backup.rs` | Serialize `AuthCredential` into bundle |
| `koi/src/commands/certmesh.rs` | Auth menu, `resolve_auth()`, FIDO2 USB interaction |
