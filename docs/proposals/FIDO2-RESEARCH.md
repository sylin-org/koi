# FIDO2/WebAuthn Rust Ecosystem Research

**Purpose:** Architectural research for koi — a CLI-first, daemon-based local network trust tool that currently uses TOTP for enrollment authentication. Evaluating FIDO2 as a potential upgrade/replacement.

**Date:** 2025

---

## Table of Contents

1. [Protocol Fundamentals](#1-protocol-fundamentals)
2. [Rust Crate Analysis](#2-rust-crate-analysis)
3. [SSH FIDO2 Precedent (Non-Browser)](#3-ssh-fido2-precedent)
4. [Mobile FIDO2 / Cross-Device Options](#4-mobile-fido2--cross-device-options)
5. [Architectural Recommendations for koi](#5-architectural-recommendations-for-koi)

---

## 1. Protocol Fundamentals

### The FIDO2 Stack

FIDO2 is **two specifications** working together:

```
┌─────────────────────────────────────────────────┐
│  WebAuthn (W3C)                                 │
│  - Web API for browsers (navigator.credentials) │
│  - Defines Relying Party (RP) verification      │
│  - Assumes browser + HTTPS origin model         │
│  - RP ID = domain name (e.g., "example.com")    │
└────────────────────┬────────────────────────────┘
                     │ (browser mediates)
┌────────────────────▼────────────────────────────┐
│  CTAP2 (FIDO Alliance)                          │
│  - Client-to-Authenticator Protocol             │
│  - Transport: USB HID, BLE, NFC, hybrid/caBLE   │
│  - CBOR-encoded messages                        │
│  - Direct device communication                  │
│  - NO browser required at this layer            │
└─────────────────────────────────────────────────┘
```

**Key insight for koi:** WebAuthn is the browser-facing API. CTAP2 is the wire protocol to talk to authenticators. A CLI application needs CTAP2, not WebAuthn. The WebAuthn RP verification logic (challenge/response, signature verification) is useful server-side regardless.

### Authenticator Taxonomy

| Type | Attachment | Examples | Transport |
|------|-----------|----------|-----------|
| **Platform authenticator** | Built into device | Windows Hello, Touch ID, Android biometrics | `internal` |
| **Roaming authenticator** | External, portable | YubiKey, SoloKey, Nitrokey, FEITIAN | `usb`, `nfc`, `ble` |
| **Hybrid/CDA authenticator** | Phone-as-authenticator | Smartphone via QR+BLE | `hybrid` (caBLE) |
| **Software authenticator** | Virtual, in-memory | 1Password's passkey-authenticator crate | `internal` |

### Core Ceremony Flow (Registration)

1. **RP generates challenge** (random bytes, ≥16 bytes)
2. **Client sends challenge to authenticator** via CTAP2 (over USB/BLE/NFC)
3. **Authenticator creates key pair**, requires user presence (touch) and optionally user verification (PIN/biometric)
4. **Authenticator returns:** credential ID, public key, attestation statement (signed)
5. **RP verifies** attestation signature, stores public key + credential ID

### Core Ceremony Flow (Authentication)

1. **RP generates challenge**, sends with allowed credential IDs
2. **Client sends to authenticator** via CTAP2
3. **Authenticator signs challenge** with stored private key (after user presence/verification)
4. **Authenticator returns:** authenticator data + signature
5. **RP verifies** signature against stored public key

### CTAP2 Key Concepts

- **User Presence (UP):** Physical touch/tap — proves human is at the device
- **User Verification (UV):** PIN, fingerprint, or face — proves *which* human
- **Discoverable Credentials (resident keys):** Stored entirely on authenticator, enables passwordless
- **Non-discoverable Credentials:** Key handle stored server-side, authenticator only has master key
- **Attestation:** Cryptographic proof of authenticator make/model (optional, privacy-sensitive)
- **COSE keys:** CBOR Object Signing and Encryption — the key format used (not X.509)
- **Supported algorithms:** ES256 (P-256/ECDSA), EdDSA (Ed25519), RS256 (RSA) — ES256 is most universal

### Transport Protocols

| Transport | Range | Setup | CTAP2 Support | Notes |
|-----------|-------|-------|---------------|-------|
| **USB HID** | Physical | Plug in | Full | Most reliable, widest authenticator support |
| **NFC** | ~4cm | Tap | Full | Mobile-friendly, requires NFC reader |
| **BLE** | ~10m | Pairing | Full | Wireless, more complex setup |
| **Hybrid/caBLE** | Internet-bridged | QR code scan | Full | Phone-as-authenticator, uses BLE for proximity + cloud tunnel |
| **Internal** | On-device | N/A | Platform-specific | Windows Hello, Touch ID, etc. |

---

## 2. Rust Crate Analysis

### Tier 1: Production-Ready, Actively Maintained

#### `webauthn-rs` — Relying Party (Server-Side) Library

| Property | Value |
|----------|-------|
| **Version** | 0.5.4 |
| **Downloads** | 1,861,985 all-time |
| **Last Updated** | ~2 months ago |
| **License** | MPL-2.0 |
| **SLoC** | ~1,057 |
| **Role** | **Server/RP only** — verifies registrations and assertions |
| **Browser Required?** | **Yes, assumes browser flow** — requires `rp_id` (domain) and `rp_origin` (URL) |
| **Platform Support** | Any (pure Rust, no platform deps) |
| **Dependencies** | Minimal (serde, base64, openssl/ring for crypto) |
| **Maintenance** | Active — Kanidm project (William Brown / Firstyear) |
| **Security Audit** | ✅ Passed audit by SUSE product security |

**Assessment for koi:** Excellent for verifying FIDO2 assertions on the daemon side. Would need an `rp_id` — could use a synthetic one like `"koi.local"` rather than a real domain. The origin-checking logic would need to be relaxed or customized for non-browser use. The core cryptographic verification is sound and audited.

**Key API surface:**
```rust
// Server creates challenge
let (ccr, reg_state) = webauthn.start_passkey_registration(user_id, &user_name, &user_display_name, None)?;
// After client returns attestation:
let passkey = webauthn.finish_passkey_registration(&response, &reg_state)?;
// Authentication:
let (rcr, auth_state) = webauthn.start_passkey_authentication(&[passkey])?;
let auth_result = webauthn.finish_passkey_authentication(&response, &auth_state)?;
```

---

#### `ctap-hid-fido2` — USB HID Client Library ⭐ **Best fit for koi CLI**

| Property | Value |
|----------|-------|
| **Version** | 3.5.8 |
| **Downloads** | 50,996 all-time |
| **Last Updated** | ~3 months ago |
| **License** | MIT |
| **SLoC** | ~5,000 |
| **Role** | **Client — talks directly to USB FIDO2 authenticators** |
| **Browser Required?** | **NO** — CLI-native, includes `ctapcli` tool |
| **Platform Support** | macOS, Windows (admin needed), Linux/RPi (libusb + libudev) |
| **Dependencies** | hidapi (USB HID), ring (crypto) |
| **Maintenance** | Active, single maintainer (gebogebogebo) |
| **Tested Authenticators** | YubiKey Bio, YubiKey 5, FEITIAN, SoloKey, Nitrokey, OpenSK, Idem Key |

**Assessment for koi:** **Most directly relevant crate.** Implements CTAP2 over USB HID without any browser dependency. Provides the full client-side flow: `make_credential` (register) and `get_assertion` (authenticate), plus PIN management, credential management, and bio enrollment. The included `ctapcli` CLI tool demonstrates exactly the kind of non-browser FIDO2 interaction koi would need.

**Key capabilities:**
- Register credentials (make_credential)
- Authenticate (get_assertion)
- PIN set/change
- Credential management (list, delete resident keys)
- Bio enrollment (fingerprints)
- CTAP 2.0 and 2.1 support
- `hmac-secret` extension support

**Platform considerations:**
- **Windows:** Requires running as admin (or special USB HID access)
- **Linux:** Requires `libusb-1.0-0-dev` + `libudev-dev`, plus udev rules for FIDO devices
- **macOS:** Works out of the box

---

#### `passkey` (1Password) — Client + Authenticator Library

| Property | Value |
|----------|-------|
| **Version** | 0.5.0 |
| **Downloads** | 534,574 all-time |
| **Last Updated** | ~1 month ago |
| **License** | MIT / Apache-2.0 |
| **Role** | **Both client AND authenticator** — WebAuthn L3 + CTAP2 |
| **Browser Required?** | No (provides software authenticator) |
| **Platform Support** | Any (pure Rust) |
| **Dependencies** | coset, ciborium (CBOR), p256 (crypto) |
| **Maintenance** | Active — 1Password team |

**Sub-crates:**
- `passkey-client` — WebAuthn client implementation
- `passkey-authenticator` — Software/virtual authenticator with pluggable `CredentialStore` trait
- `passkey-transports` — CTAP HID transport
- `passkey-types` — WebAuthn/CTAP2 type definitions
- `public-suffix` — domain validation

**Assessment for koi:** Interesting dual role. The `passkey-authenticator` could serve as a **software authenticator** for testing or for nodes that lack physical security keys. The `CredentialStore` trait allows custom storage backends. However, the client always reports as "Platform" attachment with "internal" transport, and only supports ES256. Most useful as a **validation/testing tool** rather than production authenticator.

**Key trait:**
```rust
/// Pluggable credential storage
#[async_trait]
pub trait CredentialStore {
    type PasskeyItem: TryFrom<Passkey> + Into<Passkey>;
    async fn find_credentials(&self, ids: Option<&[PublicKeyCredentialDescriptor]>, rp_id: &str)
        -> Result<Vec<Self::PasskeyItem>, Error>;
    async fn save_credential(&mut self, cred: Passkey, user: PublicKeyCredentialUserEntity, rp: PublicKeyCredentialRpEntity)
        -> Result<(), Error>;
    // ...
}
```

---

#### `authenticator` (Mozilla) — Firefox's CTAP Client

| Property | Value |
|----------|-------|
| **Version** | 0.5.0 |
| **Downloads** | 1,206,416 all-time |
| **Last Updated** | ~4 months ago |
| **License** | MPL-2.0 |
| **SLoC** | ~20,000 |
| **Role** | **Client — USB HID CTAP1/CTAP2 interaction** |
| **Browser Required?** | No (but designed for Firefox integration) |
| **Platform Support** | Windows, Linux, FreeBSD, NetBSD, OpenBSD, macOS |
| **Dependencies** | libudev (Linux), core-foundation (macOS), winapi (Windows), optional OpenSSL |
| **Maintenance** | Active — Mozilla team |

**Assessment for koi:** Battle-tested in Firefox with millions of users. However, has a Firefox-centric API with C FFI headers (designed for Gecko integration). The docs.rs build **fails** for v0.5.0 (last successful build was v0.3.1), suggesting API instability. Much larger codebase (20K SLoC) with more platform-specific code. Less suitable than `ctap-hid-fido2` for koi's simpler needs, but worth noting as the most battle-tested option.

---

### Tier 2: Niche / Supporting Crates

#### `fido2-rs` — libfido2 C Bindings

| Property | Value |
|----------|-------|
| **Version** | 0.4.0 |
| **Downloads** | 3,503 all-time |
| **License** | MIT |
| **SLoC** | ~1,476 |
| **Role** | FFI bindings to Yubico's libfido2 C library |
| **Browser Required?** | No |
| **C Dependency** | **Yes — requires libfido2 installed** |
| **Maintenance** | Single owner (tyan-boot), very low adoption |

**Assessment for koi:** Wraps the same C library that OpenSSH uses internally. Supports Windows Hello (`Device::open("windows://hello")`). However, the heavy C dependency (libfido2 requires libcbor + OpenSSL + zlib + libudev) makes cross-compilation harder. Low adoption suggests limited community testing.

#### `cosey` — COSE Key Types

| Property | Value |
|----------|-------|
| **Version** | 0.4.0 |
| **Downloads** | 47,909 all-time |
| **License** | Apache-2.0 / MIT |
| **SLoC** | ~407 |
| **Role** | COSE_Key serialization/deserialization only |
| **no_std** | ✅ Yes — embedded-friendly |
| **Maintenance** | trussed-dev (embedded security project) |

**Assessment for koi:** Utility crate only — not an authenticator or RP library. Useful if building custom FIDO2 message parsing. The `no_std` support is interesting for embedded scenarios.

#### Non-existent / Dead Crates

- **`fido-common`** — Does not exist on crates.io
- **`fido2-client-rs`** (github.com/niccolozanotti) — Repository returns 404

---

### Crate Comparison Matrix

| Crate | Role | Browser-Free? | Downloads | Last Updated | Platform Deps | Audit |
|-------|------|--------------|-----------|-------------|---------------|-------|
| **webauthn-rs** | RP/Server | Partial¹ | 1.86M | ~2mo | None | ✅ Yes |
| **ctap-hid-fido2** | Client/USB | ✅ Yes | 51K | ~3mo | hidapi | No |
| **passkey** | Client+Auth | ✅ Yes | 535K | ~1mo | None | No |
| **authenticator** | Client/USB | ✅ Yes | 1.2M | ~4mo | Platform-specific | No |
| **fido2-rs** | Client (FFI) | ✅ Yes | 3.5K | ~3mo | libfido2 (C) | No |
| **cosey** | Types only | ✅ Yes | 48K | ~4mo | None | No |

¹ The crypto verification is browser-free; the RP ID / origin validation assumes browser context but can be customized.

---

## 3. SSH FIDO2 Precedent

### How OpenSSH Uses FIDO2 (No Browser)

OpenSSH is the **definitive precedent** for non-browser FIDO2. Since OpenSSH 8.2 (Feb 2020), SSH supports FIDO2 security keys as a first-class key type.

**Key types added:**
- `ecdsa-sk` — ECDSA on P-256 with FIDO2 security key
- `ed25519-sk` — Ed25519 with FIDO2 security key

**How it works:**
```bash
# Generate a FIDO2-backed SSH key (user touches security key)
ssh-keygen -t ed25519-sk

# Generate a resident/discoverable key (stored on device)
ssh-keygen -t ed25519-sk -O resident

# Download resident keys from authenticator
ssh-keygen -K

# Use with custom application string (like koi could do!)
ssh-keygen -t ed25519-sk -O application=ssh:koi-enrollment
```

**Architecture:**
1. OpenSSH links against **libfido2** (Yubico's C library) for USB HID communication
2. The `SSH_SK_PROVIDER` environment variable can override the default library
3. Communication is **pure CTAP2 over USB HID** — no browser, no WebAuthn API, no HTTP
4. The "application" field defaults to `"ssh:"` — this is analogous to WebAuthn's `rp_id`
5. Challenge can be provided externally via `-O challenge=path` for out-of-band enrollment protocols

**FIDO2 options supported by ssh-keygen:**
- `application` — Override the FIDO application string (must start with `"ssh:"`)
- `challenge` — Custom challenge for out-of-band enrollment
- `resident` — Store key on authenticator (discoverable credential)
- `verify-required` — Require PIN/biometric (User Verification)
- `no-touch-required` — Skip user presence test
- `device` — Specify a particular FIDO device
- `write-attestation` — Save attestation data

### What This Proves for koi

1. **FIDO2 works perfectly without a browser.** OpenSSH has been doing it since 2020 across all major platforms.
2. **The CTAP2 layer is the right abstraction** — not WebAuthn. SSH doesn't use WebAuthn at all.
3. **The `application` field** is the FIDO2 equivalent of a domain/service identifier. SSH uses `"ssh:"` prefix; koi could use something like `"koi:"` or `"ssh:koi"`.
4. **Custom challenge support** enables out-of-band enrollment — exactly koi's use case.
5. **Resident keys** mean the authenticator can store the enrollment credential directly, enabling passwordless re-enrollment.
6. **libfido2** (C) is the proven implementation, but Rust-native alternatives (`ctap-hid-fido2`) provide the same CTAP2 functionality without the C dependency.

---

## 4. Mobile FIDO2 / Cross-Device Options

### Cross-Device Authentication (CDA) / Hybrid Transport / caBLE

The `hybrid` transport (formerly called caBLE — cloud-assisted BLE) enables using a **phone as an authenticator** for a nearby computer. This is the technology behind "Use your phone to sign in" prompts.

**How it works:**
1. **Computer displays QR code** containing a one-time linking secret + BLE advertisement info
2. **Phone scans QR code** (or uses a previously established "persistent link")
3. **Phone and computer establish BLE proximity proof** (~10m range)
4. **Actual CTAP2 traffic tunnels through a cloud relay** (Google/Apple operated) encrypted end-to-end
5. **Phone performs the FIDO2 ceremony** (user presence + verification via biometrics)
6. **Assertion returns to computer** via the tunnel

**Critical limitation for koi:** Hybrid transport is implemented by **platform credential managers** (Google Password Manager, iCloud Keychain, Samsung Pass) and **browsers**. There is no standalone library or CLI that implements the hybrid/caBLE client protocol. The protocol requires:
- BLE advertising/scanning
- Cloud relay tunnel (Google's or Apple's servers)
- Phone-side OS integration (Android Credential Manager, iOS)

### Phone-as-Authenticator Options for Headless Servers

| Approach | Feasibility for koi | Notes |
|----------|-------------------|-------|
| **USB security key** | ✅ Excellent | Plug into server, `ctap-hid-fido2` handles it |
| **NFC security key** | ⚠️ Requires reader | Server needs NFC hardware (unusual) |
| **BLE security key** | ⚠️ Requires BLE | Server needs BLE adapter |
| **Phone via hybrid/caBLE** | ❌ Not feasible | Requires browser/OS integration, cloud relay |
| **Phone as BLE authenticator** | ❌ Not standardized | No protocol for direct phone-to-CLI FIDO2 over BLE |
| **Software authenticator** | ✅ Possible | `passkey-authenticator` crate — runs on the daemon itself |

### Practical Assessment

For a **headless server** or CLI daemon context:
- **USB security keys are the primary option.** This is exactly how SSH FIDO2 works.
- **Phone-as-authenticator is not feasible** without a browser or platform credential manager mediating the flow.
- **Software/virtual authenticators** are possible but defeat the purpose of hardware-bound security (unless used for testing or as a fallback).

For **koi's enrollment scenario specifically:**
- The admin plugs a USB security key into the machine running `koi enroll` (or the machine where the CLI is)
- The security key proves the admin's identity during enrollment
- This replaces the TOTP code that currently proves "I am the admin who set up this node"

---

## 5. Architectural Recommendations for koi

### Recommended Approach: CTAP2-Only Client + Custom RP Verification

```
┌──────────────────┐     CTAP2/USB HID     ┌──────────────────┐
│  koi CLI          │◄────────────────────►│  Security Key     │
│  (ctap-hid-fido2) │                       │  (YubiKey, etc.)  │
│                   │                       └──────────────────┘
│  Challenge ◄──────┤
│  Assertion ──────►│
└────────┬─────────┘
         │ network (mTLS)
┌────────▼─────────┐
│  koi daemon       │
│  (RP verification)│
│  - verify sig     │
│  - check challenge│
│  - store pub key  │
└──────────────────┘
```

### Crate Selection

| Component | Recommended Crate | Why |
|-----------|------------------|-----|
| **USB HID client** | `ctap-hid-fido2` | CLI-native, no browser, proven with major security keys |
| **RP verification** | `webauthn-rs` (types + crypto) or hand-rolled | Audited crypto, but may need to bypass origin checks |
| **COSE key handling** | `cosey` or `passkey-types` | For parsing/storing public keys in COSE format |
| **Testing** | `passkey-authenticator` | Virtual authenticator for CI/CD testing |

### Integration Design for koi Enrollment

**Current flow (TOTP):**
```
Admin runs: koi admin setup → gets TOTP secret
New node:   koi enroll --token <6-digit-TOTP>
```

**Proposed flow (FIDO2):**
```
Admin runs: koi admin setup → registers security key (touch required)
                             → stores public key as "admin credential"

New node:   koi enroll       → daemon sends challenge to CLI
            CLI prompts:     "Touch your security key..."
            ctap-hid-fido2:  → sends CTAP2 makeCredential/getAssertion to USB device
            User touches key → assertion signed
            CLI sends assertion to daemon
            Daemon verifies signature against stored admin public key
            Enrollment approved ✅
```

### Key Design Decisions

1. **Application ID:** Use `"ssh:koi"` or define a custom scheme. The FIDO2 `rp_id` equivalent for non-browser use is the `application` string. SSH constrains it to `"ssh:"` prefix.

2. **Discoverable vs Non-discoverable:** For enrollment, **non-discoverable** is likely sufficient — the daemon knows which admin credential to expect. Discoverable credentials are useful if multiple admins need to enroll without identifying themselves first.

3. **User Verification:** Require UV (`verify-required`) for enrollment — this adds PIN/biometric on top of physical presence, making it true multi-factor (something you have + something you know/are).

4. **Platform dependencies:** `ctap-hid-fido2` needs:
   - **Windows:** Admin privileges for raw USB HID access
   - **Linux:** `libudev-dev` + `libusb-1.0-0-dev`, udev rules
   - **macOS:** No additional deps

5. **Fallback:** Keep TOTP as a fallback for environments without USB access (e.g., cloud VMs, containers). FIDO2 would be the preferred/stronger option.

6. **Attestation:** For koi's trust model, attestation is optional. The important thing is the key pair, not the authenticator's make/model.

### Risks and Considerations

| Risk | Mitigation |
|------|-----------|
| `ctap-hid-fido2` single maintainer | Mozilla's `authenticator` crate as backup; core CTAP2 protocol is stable |
| Windows requires admin for USB HID | Document requirement; or use `fido2-rs` with libfido2 which may handle Windows Hello |
| No security audit on client crates | The cryptographic primitives (ECDSA, CBOR) come from audited libraries (ring, etc.) |
| Container/VM environments lack USB | FIDO2 optional, TOTP fallback required |
| Complexity increase over TOTP | FIDO2 is significantly more complex; only worth it if phishing resistance matters for enrollment |

### Build/Test Dependencies to Add

```toml
# Cargo.toml — new dependencies for FIDO2 support
[dependencies]
ctap-hid-fido2 = "3.5"       # USB HID FIDO2 client
# webauthn-rs = "0.5"         # Optional: RP-side verification types
# cosey = "0.4"               # Optional: COSE key types

[dev-dependencies]
# passkey-authenticator = "0.5"  # Virtual authenticator for tests
```

### Decision Framework

**Add FIDO2 if:**
- Enrollment security is critical (adversary might intercept TOTP codes)
- Users/admins already have FIDO2 security keys
- Physical presence proof is important (admin must be at the machine)

**Stay with TOTP if:**
- Simplicity is paramount
- Deployment targets are mostly cloud VMs / containers (no USB)
- Threat model doesn't include TOTP interception

**Hybrid approach (recommended):**
- Implement FIDO2 as an optional, stronger enrollment method
- Keep TOTP as the default/fallback
- Feature-gate FIDO2 behind a cargo feature flag to avoid mandatory USB dependencies

```toml
[features]
default = []
fido2 = ["ctap-hid-fido2"]
```
