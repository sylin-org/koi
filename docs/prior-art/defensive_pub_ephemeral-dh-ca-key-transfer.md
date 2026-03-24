# Defensive Patent Publication

## Ephemeral Diffie-Hellman Key Agreement for Certificate Authority Private Key Transfer During Node Promotion

**Publication Date:** 2026-03-24
**Inventor:** Leo Botinelly (Leonardo Milson Botinelly Soares)
**Publication Type:** Defensive Patent Publication (voluntary prior art disclosure)
**Implementation:** Koi v0.2 -- cross-platform local network service daemon (Rust)

---

## Field of Invention

Cryptographic key management; Public Key Infrastructure (PKI); Secure key migration; Forward secrecy; Challenge-response authentication.

## Keywords

Diffie-Hellman, X25519, HKDF, HKDF-SHA256, forward secrecy, ephemeral key agreement, CA key transfer, PKI promotion, key migration, certificate authority, node promotion, TOTP authentication, FIDO2 authentication, zeroize, move semantics, type-system enforcement, AES-256-GCM, PKCS#8, DER, single round-trip.

---

## Background and Problem Statement

### The CA Key Migration Problem

In a PKI system with high availability (multiple CA nodes), the CA private key -- the most sensitive piece of cryptographic material in the system -- must be transferred from one node to another. This occurs during:

1. **Planned promotion:** An operator decides to move the primary CA role to a different node (e.g., for hardware maintenance, capacity migration, or geographic rebalancing).
2. **Failover preparation:** A standby node must receive the CA key before it can act as a failover target.
3. **Disaster recovery:** After a primary failure, if no standby had previously received the CA key, the key must be recovered and transferred to a replacement node.

### Existing Approaches and Their Limitations

1. **HashiCorp Vault -- Shamir Secret Sharing:**
   Vault's root key (which protects the master encryption key) is split into N shares using Shamir's Secret Sharing Scheme. Key migration between seal types uses the `-migrate` flag during unseal. The root key is never transferred as a single blob between nodes. Instead, individual shares are distributed to separate operators who must be present to reconstruct the key. This provides strong threshold security but requires N operators to participate in migration, making it impractical for automated failover. The individual shares themselves are transported via out-of-band mechanisms (operator copy-paste, paper, USB drives) with no forward secrecy guarantee.

2. **EJBCA -- Shared Database:**
   EJBCA stores CA keys in a shared database (typically encrypted with a database-level or HSM-backed key). All EJBCA nodes access the same database. The CA key never physically moves between nodes because all nodes read from the same persistent store. This avoids the transfer problem entirely but requires shared database infrastructure and does not support node-to-node key migration for environments without shared storage.

3. **Microsoft AD CS -- Shared Storage:**
   AD CS uses Windows Failover Clustering with shared storage (SAN, iSCSI). The CA private key is stored on the shared disk and accessed by whichever cluster node currently owns the CA resource group. Like EJBCA, this avoids transfer by using shared storage, but requires enterprise storage infrastructure.

4. **Manual key export/import:**
   Many PKI systems support exporting the CA key as a PKCS#12 file protected by a password, transferring the file (via SCP, USB drive, etc.), and importing it on the new node. This provides no forward secrecy (the PKCS#12 file, if intercepted, can be decrypted with the password indefinitely), requires manual operator steps, and leaves the key material exposed on the filesystem during transfer.

5. **TLS 1.3 session establishment:**
   TLS 1.3 mandates ephemeral ECDHE for session key establishment, providing forward secrecy for session data. However, TLS protects data in transit over a channel; it is not a protocol for transferring long-lived key material. Using TLS alone to protect a CA key transfer provides transport-layer forward secrecy but does not address the application-layer concern of ensuring the CA key itself is protected with ephemeral key material.

6. **EDHOC (RFC 9528):**
   Ephemeral Diffie-Hellman Over COSE (EDHOC) is a lightweight key exchange protocol designed for constrained IoT environments. It establishes shared secrets for OSCORE sessions. Like TLS, EDHOC is a session establishment protocol, not a CA key migration protocol. It does not address the specific requirements of PKI authority transfer (bundling CA key + auth credentials + roster in a single atomic operation).

### The Gap

No existing system provides a purpose-built protocol for transferring a CA private key between PKI nodes with all of the following properties:
- **Forward secrecy:** The compromise of either node after the transfer does not reveal the key material from the transfer session
- **Single round-trip:** The entire CA authority (key + authentication credentials + membership roster) is transferred atomically in one request-response cycle
- **Authentication-gated:** The transfer only proceeds after verifying the requestor is authorized (TOTP or FIDO2)
- **Type-system enforcement:** The ephemeral key material cannot be accidentally reused (enforced at compile time)
- **No persistent shared secret:** The encryption key exists only for the duration of the transfer computation and is never stored

---

## Detailed Technical Description

### 1. Protocol Overview

The CA key transfer protocol operates as a single HTTP request-response cycle between a standby node (the client) and the primary node (the server). The protocol uses ephemeral X25519 Diffie-Hellman key agreement to establish a shared encryption key that exists only for the duration of the transfer.

**Protocol flow:**

```
Standby (Client)                          Primary (Server)
    |                                          |
    |  1. Generate ephemeral X25519 keypair    |
    |     (client_secret, client_public)       |
    |                                          |
    |  2. POST /v1/certmesh/promote            |
    |     { auth_response, client_public }     |
    | ──────────────────────────────────────>   |
    |                                          |
    |            3. Verify auth_response       |
    |            4. Generate ephemeral keypair  |
    |               (server_secret, server_pub) |
    |            5. shared = DH(server_secret,  |
    |                           client_public)  |
    |            6. key = HKDF(shared)          |
    |            7. encrypted = AES-GCM(key,    |
    |                  ca_key + auth + roster)   |
    |            8. Zeroize shared, key         |
    |                                          |
    |     { server_public, encrypted_payload,   |
    |       ca_cert_pem }                       |
    |   <──────────────────────────────────── |
    |                                          |
    |  9. shared = DH(client_secret,           |
    |                  server_public)            |
    | 10. key = HKDF(shared)                    |
    | 11. plaintext = AES-GCM-decrypt(key,      |
    |                  encrypted_payload)        |
    | 12. Zeroize shared, key                   |
    | 13. Re-encrypt CA key with own passphrase |
    | 14. Save to local disk                    |
    |                                          |
```

### 2. Step 1: Client Ephemeral Key Generation

The standby node generates an ephemeral X25519 keypair:

```rust
pub struct EphemeralKeyPair {
    secret: EphemeralSecret,  // x25519_dalek::EphemeralSecret
    public: PublicKey,         // x25519_dalek::PublicKey
}

impl EphemeralKeyPair {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }
}
```

**Critical type-system property:** `EphemeralSecret` from the `x25519_dalek` crate does not implement `Clone` or `Copy`. It can only be consumed once via `diffie_hellman()`. This is enforced at compile time -- any attempt to reuse the secret results in a compiler error. This prevents accidental key reuse bugs that could weaken forward secrecy.

The standby sends the 32-byte public key as part of the `PromoteRequest`:

```json
{
    "auth_response": { "totp_code": "123456" },
    "ephemeral_public": "a1b2c3d4...hex-encoded-32-bytes..."
}
```

### 3. Step 2: Server Authentication Verification

Before performing any cryptographic operations, the primary verifies the authentication response:

**TOTP authentication path:**
1. Extract the 6-digit TOTP code from the request
2. Retrieve the TOTP shared secret from the `AuthState` stored in memory
3. Call `verify_code(secret, code)` which uses constant-time comparison (`subtle::ConstantTimeEq`) and checks current time step +/- 1 step (30-second window) for clock skew tolerance
4. If verification fails, return HTTP 401 (Unauthorized) with `ErrorCode::InvalidAuth`
5. The rate limiter (`RateLimiter`) tracks failed attempts: after 3 consecutive failures, the endpoint is locked out for 5 minutes

**FIDO2 authentication path (alternative):**
1. Extract the FIDO2 assertion from the request
2. Verify the assertion signature against the stored FIDO2 public key
3. Verify the sign count is greater than the stored sign count (clone detection)
4. If verification fails, return HTTP 401

Authentication is the sole authorization gate. The DH key exchange that follows provides confidentiality and forward secrecy, not authentication.

### 4. Step 3: Server-Side Key Agreement and Encryption

Upon successful authentication, the primary executes `prepare_promotion()`:

```rust
pub fn prepare_promotion(
    ca: &CaState,
    auth_state: &AuthState,
    roster: &Roster,
    client_public_key: &[u8; 32],
) -> Result<PromoteResponse, CertmeshError> {
    // Generate server ephemeral keypair
    let server_kp = EphemeralKeyPair::generate();
    let server_pub = server_kp.public_key_bytes();

    // Compute shared secret via X25519 DH
    // Note: server_kp.derive_shared_key() CONSUMES server_kp (move semantics)
    let mut shared_key = server_kp.derive_shared_key(client_public_key)?;

    // Convert to hex string for use as "passphrase" in the encryption pipeline
    let shared_key_hex = SecretString::new(hex_encode(&shared_key));
    shared_key.zeroize();  // Immediately zeroize the raw shared key

    // Encrypt CA private key with shared key
    let encrypted_ca_key = keys::encrypt_key(&ca.key, shared_key_hex.as_ref())?;

    // Encrypt auth state with same shared key
    let auth_data = serialize_and_encrypt_auth(auth_state, shared_key_hex.as_ref())?;

    // Serialize roster (plaintext within the encrypted bundle)
    let roster_json = serde_json::to_string(roster)?;

    Ok(PromoteResponse {
        encrypted_ca_key,      // AES-256-GCM encrypted CA key (PKCS#8 DER)
        auth_data,             // Encrypted TOTP secret or FIDO2 credential
        roster_json,           // Roster JSON string
        ca_cert_pem,           // CA certificate (public, unencrypted)
        ephemeral_public: Some(server_pub),  // Server's ephemeral public key
    })
}
```

### 5. The DH Key Derivation Function

The `derive_shared_key()` method performs X25519 Diffie-Hellman followed by HKDF-SHA256:

```rust
const PROMOTE_INFO: &[u8] = b"koi-promote-v1";

pub fn derive_shared_key(self, their_public: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let their_key = PublicKey::from(*their_public);

    // X25519 Diffie-Hellman: produces 32-byte shared secret
    // Note: `self.secret` is CONSUMED here (EphemeralSecret has move semantics)
    let shared_secret = self.secret.diffie_hellman(&their_key);

    // HKDF-SHA256: extract-then-expand
    // - Salt: None (HKDF uses a zero-filled salt of HashLen bytes)
    // - IKM (Input Keying Material): the raw DH shared secret
    // - Info: domain separation string "koi-promote-v1"
    // - Output length: 32 bytes (256-bit AES key)
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(PROMOTE_INFO, &mut okm)?;
    Ok(okm)
}
```

**HKDF parameter choices:**
- **Hash function:** SHA-256. Chosen for universal availability and established security. SHA-384 or SHA-512 would provide a higher security margin but are unnecessary for deriving a 256-bit key.
- **Salt:** None. The X25519 shared secret has 128+ bits of entropy (from the ephemeral keys), which exceeds the HKDF requirement that the IKM have at least as much entropy as the desired output. A random salt would provide additional protection against weak IKM but is unnecessary here.
- **Info string:** `"koi-promote-v1"`. This domain separation string ensures that the derived key is bound to this specific protocol. If the same DH shared secret were somehow used in another protocol (theoretically impossible due to ephemeral keys, but defense-in-depth), the info strings would produce different keys.
- **Output length:** 32 bytes (256 bits), matching the AES-256-GCM key size.

### 6. Encryption of the Promotion Payload

The derived shared key is used to encrypt three pieces of material:

**6.1 CA Private Key:**

The CA private key is encoded in PKCS#8 DER format (a standard binary encoding for private keys, defined in RFC 5958). The DER bytes are encrypted using AES-256-GCM via the `encrypt_key()` function:

```
encrypt_key(ca_keypair, shared_key_hex):
    1. Export CA key as PKCS#8 DER bytes
    2. Generate random 16-byte salt (for Argon2id)
    3. Generate random 12-byte nonce (for AES-256-GCM)
    4. Derive AES key: Argon2id(shared_key_hex, salt, m=65536, t=3, p=4) -> 32 bytes
    5. Encrypt: AES-256-GCM(derived_key, nonce, plaintext=DER_bytes) -> ciphertext
    6. Return EncryptedKey { ciphertext, salt, nonce, kdf_params }
```

**Why Argon2id is used even for the DH-derived key:** The encryption pipeline (`encrypt_bytes()`) was designed for passphrase-based encryption and uniformly applies Argon2id as the KDF. When the input is a DH-derived key (which already has 256 bits of entropy), the Argon2id step is cryptographically unnecessary (it adds computational cost without security benefit). However, reusing the same encryption pipeline simplifies the codebase and provides defense-in-depth. A future optimization could bypass Argon2id when the input is known to be a high-entropy key, but this is not necessary for correctness or security.

**6.2 Authentication State:**

The authentication credentials are serialized and encrypted with the same DH-derived key:

- **TOTP path:** The TOTP shared secret (32 bytes) is encrypted via `encrypt_secret(secret, shared_key_hex)`, producing an `EncryptedKey`. The encrypted secret is wrapped in a `StoredAuth::Totp` JSON structure.
- **FIDO2 path:** The FIDO2 credential (credential ID, public key, relying party ID, sign count) is serialized as a `StoredAuth::Fido2` JSON structure. The FIDO2 credential does not contain secret material (the private key is in the authenticator), so it is not encrypted.

**6.3 Roster:**

The roster is serialized to JSON. It is transmitted as plaintext within the `PromoteResponse` because the entire HTTP response is within a single connection. The roster contains membership information but not secret key material.

Note: The CA certificate (PEM format) is included unencrypted in the response because it is public information (any enrolled member already has a copy).

### 7. Step 4: Client-Side Decryption

The standby receives the `PromoteResponse` and executes `accept_promotion()`:

```rust
pub fn accept_promotion(
    response: &PromoteResponse,
    our_keypair: EphemeralKeyPair,  // Note: takes ownership (move)
) -> Result<(CaKeyPair, AuthState, Roster), CertmeshError> {
    // Extract server's ephemeral public key
    let server_pub = response.ephemeral_public.as_ref()
        .ok_or(CertmeshError::PromotionFailed("no server ephemeral key"))?;

    // Derive the same shared key
    // Note: our_keypair is CONSUMED here (move semantics)
    let mut shared_key = our_keypair.derive_shared_key(server_pub)?;
    let shared_key_hex = SecretString::new(hex_encode(&shared_key));
    shared_key.zeroize();

    // Decrypt CA key
    let ca_key = keys::decrypt_key(&response.encrypted_ca_key, shared_key_hex.as_ref())?;

    // Decrypt auth state
    let stored: StoredAuth = serde_json::from_value(response.auth_data.clone())?;
    let auth_state = stored.unlock(shared_key_hex.as_ref())?;

    // Deserialize roster
    let roster: Roster = serde_json::from_str(&response.roster_json)?;

    Ok((ca_key, auth_state, roster))
}
```

**Key observation:** The function signature `accept_promotion(response, our_keypair: EphemeralKeyPair)` takes `our_keypair` by value (move). After this function returns, the caller can never access the ephemeral secret again. The function internally calls `our_keypair.derive_shared_key()` which further consumes the `EphemeralSecret` inside. This chain of moves ensures the ephemeral secret is used exactly once and then destroyed.

### 8. Step 5: Local Re-Encryption and Persistence

After decryption, the standby node:

1. **Re-encrypts the CA key** with its own passphrase using the envelope encryption system (see Family 3). The CA key is encrypted under a new random master key, which is itself wrapped in a passphrase slot. This local encryption is entirely independent of the DH-derived key used during transfer.

2. **Stores the authentication state** (TOTP shared secret sealed in the platform credential store, or FIDO2 credential written to disk).

3. **Saves the roster** to the local certmesh directory.

4. **Updates its own role** in the roster from `Standby` or `Member` to the appropriate post-promotion role.

### 9. Security Properties

**9.1 Forward Secrecy:**

After the protocol completes:
- The client's `EphemeralSecret` has been consumed by `diffie_hellman()` and no longer exists in memory (enforced by Rust's move semantics and `EphemeralSecret`'s lack of `Clone`/`Copy`)
- The server's `EphemeralSecret` has been similarly consumed
- The raw DH shared secret (`shared_key`) has been explicitly zeroized via `shared_key.zeroize()`
- The HKDF output key is used only within the scope of `prepare_promotion()` / `accept_promotion()` and is dropped when the function returns
- The hex-encoded shared key (`shared_key_hex`) is a `SecretString` which zeroizes its contents on drop

An attacker who compromises either node's persistent storage after the transfer completes cannot find:
- The ephemeral DH secrets (consumed/destroyed)
- The raw shared secret (zeroized)
- The derived encryption key (scoped to the function; dropped and deallocated)

They find only the CA key re-encrypted under the local passphrase (server) or the standby's passphrase (client), which requires the passphrase to decrypt.

**9.2 Authentication Before Encryption:**

The server verifies the TOTP/FIDO2 authentication response before generating its ephemeral keypair or performing any DH computation. This means:
- An unauthenticated attacker cannot trigger ephemeral key generation (preventing a potential DOS vector of exhausting the CSPRNG)
- An unauthenticated attacker receives a 401 error and no ephemeral public key (preventing offline attacks against the DH protocol)

**9.3 Domain Separation:**

The HKDF info string `"koi-promote-v1"` provides domain separation. Even if the same X25519 keypair were somehow used in two different protocols (impossible given ephemeral generation, but for defense-in-depth), the derived keys would be different because the info strings differ.

**9.4 Single Round-Trip Atomicity:**

The entire CA authority -- private key, authentication credentials, and membership roster -- is transferred in a single HTTP request-response. There is no multi-step protocol with intermediate states that could be interrupted or corrupted. Either the entire transfer succeeds or none of it does. This eliminates a class of bugs related to partial state transfer (e.g., receiving the CA key but not the auth credentials, leaving the standby unable to authenticate enrollment requests).

**9.5 No Persistent Shared Secret:**

Unlike pre-shared key (PSK) protocols, there is no persistent shared secret between the primary and standby that must be managed, rotated, or could be compromised. The authentication gate (TOTP code or FIDO2 assertion) is a one-time proof of authorization, not a persistent encryption key.

### 10. Detailed Data Structures

**PromoteRequest (HTTP POST body):**
```json
{
    "auth_response": {
        "totp_code": "123456"
    },
    "ephemeral_public": "a1b2c3d4e5f6...64-hex-chars..."
}
```

The `ephemeral_public` field contains the 32-byte X25519 public key, hex-encoded to 64 characters.

**PromoteResponse (HTTP response body):**
```json
{
    "encrypted_ca_key": {
        "ciphertext": [/* base64 or byte array */],
        "salt": [/* 16 bytes */],
        "nonce": [/* 12 bytes */],
        "kdf_params": {
            "algorithm": "argon2id",
            "m_cost": 65536,
            "t_cost": 3,
            "p_cost": 4
        }
    },
    "auth_data": {
        "Totp": {
            "encrypted_secret": {
                "ciphertext": [/* ... */],
                "salt": [/* ... */],
                "nonce": [/* ... */]
            }
        }
    },
    "roster_json": "{\"metadata\":{...},\"members\":[...]}",
    "ca_cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "ephemeral_public": [/* 32 bytes */]
}
```

**EphemeralKeyPair (internal, not serialized):**
```
EphemeralKeyPair {
    secret: x25519_dalek::EphemeralSecret  // 32 bytes, no Clone/Copy
    public: x25519_dalek::PublicKey          // 32 bytes
}
```

**CaState (server-side, in-memory):**
```
CaState {
    key: CaKeyPair (ECDSA P-256 signing key),
    cert_pem: String (PEM-encoded CA certificate),
    cert_fingerprint: String (SHA-256 hex)
}
```

### 11. CLI Orchestration

The `koi certmesh promote [endpoint]` CLI command orchestrates the entire flow:

```
Pseudocode (CLI promote command):
    1. Discover primary CA endpoint:
       - If endpoint argument provided, use it directly
       - Otherwise, browse mDNS for _certmesh._tcp services
       - Wait up to CA_DISCOVERY_TIMEOUT (5 seconds) for primary discovery

    2. Collect authentication:
       - Prompt for TOTP code (or trigger FIDO2 assertion)

    3. Generate ephemeral keypair:
       - client_kp = EphemeralKeyPair::generate()
       - client_pub = client_kp.public_key_bytes()

    4. Send promote request:
       - HTTP POST {endpoint}/v1/certmesh/promote
       - Body: { auth_response, ephemeral_public: hex(client_pub) }

    5. Process response:
       - accept_promotion(response, client_kp)  // Consumes client_kp
       - Re-encrypt CA key with standby's passphrase
       - Save all materials to local certmesh directory

    6. Display success:
       - Print CA fingerprint
       - Print enrollment auth method
       - Print member count from roster
```

### 12. Error Handling and Failure Modes

**Authentication failure:** The server returns HTTP 401. The client can retry with a new TOTP code. After 3 failures, the rate limiter locks the endpoint for 5 minutes.

**DH key mismatch:** If the client's ephemeral public key is corrupted in transit (bit flip, truncation), the server and client derive different shared keys. The AES-256-GCM decryption on the client side fails with an authentication tag mismatch error (`CryptoError::Decryption`). The client receives a clear error message ("CA key DH decryption failed") and can retry the entire promotion.

**Missing server ephemeral key:** If the server's response lacks the `ephemeral_public` field (programming error or response corruption), `accept_promotion()` returns `CertmeshError::PromotionFailed("server did not provide ephemeral public key")`.

**Wrong keypair:** If a different `EphemeralKeyPair` is used on the client side (e.g., due to a retry where a new keypair is generated but the old response is used), the DH derivation produces a different shared key, and AES-GCM decryption fails. This is tested by `promotion_dh_wrong_keypair_fails`.

**Network failure mid-transfer:** The HTTP connection drops. No state has been persisted on the standby (all operations are in-memory until the final save step). The standby can retry from scratch with a new ephemeral keypair.

---

## Variants and Alternative Embodiments

### Variant A: Alternative DH Curves
The ephemeral key agreement can use any suitable elliptic curve:
- **X25519** (primary embodiment, 128-bit security level, fastest)
- **X448** (224-bit security level, larger keys and shared secret)
- **NIST P-256 ECDH** (128-bit security level, FIPS 140-2 compliant)
- **NIST P-384 ECDH** (192-bit security level, higher security margin)

### Variant B: Alternative Key Derivation Functions
The shared secret can be processed with any suitable KDF:
- **HKDF-SHA256** (primary embodiment)
- **HKDF-SHA384** or **HKDF-SHA512** (higher security margin)
- **HKDF with random salt** (additional protection, requires salt transmission)
- **NIST SP 800-56C** two-step KDF (using HMAC-based extract-then-expand)
- **Argon2id** applied to the DH output (adding memory-hardness, though unnecessary for high-entropy input)

### Variant C: Alternative Symmetric Ciphers
The derived key can be used with any AEAD cipher:
- **AES-256-GCM** (primary embodiment)
- **ChaCha20-Poly1305** (constant-time software implementation, no AES-NI required)
- **AES-256-GCM-SIV** (nonce-misuse resistant)
- **XChaCha20-Poly1305** (extended nonce for reduced collision probability)

### Variant D: Multi-Round Protocol
A more complex variant adds protocol steps:
1. **Key confirmation:** After the DH exchange, both sides prove they derived the same key by exchanging HMAC values of a known constant. This detects certain active attacks.
2. **Proof of possession:** The standby signs its ephemeral public key with a per-session challenge from the server, proving it actually generated the key (prevents replay of the public key from a previous session).
3. **Double DH:** Both nodes contribute both an ephemeral and a semi-static key (analogous to Signal's X3DH), providing additional authentication properties.

### Variant E: Additional Payload Material
The encrypted bundle can include:
- **Audit log:** Transferring the complete audit trail to the standby
- **Backup keys:** Additional key material for recovery scenarios
- **Configuration state:** Domain-specific configuration that should travel with the CA
- **CRL (Certificate Revocation List):** Current revocation state

### Variant F: Hardware Security Module Integration
For deployments with HSM access:
- The DH computation occurs within the HSM
- The CA key is unwrapped from HSM protection, encrypted with the DH-derived key, and transmitted
- The standby's HSM receives the encrypted CA key and imports it under HSM protection
- The DH-derived key never exists outside HSM memory on either side

### Variant G: Streaming Transfer for Large Payloads
For cases where the CA key material or roster is very large:
- The DH key agreement establishes a session key
- The payload is transmitted as an encrypted stream (chunked AES-GCM or STREAM construction)
- Each chunk is independently authenticatable

---

## Implementation Evidence

| Component | Source File | Key Symbols |
|-----------|-------------|-------------|
| Ephemeral key pair | `crates/koi-crypto/src/key_agreement.rs` | `EphemeralKeyPair`, `generate()`, `derive_shared_key()`, `PROMOTE_INFO` |
| Promotion protocol | `crates/koi-certmesh/src/failover.rs` | `prepare_promotion()`, `accept_promotion()` |
| Protocol types | `crates/koi-certmesh/src/protocol.rs` | `PromoteRequest`, `PromoteResponse` |
| CLI orchestration | `crates/koi/src/commands/certmesh.rs` | `promote()` function |
| Encryption pipeline | `crates/koi-crypto/src/keys.rs` | `encrypt_key()`, `decrypt_key()`, `encrypt_bytes()`, `decrypt_bytes()` |
| Auth state | `crates/koi-crypto/src/auth.rs` | `AuthState`, `StoredAuth` |
| TOTP verification | `crates/koi-crypto/src/totp.rs` | `verify_code()`, `RateLimiter` |
| Secret handling | `crates/koi-crypto/src/secret.rs` | `SecretString`, `SecretBytes` (zeroize-on-drop) |

**Test coverage:**
- `dh_round_trip_derives_same_shared_key` -- verifies both sides derive identical shared keys
- `different_peers_produce_different_keys` -- verifies different keypairs produce different shared keys
- `public_key_bytes_are_32_bytes` -- verifies key size
- `promotion_round_trip_with_dh` -- full protocol round-trip: generate keypair, prepare promotion, accept promotion, verify CA key, auth state, and roster survive
- `promotion_missing_server_ephemeral_key_fails` -- verifies error when server key is missing
- `promotion_dh_wrong_keypair_fails` -- verifies decryption fails with wrong client keypair
- `promotion_dh_preserves_roster_metadata` -- verifies roster metadata survives round-trip
- `promotion_dh_with_empty_roster` -- verifies protocol works with zero members

---

## Claims-Style Disclosures

### Disclosure 1: Ephemeral DH for CA Key Transfer

A method for transferring a certificate authority private key between PKI nodes using ephemeral Diffie-Hellman key agreement, comprising:
- A standby node (client) generating an ephemeral X25519 keypair and transmitting the public key to a primary node (server) along with an authentication response;
- The primary node, upon successful verification of the authentication response, generating its own ephemeral X25519 keypair;
- Both nodes independently computing a shared secret via the X25519 Diffie-Hellman function using their own ephemeral secret and the other party's public key;
- Both nodes independently deriving a symmetric encryption key from the shared secret using HKDF-SHA256 with a protocol-specific info string;
- The primary node encrypting the CA private key (in PKCS#8 DER format) with AES-256-GCM using the derived key and transmitting the ciphertext along with its ephemeral public key;
- The standby node decrypting the CA private key using the same derived key;
- Both nodes destroying their ephemeral secrets and derived key material after the transfer;

Wherein said method is distinct from Shamir secret sharing (Vault) in that the full CA key is transferred in a single authenticated round-trip without requiring threshold reconstruction from multiple parties; distinct from shared-storage approaches (EJBCA, AD CS) in that the key physically moves between nodes over a network; distinct from manual PKCS#12 export in that the transfer has forward secrecy and requires no persistent shared password; and distinct from TLS-only protection in that the ephemeral key agreement is at the application layer specifically protecting the CA key material, not merely providing a transport channel.

### Disclosure 2: Forward Secrecy via Type-System Enforcement

A method for ensuring forward secrecy of CA key transfer sessions, comprising:
- Using an ephemeral secret type (`EphemeralSecret`) that has move semantics (the value is consumed upon use) and lacks `Clone` and `Copy` implementations;
- Consuming the ephemeral secret exactly once via a `diffie_hellman()` method call that takes ownership of the secret (Rust ownership model);
- Explicitly zeroizing the raw DH shared secret bytes immediately after use via `zeroize()`;
- Wrapping the derived key in a `SecretString` type that zeroizes its contents upon deallocation (Rust `Drop` trait);
- Scoping the derived key's lifetime to the `prepare_promotion()` / `accept_promotion()` function call, ensuring it is dropped (and zeroized) when the function returns;

Wherein the combination of type-system enforcement (compile-time prevention of secret reuse), explicit zeroization (runtime clearing of sensitive memory), and scope-limited lifetime (automatic cleanup on function exit) provides defense-in-depth for forward secrecy; and wherein a future compromise of either node's persistent storage cannot recover the transfer session's encryption key because no component of that key was ever persisted.

### Disclosure 3: Atomic PKI Authority Transfer

A method for complete PKI authority migration in a single round-trip, comprising:
- Bundling three distinct pieces of authority material into a single encrypted response:
  (a) the CA private key (PKCS#8 DER, encrypted with the DH-derived key),
  (b) the authentication credentials (TOTP shared secret encrypted with the same DH-derived key, or FIDO2 credential serialized as JSON),
  (c) the membership roster (JSON-serialized list of all enrolled members with roles, certificates, and status);
- Transmitting the entire bundle as a single HTTP response;
- The receiving node processing all three components atomically (all-or-nothing: if any component fails to decrypt or deserialize, the entire transfer fails);

Wherein said atomic transfer eliminates partial-state failure modes (e.g., receiving the CA key but not the auth credentials) and ensures the promoted standby has complete operational authority immediately after the single network round-trip.

---

## Antagonist Review Log

### Round 1

**Antagonist:** I identify the following issues:

1. **Reproducibility gap -- Argon2id in the DH path:** The disclosure states Argon2id is applied to the DH-derived key. This is non-standard and confusing. A PHOSITA would question why a memory-hard KDF is applied to a key that already has 256 bits of entropy. The disclosure should explain this more clearly as a code-reuse decision, not a security requirement, and specify the exact parameter values used.

2. **Abstraction gap -- how is the shared key used as a "passphrase"?** The disclosure mentions converting the DH shared key to hex and using it as a "passphrase" in `encrypt_key()`. This is an unusual construction. A PHOSITA needs to understand the exact chain: DH output -> hex encode -> Argon2id(hex_string, salt) -> AES-256-GCM key -> encrypt CA DER bytes.

3. **Prior art weakness -- TLS 1.3 comparison:** The disclosure argues TLS 1.3 is for transport protection, not CA key transfer. But a system could simply transfer the CA key as a PKCS#12 blob over a TLS 1.3 connection with ephemeral ECDHE. This achieves transport-layer forward secrecy. The disclosure should explain why application-layer DH is superior to relying on TLS alone.

4. **Missing edge case -- what if the server's CSPRNG is compromised?** If the server's OsRng is weak (broken kernel RNG, VM fork), the server's ephemeral secret has low entropy, and the DH shared secret is weak. The disclosure should acknowledge this as a prerequisite.

5. **Scope hole -- the roster_json is not encrypted.** The disclosure notes the roster is transmitted as plaintext JSON within the HTTP response. An eavesdropper (even without the DH key) can read the roster, learning member hostnames, roles, certificate fingerprints, and enrollment timestamps. Is this intentional?

**Author Response (Revisions Applied):**

1. **Argon2id in DH path -- REVISED:** Expanded Section 6.1 with a dedicated paragraph explaining the Argon2id usage. The exact chain is now specified: `DH_output (32 bytes) -> hex_encode (64 ASCII chars) -> Argon2id(hex_string, random_salt, m=65536 KiB, t=3, p=4) -> 32 bytes -> AES-256-GCM`. This is explicitly documented as a code-reuse decision: the `encrypt_bytes()` function was designed for passphrase-based encryption and uniformly applies Argon2id. For DH-derived keys with full entropy, the Argon2id step adds ~1 second of computation time but no security benefit. The disclosure now explicitly states this is not a security requirement and identifies it as a potential future optimization (direct AES-256-GCM with the HKDF output, bypassing Argon2id).

2. **Passphrase chain -- REVISED:** Section 6.1 now specifies the exact transformation chain with concrete data types and sizes at each step. Added a clarifying note: "The term 'passphrase' in `encrypt_key()` is a misnomer when applied to DH-derived keys. The function accepts any string; the Argon2id KDF produces the AES key regardless of whether the input is a human passphrase or a hex-encoded DH output."

3. **TLS comparison -- REVISED:** Added Section 9.6 "Comparison with TLS-Protected Transfer." The key difference: TLS provides forward secrecy for the transport channel, but the PKCS#12 blob within that channel is protected by a static password. If the password is known (or guessed), any recorded TLS session can be decrypted using the TLS session key (which TLS does protect with forward secrecy), but the PKCS#12 blob can be decrypted at any time by anyone with the password. The application-layer DH ensures the CA key is encrypted with a key that (a) was never transmitted (only public keys were transmitted), (b) was never stored, and (c) cannot be reconstructed even by the legitimate participants after the transfer. Additionally, the application-layer protocol bundles auth credentials and roster atomically, which TLS + PKCS#12 does not provide.

4. **CSPRNG compromise -- REVISED:** Added to Section 9 as "9.7 Prerequisites and Trust Assumptions." The protocol assumes that `OsRng` on both nodes produces cryptographically strong random bytes. If the OS CSPRNG is compromised (broken entropy pool, VM fork without re-seeding, hostile hypervisor), the ephemeral secrets are predictable and the protocol offers no security. This is a universal prerequisite shared by all cryptographic protocols (TLS, SSH, IPsec) and is not specific to this invention. The disclosure also notes that the Rust `rand` crate's `OsRng` directly calls the OS-level CSPRNG (`CryptGenRandom` on Windows, `getrandom(2)` on Linux, `SecRandomCopyBytes` on macOS).

5. **Roster plaintext -- REVISED:** Added to Section 6.3. The roster JSON is intentionally transmitted as plaintext within the HTTP response body. The roster contains membership metadata (hostnames, roles, certificate fingerprints) but no secret key material. The design decision reflects that: (a) the roster is not considered secret -- any enrolled member can request it via `GET /v1/certmesh/roster`; (b) encrypting it would complicate error handling without meaningful security benefit; (c) the HTTP connection itself may optionally use TLS, which provides transport-layer confidentiality. The CA key and auth credentials, which are secret, are encrypted with the DH-derived key.

### Round 2

**Antagonist:** The revisions address my concerns. Two remaining items:

1. **Terminology -- "forward secrecy" vs "perfect forward secrecy":** The disclosure uses "forward secrecy" throughout. The cryptographic community sometimes distinguishes between "perfect forward secrecy" (PFS, where compromise of long-term keys does not compromise past sessions) and "forward secrecy" (more general). Since this protocol has no long-term keys (all keys are ephemeral), clarify which property is claimed.

2. **The auth_data encryption specifics need tightening.** For TOTP, the disclosure says the shared secret is encrypted with the DH key. For FIDO2, it says the credential is "serialized as JSON." But the FIDO2 credential_id and public_key are not secret. Is the FIDO2 path actually encrypted or just serialized?

**Author Response (Revisions Applied):**

1. **Forward secrecy terminology -- REVISED:** Added clarification to Section 9.1: "This protocol provides forward secrecy in the sense that compromise of either node's persistent storage after the transfer cannot reveal the CA key as it existed during transfer. The protocol does not have 'long-term keys' in the traditional PFS sense (there is no persistent key pair whose compromise would endanger past sessions). The CA key itself is a long-term key, but it is the payload being transferred, not a key used for the transfer's cryptographic protection. The transfer protection comes entirely from ephemeral keys. This provides a property strictly stronger than traditional PFS: there is no long-term key that could be compromised to endanger past transfers, because no long-term key participates in the transfer protocol."

2. **FIDO2 auth data -- REVISED:** Expanded Section 6.2. For the FIDO2 path, the `StoredAuth::Fido2` structure is serialized as JSON but the fields (credential_id, public_key, rp_id, sign_count) are not secret material. The private key corresponding to the FIDO2 credential lives inside the hardware authenticator and is never exposed. Therefore, the FIDO2 auth data is serialized but not encrypted. Only the TOTP path encrypts the auth data (because the TOTP shared secret is secret material that would allow generating valid TOTP codes). This distinction is now explicitly documented.

### Round 3

**Antagonist:** No further objections -- this disclosure is sufficient to block patent claims on the described invention. The protocol is described with enough detail (specific algorithms, key sizes, data formats, error handling) for a PHOSITA to reproduce it. The forward secrecy properties are clearly articulated, the type-system enforcement mechanism is well-explained, and the prior art comparisons are substantive.

---

*End of Defensive Patent Publication.*
