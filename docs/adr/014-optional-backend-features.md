# ADR-014: Optional heavy backends are default-on cargo features

- **Status:** Accepted
- **Date:** 2026-06-13
- **Supersedes/relates:** ADR-013 (runtime adapters), ADR-010 (docker adapter), STACK-0001

## Context

`koi-embedded` is a library: consumers choose what to compile. Three dependencies are
**heavy, rarely-run, and version-locking**, yet were compiled into every consumer —
including a lean mDNS-only embedder that never touches them:

- **`bollard`** (Docker/Podman backend, `koi-runtime/src/docker.rs`). Its `bollard-stubs`
  pins with an exact `=` version, so a consumer who also uses bollard is locked to koi's
  exact version. The runtime adapter is already disabled by default at runtime
  (`runtime_enabled = false`).
- **`keyring`** (OS credential store, `koi-crypto/src/tpm.rs`). Drags in Secret
  Service / **D-Bus** / zbus on Linux — absent in a minimal container image.
- **`qrcode` + `image`** (TOTP enrollment QR rendering, `koi-crypto/src/totp.rs`). The
  `image` PNG codec is large and used only to draw a one-time enrollment QR.

P06 made this worse: the `koi-dashboard` event forwarder maps every domain's events, so
`koi-embedded → koi-dashboard` now drags the full crypto/TLS/Docker closure transitively.

Koi canon bans `#[cfg(feature)]` for **capabilities** (capabilities are runtime tunables,
`--no-<cap>`). But a `bollard`/`keyring`/`qr` dependency is a **backend / output format**,
not a capability — compile-time selection of a backend is legitimate and idiomatic for a
library (cf. reqwest TLS backends, sqlx drivers).

## Decision

Gate each heavy backend behind a **default-on** cargo feature at its **leaf crate**, and
propagate the choice through the workspace:

1. **Gate at the leaf module only.** The optional dep is `optional = true`; only the one
   module that imports it (`docker.rs` / `tpm.rs` / `totp.rs`) is `#[cfg(feature = …)]`.
   The capability, its public types, and the trait stay unconditional.
2. **Keep the signature, gate the impl.** Functions a caller invokes unconditionally
   (`tpm::seal_key_material`, `totp::qr_code_*`, the runtime backend match) keep stable
   signatures with a graceful fallback when the feature is off — no `#[cfg]` at any call
   site. Fallbacks: vault passphrase backend; the `otpauth://` URI text; backend
   `BackendUnavailable` (the same bucket as the unimplemented systemd/incus/k8s
   backends).
3. **Default-on.** `default = [feature]` everywhere, so existing consumers and the
   `koi-net` binary are byte-identical. A lean consumer opts out with
   `default-features = false` and re-arms à la carte (`features = ["docker"]`).
4. **Propagate via Cargo.** Every internal edge to a gated leaf carries
   `default-features = false` — set in **`[workspace.dependencies]`** (Cargo *ignores*
   member-level `default-features = false` on inherited deps otherwise). Intermediate
   crates re-expose default-on pass-through features; the binary requests the leaf
   features explicitly (so a future default flip can't silently strip it); the top
   library (`koi-embedded`) forwards to the leaf features, which Cargo feature
   unification arms across the whole subgraph. An umbrella `full = […]` enables all.
5. **Guard it.** `scripts/check-lean-embedded.sh` (CI `lean` job) builds the leaves +
   `koi-embedded` with `--no-default-features` and asserts, from an **external probe**
   (robust to workspace feature unification), that a lean consumer's tree contains none
   of bollard / keyring / image / qrcode.

## Consequences

- A lean `koi-embedded` consumer (e.g. zen-garden's `lantern`) sheds bollard, the
  OS-keychain/D-Bus stack, and the image codec with one line. zen-garden's `moss`, which
  pins its own `bollard` to match koi's, can decouple via `default-features = false`.
- **Behavioral edge:** with `keyring` off, TOTP credential-store **unlock slots** are
  unavailable (passphrase unlock remains); with `qr` off, QR renderers return the
  `otpauth://` URI text. Both are correct for the headless audience that opts out.
- This does **not** reconcile a genuine `bollard` *version* conflict for a consumer that
  enables `docker` and pulls a different bollard major — it only removes the *forced*
  compile for non-Docker consumers.
- Future backends (systemd/incus/k8s) follow this same shape; `runtime`/`crypto` are
  outside STACK-0001's frozen contract surface, so this ADR governs non-contract
  capabilities and does not touch the frozen mdns/dns/certmesh/udp/truststore surface or
  the HKDF domain-separation bytes.
