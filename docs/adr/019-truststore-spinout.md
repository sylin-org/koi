# ADR-019 — Spin `koi-truststore` out to the external `os-truststore` crate

- **Status:** Accepted
- **Date:** 2026-06-20
- **Supersedes:** the in-repo `koi-truststore` foundation crate

## Context

`koi-truststore` was a small foundation crate (platform CA-root install: `certutil` /
`security` / `update-ca-certificates`). The 2026-06 maturity assessment flagged it as a
"model small crate" and a reusable primitive, and STACK-0001 names `truststore` as part of
Koi's contract surface. The Rust ecosystem has **no mature, turnkey crate that installs a
CA root cross-platform** (the popular crates only *read* the system store), so the
capability has standalone value beyond Koi.

We therefore spun it out into its own repository and family — **`os-tools`** (the
"Operational Symmetry" family: `OS` = one symmetric API, mirror-not-copy platform
implementations) — as the crate **`os-truststore`**, rebuilt as an orchestrator with a
delight-first, cert-as-identity API (`Cert::from_pem` → `install`/`is_installed`/`uninstall`),
an exhaust-all-methods Linux backend, native `schannel` on Windows, honest macOS
degradation, and an in-process `rustls` trust helper. See the os-tools repo's
`docs/adr/0001` and `docs/PRIOR-ART.md`.

This ADR records the Koi-side consequences.

## Decision

1. **Delete `crates/koi-truststore`** from the Koi workspace.
2. **Depend on `os-truststore` as a published crates.io version** — `os-truststore = "0.0.2"`.
   (Initially this was a git dependency `{ git = "https://github.com/sylin-org/os-tools" }`
   while os-truststore stabilised — a path dep was rejected because `../os-tools` breaks Koi
   CI, which checks out only Koi. Once os-truststore published `0.0.2` the git dep was
   swapped for the version pin — the "package dance" below — restoring Koi's own crates.io
   publishability.)
3. **Rewire the two consumers to the new cert-as-identity API:**
   - `koi-certmesh` (CA-create + member-join trust installs): `os_truststore::Cert::from_pem(pem)`
     then `os_truststore::install(&cert)`, best-effort (logged warn) as before.
   - `koi trust` (`commands/trust.rs`): install via `Cert::from_pem` + `Install::new(&cert).label(name)`;
     remove reconstructs the cert from the entry's recorded source path, then `uninstall(&cert)`.
     The `koi trust install/list/remove <name>` CLI and the `state/trust.json` tracking are
     **unchanged** — only the underlying calls swapped.
4. **Update the guards/docs:** the architecture guard drops `koi-truststore` from the
   foundation class; `publish.yml` drops it from the publish list; the dependency-graph
   docs reference the external crate.

## STACK-0001

STACK-0001 names `truststore` as a contract surface and is canon ("do not contradict
without an upstream architect decision"). This spin-out is that authorized decision: the
**surface still exists and is honored** — Koi consumes `os-truststore` and the
trust-store capability is unchanged — it simply lives in an external crate now. The HKDF
domain-separation strings, the certmesh/mdns/dns/udp surfaces, and the consumer-agnostic
rule are untouched.

## Consequences

- **Package dance — done (2026-06-20).** While `os-truststore` was git-sourced, Koi could
  not publish `koi-certmesh` / `koi-net` to crates.io (`cargo publish` rejects a git source
  without a version). `os-truststore 0.0.2` is now published, and the git dep was swapped for
  `os-truststore = "0.0.2"`, so Koi is publishable again. Local builds, CI, and the release
  *test* gate were unaffected throughout.
- The trust-store implementation, its tests (unit + cross-distro round-trips on
  Debian/Fedora/Arch), and its MSRV (1.88, bounded by the `time` crate) now live in
  os-tools and are exercised by os-tools CI, not Koi's.
- `koi trust remove <name>` now requires the original source PEM to still exist (it
  reconstructs the cert to uninstall it); it errors clearly if the file is gone. This is a
  minor behavioral narrowing accepted to keep the dogfood contained (no `trust.json`
  schema change).
- Koi's MSRV (1.92) already exceeds os-truststore's (1.88), so there is no toolchain
  conflict.
