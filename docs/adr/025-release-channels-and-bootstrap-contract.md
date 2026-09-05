# ADR-025: Artifact-First Release Channels

**Status:** Accepted
**Date:** 2026-07-19
**Builds on:** ADR-024 (Find, Trust, Connect)
**Applies to:** native archives, direct installers, crates.io, cargo-binstall, npm, GHCR, and future OS package manifests

> **Amended 2026-08-25 by [ADR-034](034-multi-channel-distribution.md) (D5):** the npm channel changes
> shape from a download-dispatcher to the platform-carrier pattern (`optionalDependencies` with `os`/`cpu`
> per target). Two things here are **not** amended: §3's placement rule — a service is never registered
> from an npm-managed path; installation still places the binary in Koi's stable per-user location — and
> §1's single-build/single-manifest chokepoint, which carriers consume like every other channel. The
> "one npm binary package per target" rejection below is accordingly superseded; the remaining rejected
> alternatives stand.

---

## Context

Koi already builds one native binary for six target triples. A version tag tests the
workspace, creates those archives, publishes SHA-256 sidecars, attaches keyless build
provenance, creates a GitHub Release, assembles the Linux archives into a multi-arch
container, and publishes the Rust crate graph.

That is a sound release foundation, but it is not yet a complete distribution
experience. GitHub archives and the checksum-verifying shell and PowerShell installers
are real binary channels, while `cargo install koi-net` still asks every user to
rebuild a large native program. Native package managers have no common machine-readable
contract to consume. Adding each channel independently would repeat target mapping,
archive naming, and checksum decisions in several repositories and languages.

`npx` is attractive because it is widely available and makes trial commands pleasant.
It also has an important boundary: npm executes an npx package from npm's cache. Koi
can install itself as a long-running OS service, so the cached package location must
never become the registered service binary.

## Decision

### 1. Build once; publish the result many ways

The GitHub Actions native build matrix is Koi's only release build. Publication
channels consume its outputs; they do not compile Koi again and do not carry their own
binary builds.

Every release carries a deterministic `koi-v<version>-manifest.json` containing:

- the schema version, Koi version, tag, and canonical repository;
- all six target triples;
- each archive's exact name, byte size, SHA-256 digest, and versioned URL; and
- the SHA-256 digest and versioned raw URL of `install.sh` and `install.ps1`.

The release workflow generates this contract from the completed archives and rejects
a missing target, malformed sidecar, mislabeled sidecar, or digest mismatch. The
manifest is published beside the archives and receives a provenance attestation.
Channel automation may check and transform this contract, but archive identity is
evaluated here once.

### 2. Channel responsibilities stay thin

The supported channel model is:

| Channel | Responsibility | Binary source |
|---|---|---|
| Direct shell/PowerShell | Detect, verify, extract, and place the native binary | GitHub Release |
| `cargo binstall koi-net` | Select the official target archive and extract `koi` | GitHub Release |
| `npx @sylin-org/koi` | Verify and invoke the matching versioned direct installer | GitHub Release |
| GHCR | Package the exact Linux release binaries as a container | Build artifacts |
| crates.io | Publish Rust libraries and the source-install escape hatch | Tagged source |
| Future WinGet/Homebrew | Translate the manifest into native package metadata | GitHub Release |

`cargo-binstall` metadata disables third-party quick-install artifacts and compilation
fallback. If the official prebuilt archive cannot be used, that command fails instead
of quietly changing its trust or performance model.

### 3. npm is a bootstrap, not a runtime distribution

The npm package has one executable named `koi`, no runtime dependencies, and no
`postinstall` hook. Its version equals the native Koi release version.

When explicitly executed, it:

1. selects the POSIX or Windows installer from its embedded release manifest;
2. downloads that installer from the matching versioned Git tag URL;
3. verifies the installer before executing it;
4. pins `KOI_VERSION` to the npm package's version;
5. lets the existing installer place the binary in Koi's stable per-user location;
   and
6. forwards any remaining arguments to that stable native binary.

Thus `npx @sylin-org/koi -- mdns discover` may provide a one-command trial, but the result
is an ordinary native Koi installation. A service is never registered from an npm
cache path. Subsequent commands are simply `koi ...`.

The package name is `@sylin-org/koi`, matching the canonical GitHub organization and
repository recorded in the release manifest. `koi` is occupied by an unrelated npm
package. The package verifier derives this scoped identity from the manifest so registry
naming cannot drift from the repository while the bootstrap contract remains unchanged.

### 4. External publication is deliberately gated

Packaging tests run during every manual release dry run and real tag build. npm
publication runs only after the GitHub Release exists and only when all of these are
true:

1. the scoped public package has received its one-time initial publication;
2. npm trusted publishing names this repository and `release.yml`;
3. the repository variable `NPM_PUBLISH_ENABLED` is exactly `true`; and
4. the tag path has passed native tests, all six builds, manifest validation, npm
   tests, and npm pack validation.

Normal npm releases use GitHub Actions OIDC and npm provenance, not a long-lived npm
token. WinGet submissions, Homebrew tap creation, package-visibility changes, and the
first npm publication remain explicit external operations rather than side effects of
preparing this repository.

### 5. Release preparation owns an exact file set

The version-bump command may update Cargo metadata, npm metadata, the lockfile, and
curated release prose. It stages only those known files. It must never use
`git add -A`, because unrelated experiments, evidence, or user work do not become
release content merely by sharing a working tree.

The tag command validates channel tests and package-version agreement. By default it
only tags the exact remote `main` tip. An exceptional recovery release requires an
explicit override.

### 6. Public documentation follows availability

Documentation distinguishes three states:

- **available:** verified and publicly installable now;
- **prepared:** implementation is merged and exercised, but a registry or repository
  has not been activated; and
- **planned:** the channel still needs engineering or operational ownership.

Unavailable commands are never presented as working quick-start commands. Once a
channel is activated and independently verified, the installation guide may promote
it without changing this architecture.

### 7. One release identity controls every channel

`scripts/release-version.mjs` is the release-domain boundary for parsing the workspace
version and deciding whether it is stable or a prerelease. Version preparation, tag
creation, release manifests, and both publication workflows consume that result instead
of independently interpreting strings. A tag-triggered workflow refuses when the pushed
tag differs from the workspace version.

Stable releases advance the normal public defaults: the GitHub Latest release, npm's
`latest` dist-tag, and GHCR's `latest` plus major/minor tag. Prereleases are deliberately
opt-in: GitHub marks them as prereleases and not Latest, npm publishes them under `next`,
and GHCR publishes only the exact prerelease version. crates.io receives the exact SemVer
prerelease and propagation is checked through that exact version's registry entry, never
inferred from whichever version the registry currently calls maximum.

Cargo installation recipes follow the same decision. Stable documentation may use the
compatible `major.minor` requirement; prerelease documentation names the full prerelease
because Cargo will not select a prerelease from a stable-only requirement.

Public release versions follow SemVer with three numeric components and optional
prerelease identifiers. Build metadata is excluded because every channel and artifact
must share one unambiguous public identity. An automatic bump from a prerelease is also
refused: the operator must explicitly choose the next candidate or stable version.

### 8. Candidate validation is an evidence contract

The manual `Release` workflow is validation, never publication. Its default token has
read-only repository access; release creation, attestations, GHCR and npm writes are
declared only on tag-gated jobs. Crates publication is callable only from that tag
path and has no independent manual trigger.

Every successful manual build uploads `candidate-validation-<source-sha>`, containing
one JSON document with this schema-1 shape:

```json
{
  "schemaVersion": 1,
  "sources": [{"repository": "https://github.com/sylin-org/koi", "sha": "<40-hex>"}],
  "artifactManifest": {
    "file": "koi-v<version>-manifest.json",
    "sha256": "<64-hex>",
    "schemaVersion": 1,
    "version": "<semver>",
    "tag": "v<semver>",
    "targets": [{"target": "<supported-triple>", "sha256": "<64-hex>"}]
  },
  "hostedEvidence": [{"name": "<required-job>", "status": "success", "url": "<run-url>"}],
  "nativeEvidence": [{"platform": "<fleet-hat>", "status": "pending", "sourceSha": null, "artifactSha256": null, "url": null}],
  "previewTargets": [{"targets": ["<triple>"], "qualification": "<bounded-claim>"}],
  "verdict": {"infrastructure": "passed", "candidate": "pending", "blockers": ["<reason>"]}
}
```

The required hosted job set is `prepare`, `test`, `build`, `finalize-windows`, and
`channels`. A missing, skipped or failed member makes infrastructure fail. The report
hashes the validated six-target artifact manifest and binds every later native entry
to the same source SHA and an exact artifact SHA-256. Windows, CachyOS, Bluefin,
Alpine and Debian native evidence remains pending until R29 supplies links; macOS is
explicitly build-only and unverified. Therefore an early green manual workflow proves
candidate infrastructure, not release acceptance.

## Consequences

- Adding a publication channel does not add a Koi build or duplicate archive identity.
- JavaScript remains a disposable bridge into the native product rather than a second
  implementation surface.
- Rust users gain a no-compilation route without trusting unofficial binary mirrors.
- A tag dry run catches packaging drift before an irreversible registry publication.
- A candidate report joins exact source, hosted results and artifact identity without
  turning missing native evidence into a release claim.
- Release operation becomes safer in a shared, intentionally dirty development tree.
- WinGet and Homebrew can be added as manifest consumers once their external homes and
  lifecycle expectations are ready.
- A release candidate can ship early for exact-artifact soaking without displacing stable
  defaults; defects become a subsequent candidate rather than retroactive artifact changes.

The cost is that the manifest schema becomes a release compatibility surface. Schema
changes require explicit versioning, and activation of each external registry still
has a small one-time operational step.

## Rejected alternatives

### Publish one npm binary package per target

This commonly used pattern would create six platform packages plus a dispatcher,
seven publication identities, seven trust configurations, and another archive layout.
Koi already has official native artifacts and installers, so the extra packages add
coordination without adding capability.

### Run or register Koi directly from the npm cache

The cache is controlled by npm's execution lifecycle, not Koi's service lifecycle. A
service registration pointing there could disappear or change independently of the
OS service. Stable native placement is mandatory.

### Make `cargo install` the primary Rust channel

It remains a useful source-build escape hatch, but it transfers compilation time,
toolchain requirements, and native dependency failures to every operator. It is not
the delightful default for a released application.

### Add WinGet, Homebrew, Scoop, apt, and rpm simultaneously

Each has distinct repositories, review processes, signing, upgrade, and uninstall
expectations. Establishing the artifact contract and two thin bootstrap paths first
provides evidence and generation inputs without multiplying half-maintained channels.
