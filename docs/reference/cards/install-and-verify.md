---
type: REF
domain: packaging
title: "Install Koi + verify the build"
audience: [operators, developers, ai-agents]
status: current
last_updated: 2026-07-19
koi_version: v1.0.0-rc.2
validation:
  date_last_tested: 2026-06-22
  status: drafted
  scope: "installer code reviewed; release-manifest generation exercised against all live v1.0.0-rc.2 archives and sidecars; npm bootstrap tests and pack smoke green; direct installer and attestation execution still require an independently live-tested release run"
---

# Install Koi + verify the build

> One-screen map of getting `koi` onto a box and proving the binary is genuine. First run, end to end: [getting-started.md](../../tutorials/getting-started.md) · supply-chain stance: [security-model.md](../security-model.md) ("Supply chain") · containers: [CONTAINERS.md](../../../CONTAINERS.md).

**What it does** — One line installs Koi. The installer **downloads** the prebuilt archive for your OS/arch from GitHub Releases (it never compiles), **verifies its SHA-256** against the published `.sha256`, drops the `koi` binary on your PATH, and finishes by running `koi status` so you never land at a blank prompt. Each release is one native build expressed as six signed archives (`x86_64`/`aarch64` × Linux-musl/macOS/Windows-msvc), a machine-readable artifact manifest, and a multi-arch container at `ghcr.io/sylin-org/koi`. Every archive, the manifest, **and** the image carry a keyless (Sigstore) **build-provenance attestation**, and the image ships an **SBOM**, so `gh attestation verify` can prove a download was built by Koi's release workflow — not a tampered mirror.

## The one canonical pattern

Install with the one-liner, then (optionally) verify provenance before you trust the binary.

```bash
# Linux / macOS:
curl -fsSL https://raw.githubusercontent.com/sylin-org/koi/main/install.sh | sh
#   koi: checksum verified
#   koi: koi v1.0.0-rc.2 installed -> ~/.local/bin/koi
#   <koi status output>

# Windows (PowerShell):
irm https://raw.githubusercontent.com/sylin-org/koi/main/install.ps1 | iex

# Container (no install): published, multi-arch, with SBOM + provenance:
docker run -d ghcr.io/sylin-org/koi:latest
```

```bash
# Verify the supply chain (optional but recommended — the installer prints this line too):
gh attestation verify koi-v1.0.0-rc.2-x86_64-unknown-linux-musl.tar.gz --repo sylin-org/koi
gh attestation verify oci://ghcr.io/sylin-org/koi:1.0.0-rc.2          --repo sylin-org/koi
```

The installer already checks the SHA-256 for integrity; `gh attestation verify` adds **authenticity** — it proves the archive (or image) came out of `release.yml` in `sylin-org/koi`, defeating a swapped binary on a mirror.

## Commands & flags you'll use

| Command / knob | What it does |
|---|---|
| `curl -fsSL .../install.sh \| sh` | Linux/macOS install (HTTPS-only; refuses an HTTP downgrade). |
| `irm .../install.ps1 \| iex` | Windows install (per-user; adds the dir to your user PATH). |
| `KOI_VERSION` (`-Version`) | Pin a release tag, e.g. `v1.0.0-rc.2`. **Default: latest release.** |
| `KOI_INSTALL_DIR` (`-InstallDir`) | Install location. **Default: `/usr/local/bin` as root, else `~/.local/bin`; Windows `%LOCALAPPDATA%\Programs\koi`.** |
| `KOI_NO_MODIFY_PATH` (`-NoModifyPath`) | Skip PATH guidance (sh) / don't touch user PATH (Windows). |
| `gh attestation verify <archive\|oci://…:VER> --repo sylin-org/koi` | Verify keyless build provenance for an archive or the image. |

## Channel availability

| Channel | State | Build behavior |
|---|---|---|
| `install.sh` / `install.ps1` | **available** | Official prebuilt archive; never compiles. |
| GitHub Release archive | **available** | Manual placement of the same official prebuilt archive. |
| GHCR image | **available** | Exact Linux release binaries, assembled without recompiling. Prereleases use the exact tag. |
| `cargo binstall koi-net --version 1.0.0-rc.1` | **available** | Official release archive only; unofficial and compile fallbacks disabled. |
| `npx @sylin-org/koi@1.0.0-rc.1` | **available** | Verifies and dispatches the native installer; never runs the service from npm's cache. |
| `cargo install koi-net` | **available escape hatch** | Builds from source locally. |

Prerelease commands are intentionally versioned and do not advance stable defaults. See
[ADR-025](../../adr/025-release-channels-and-bootstrap-contract.md) for the common artifact
contract and activation gates.

## The escape hatch

No prebuilt binary for your platform (only Linux + macOS + Windows on x86_64/aarch64 ship archives)? Build from source with `cargo install` / `cargo build --release` — there's no other dependency. Behind a proxy or air-gapped? Download the archive + its `.sha256` from the [Releases page](https://github.com/sylin-org/koi/releases) by hand, check the hash yourself, and place the binary on PATH (set `KOI_INSTALL_DIR` if you script it). The installer is **HTTPS-only** and forbids redirect-to-HTTP downgrades by design, so a plaintext mirror is rejected rather than trusted.

## The proof it works

CI and the physical Windows/Linux lab exercise the installer and archive contract before a
release. `install.sh` validates the tag, picks the OS/arch target (`detect_target`), downloads archive + `.sha256`, compares `sha256_of` vs the expected hash (`checksum verified` / hard-fail on mismatch), extracts, installs via temp-then-rename, and runs `koi status`. `install.ps1` mirrors this on Windows (arch via the WoW64/registry native-arch hint, `Get-FileHash` compare, user-PATH update). `.github/workflows/release.yml` produces the per-target archives + `.sha256` on every `v*` tag, builds and independently validates the six-target release manifest, tests and packs the npm bootstrap, signs each archive and the manifest with `actions/attest-build-provenance@v2`, and pushes the multi-arch image with `provenance: true` + `sbom: true`. Attestation and publication run **only on a real tag push**; `workflow_dispatch` builds and exercises the complete packaging contract but publishes nothing. npm publication has an additional explicit repository-variable and trusted-publisher gate.
