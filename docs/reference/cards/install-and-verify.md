---
type: REF
domain: packaging
title: "Install Koi + verify the build"
audience: [operators, developers, ai-agents]
status: current
last_updated: 2026-06-22
koi_version: v0.9.0
validation:
  date_last_tested: 2026-06-22
  status: drafted
  scope: "code-reviewed against install.sh, install.ps1, .github/workflows/release.yml, CONTAINERS.md; the scripts are exercised manually and `gh attestation verify` runs only against a real tag's published artifacts — not independently live-tested"
---

# Install Koi + verify the build

> One-screen map of getting `koi` onto a box and proving the binary is genuine. First run, end to end: [getting-started.md](../../tutorials/getting-started.md) · supply-chain stance: [security-model.md](../security-model.md) ("Supply chain") · containers: [CONTAINERS.md](../../../CONTAINERS.md).

**What it does** — One line installs Koi. The installer **downloads** the prebuilt archive for your OS/arch from GitHub Releases (it never compiles), **verifies its SHA-256** against the published `.sha256`, drops the `koi` binary on your PATH, and finishes by running `koi status` so you never land at a blank prompt. There is no apt/brew repo and no build step — just a signed archive per target (`x86_64`/`aarch64` × Linux-musl/macOS/Windows-msvc) plus a multi-arch container at `ghcr.io/sylin-org/koi`. Every archive **and** the image carry a keyless (Sigstore) **build-provenance attestation**, and the image ships an **SBOM**, so `gh attestation verify` can prove a download was built by Koi's release workflow — not a tampered mirror.

## The one canonical pattern

Install with the one-liner, then (optionally) verify provenance before you trust the binary.

```bash
# Linux / macOS:
curl -fsSL https://raw.githubusercontent.com/sylin-org/koi/main/install.sh | sh
#   koi: checksum verified
#   koi: koi v0.9.0 installed -> ~/.local/bin/koi
#   <koi status output>

# Windows (PowerShell):
irm https://raw.githubusercontent.com/sylin-org/koi/main/install.ps1 | iex

# Container (no install): published, multi-arch, with SBOM + provenance:
docker run -d ghcr.io/sylin-org/koi:latest
```

```bash
# Verify the supply chain (optional but recommended — the installer prints this line too):
gh attestation verify koi-v0.9.0-x86_64-unknown-linux-musl.tar.gz --repo sylin-org/koi
gh attestation verify oci://ghcr.io/sylin-org/koi:0.9.0          --repo sylin-org/koi
```

The installer already checks the SHA-256 for integrity; `gh attestation verify` adds **authenticity** — it proves the archive (or image) came out of `release.yml` in `sylin-org/koi`, defeating a swapped binary on a mirror.

## Commands & flags you'll use

| Command / knob | What it does |
|---|---|
| `curl -fsSL .../install.sh \| sh` | Linux/macOS install (HTTPS-only; refuses an HTTP downgrade). |
| `irm .../install.ps1 \| iex` | Windows install (per-user; adds the dir to your user PATH). |
| `KOI_VERSION` (`-Version`) | Pin a release tag, e.g. `v0.9.0`. **Default: latest release.** |
| `KOI_INSTALL_DIR` (`-InstallDir`) | Install location. **Default: `/usr/local/bin` as root, else `~/.local/bin`; Windows `%LOCALAPPDATA%\Programs\koi`.** |
| `KOI_NO_MODIFY_PATH` (`-NoModifyPath`) | Skip PATH guidance (sh) / don't touch user PATH (Windows). |
| `gh attestation verify <archive\|oci://…:VER> --repo sylin-org/koi` | Verify keyless build provenance for an archive or the image. |

## The escape hatch

No prebuilt binary for your platform (only Linux + macOS + Windows on x86_64/aarch64 ship archives)? Build from source with `cargo install` / `cargo build --release` — there's no other dependency. Behind a proxy or air-gapped? Download the archive + its `.sha256` from the [Releases page](https://github.com/sylin-org/koi/releases) by hand, check the hash yourself, and place the binary on PATH (set `KOI_INSTALL_DIR` if you script it). The installer is **HTTPS-only** and forbids redirect-to-HTTP downgrades by design, so a plaintext mirror is rejected rather than trusted.

## The proof it works

Code-reviewed, not independently live-tested. `install.sh` validates the tag, picks the OS/arch target (`detect_target`), downloads archive + `.sha256`, compares `sha256_of` vs the expected hash (`checksum verified` / hard-fail on mismatch), extracts, installs via temp-then-rename, and runs `koi status`. `install.ps1` mirrors this on Windows (arch via the WoW64/registry native-arch hint, `Get-FileHash` compare, user-PATH update). `.github/workflows/release.yml` produces the per-target archives + `.sha256` on every `v*` tag, signs each `*.tar.gz`/`*.zip` with `actions/attest-build-provenance@v2`, and the `docker` job pushes the multi-arch image with `provenance: true` + `sbom: true` and a pushed image attestation — which is exactly what `gh attestation verify` consumes. Attestation runs **only on a real tag push** (the `release`/`docker` jobs are gated on `refs/tags/`); `workflow_dispatch` is a build-only dry run that publishes nothing.
