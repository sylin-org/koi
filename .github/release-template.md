${DESCRIPTION}

## Install

**One line** — detects your OS/arch, verifies the checksum, installs onto `PATH`:

```bash
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/sylin-org/koi/main/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/sylin-org/koi/main/install.ps1 | iex
```

**Container** — multi-arch image on GHCR:

```bash
docker run --rm ghcr.io/sylin-org/koi:${VERSION_NO_V} version
```

**Or download a binary** from the table below, extract, and place on your `PATH`.
**Or via crates.io:** `cargo install koi-net`.
**Or build from source:** `git clone https://github.com/sylin-org/koi && cd koi && cargo build --release`.

**Then, for always-on discovery, install as a system service:**

```bash
sudo koi install   # Linux / macOS
koi install        # Windows (Administrator)
```

## Downloads

| Platform | Architecture | Download |
|----------|-------------|----------|
| Linux | x86_64 | `koi-${VERSION}-x86_64-unknown-linux-musl.tar.gz` |
| Linux | aarch64 | `koi-${VERSION}-aarch64-unknown-linux-musl.tar.gz` |
| macOS | Intel | `koi-${VERSION}-x86_64-apple-darwin.tar.gz` |
| macOS | Apple Silicon | `koi-${VERSION}-aarch64-apple-darwin.tar.gz` |
| Windows | x86_64 | `koi-${VERSION}-x86_64-pc-windows-msvc.zip` |
| Windows | aarch64 | `koi-${VERSION}-aarch64-pc-windows-msvc.zip` |

## Verify

Every archive **and** the container image carry a signed build-provenance
attestation (GitHub Artifact Attestations / Sigstore). Prove an artifact was built
by this repo's release workflow — not a mirror or a tampered copy:

```bash
# a downloaded binary archive
gh attestation verify koi-${VERSION}-x86_64-unknown-linux-musl.tar.gz --repo sylin-org/koi

# the container image
gh attestation verify oci://ghcr.io/sylin-org/koi:${VERSION_NO_V} --repo sylin-org/koi
```

(The install scripts verify the SHA-256 below automatically; the attestation is the
stronger, signed check.)

## Checksums (SHA-256)

```
${CHECKSUMS}
```
