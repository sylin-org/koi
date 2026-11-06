${DESCRIPTION}

## Use this release

Koi helps container/LAN operators make a container application discoverable and
usable from another computer, with accurate state as it changes. Use the
[readiness and supported scenarios for this tag](https://github.com/sylin-org/koi/blob/${VERSION}/docs/launch/README.md)
to determine which workflows this artifact actually proves.

Do not infer trusted service-name HTTPS, a particular browser/runtime, or an
installation channel from the existence of an archive.

## Install this exact version

Linux or macOS:

    curl -fsSL https://raw.githubusercontent.com/sylin-org/koi/${VERSION}/install.sh | KOI_VERSION=${VERSION} sh

Windows PowerShell:

    $env:KOI_VERSION='${VERSION}'
    irm https://raw.githubusercontent.com/sylin-org/koi/${VERSION}/install.ps1 | iex

These scripts select this release's native archive and verify its checksum.
Follow the [tagged quickstart](https://github.com/sylin-org/koi/blob/${VERSION}/docs/tutorials/getting-started.md)
for the intended daemon/service setup and actual second-device task.

Alternatively download the archive for your platform, verify it and follow the
same tagged instructions. For a source build from crates.io, select the version:

    cargo install koi-net --version ${VERSION_NO_V} --locked

The container image can verify its version:

    docker run --rm ghcr.io/sylin-org/koi:${VERSION_NO_V} version

Running that command does not establish native LAN multicast access. Follow the
[tagged container guide](https://github.com/sylin-org/koi/blob/${VERSION}/CONTAINERS.md).

## Archives

| Platform | Architecture | Archive |
| --- | --- | --- |
| Linux | x86_64 | koi-${VERSION}-x86_64-unknown-linux-musl.tar.gz |
| Linux | aarch64 | koi-${VERSION}-aarch64-unknown-linux-musl.tar.gz |
| macOS | Intel | koi-${VERSION}-x86_64-apple-darwin.tar.gz |
| macOS | Apple Silicon | koi-${VERSION}-aarch64-apple-darwin.tar.gz |
| Windows | x86_64 | koi-${VERSION}-x86_64-pc-windows-msvc.zip |
| Windows | aarch64 | koi-${VERSION}-aarch64-pc-windows-msvc.zip |

Archive availability and the tested container/client scenario matrix are separate
facts. Read this tag's readiness page before choosing a deployment.

## Verify and operate

Verify GitHub build provenance for a downloaded archive or container:

    gh attestation verify koi-${VERSION}-x86_64-unknown-linux-musl.tar.gz --repo sylin-org/koi
    gh attestation verify oci://ghcr.io/sylin-org/koi:${VERSION_NO_V} --repo sylin-org/koi

Windows executables are unsigned unless this release explicitly states otherwise;
a checksum and build attestation do not constitute OS code signing.

Read [upgrade/recovery instructions](https://github.com/sylin-org/koi/blob/${VERSION}/docs/guides/upgrading.md)
and [security limits](https://github.com/sylin-org/koi/blob/${VERSION}/SECURITY.md).
Report the version, OS/runtime/client and sanitized reproduction for a problem.

## Checksums (SHA-256)

```
${CHECKSUMS}
```
