# Code signing policy

Koi publishes release artifacts from the [`sylin-org/koi`](https://github.com/sylin-org/koi)
repository. Windows release archives may contain an Authenticode-signed `koi.exe`. The signature
identifies the publisher as **SignPath Foundation**; it does not change Koi's Apache-2.0 OR MIT
license or transfer project ownership.

Free code signing provided by [SignPath.io](https://about.signpath.io/), certificate by
[SignPath Foundation](https://signpath.org/).

## Signed artifacts

- Windows x86_64 and arm64 `koi.exe` release binaries built by the GitHub Actions release workflow.
- Release checksums and GitHub build-provenance attestations are generated after signing, so they
  describe the exact bytes published in the release.
- Linux, macOS, container, crates.io, and npm artifacts are outside this Authenticode policy.

Until the SignPath subscription is active, release notes identify Windows archives as unsigned.
Once repository variable `SIGNPATH_ENABLED` is `true`, the release workflow fails rather than
publishing an unsigned Windows archive.

## Team roles

- Author, committer, and reviewer: [Leo Botinelly (`@lbotinelly`)](https://github.com/lbotinelly).
  Contributions from people without commit access require review before they are merged.
- Signing approver: [Leo Botinelly (`@lbotinelly`)](https://github.com/lbotinelly).

Everyone assigned a signing role must use multi-factor authentication for both GitHub and
SignPath. Every signing request requires manual approval in SignPath.

## Build and release controls

1. GitHub-hosted runners build `koi.exe` from the tagged repository source.
2. The workflow uploads the unsigned executables as a GitHub Actions artifact and submits that
   artifact to SignPath's GitHub trusted-build connector.
3. SignPath enforces the Koi product name, version, company, copyright, and original filename,
   then applies Authenticode signatures after manual approval.
4. The workflow verifies both signatures and metadata before creating the Windows archives.
5. The workflow generates checksums, the release manifest, and GitHub provenance attestations from
   the finalized archives before publishing them.

The release workflow and its build scripts are part of the reviewed source. Signing credentials
are stored as GitHub Actions secrets and are available only to the signing step.

Signing uses secret `SIGNPATH_API_TOKEN`; variables `SIGNPATH_ORGANIZATION_ID`,
`SIGNPATH_PROJECT_SLUG`, `SIGNPATH_SIGNING_POLICY_SLUG`, and
`SIGNPATH_ARTIFACT_CONFIGURATION_SLUG`; and the checked-in
[`signpath-artifact-configuration.xml`](docs/release/signpath-artifact-configuration.xml). Set
`SIGNPATH_ENABLED` to `true` only after the SignPath project, policy, and artifact configuration are
active.

## Privacy and network behavior

Koi communicates with devices and services on the local or private networks selected by the person
running it. Discovery, DNS, certificate enrollment, health checks, proxying, MCP, and integration
surfaces can send or receive network traffic when they are explicitly invoked or configured. Koi
does not transfer information to Sylin or to a Sylin-operated service. A configured third-party
resolver, registry, proxy, container runtime, or other integration follows that service's own
privacy policy.

See the [security model](docs/reference/security-model.md) and the relevant capability guide for
the precise trust and network boundary.

## System changes and removal

Running `koi` directly does not require a system installation. Optional administrative commands can
install a background service, add local trust material, configure `.internal` name resolution, or
create a Windows Firewall rule. Koi reports these changes as part of the requested operation.

The [installation and service guide](docs/guides/install-and-service.md) documents prerequisites,
every supported system integration, data locations, and the matching uninstall/removal commands.

## Verification

On Windows, inspect a downloaded executable with PowerShell:

```powershell
Get-AuthenticodeSignature .\koi.exe | Format-List Status, StatusMessage, SignerCertificate
(Get-Item .\koi.exe).VersionInfo | Format-List ProductName, ProductVersion, FileVersion, CompanyName
```

A signed release must report a valid signature whose certificate subject identifies SignPath
Foundation, `ProductName` equal to `Koi`, and version metadata matching the release.
