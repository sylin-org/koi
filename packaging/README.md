# Distribution packaging

This directory contains release-channel recipes and templates. A file here does not establish that its channel is published or that installation works. [Launch readiness](../docs/launch/README.md) lists available entry points and the scenario evidence required before promotion.

The preview prioritizes one reproducible installation path for Windows x64/Docker Desktop and Linux glibc x64/Docker Engine. Existing build targets remain governed by repository support policy; adding package-manager entries is not a prerequisite for proving the container/second-device journey.

| Recipe | Purpose |
| --- | --- |
| [Homebrew formula](homebrew/Formula/koi.rb) | Tap recipe requiring real artifact URLs/hashes |
| [winget notes](winget/README.md) | Windows manifest generation/submission workflow |
| [AUR recipe](aur/PKGBUILD) | Linux binary package recipe |
| [Scoop manifest](scoop/koi.json) | Windows archive package metadata |
| [Alpine APKBUILD](alpine/APKBUILD) | Native Alpine/OpenRC packaging source |

## Promote a channel

1. Select the exact accepted source and release artifact; confirm the repository's version/channel policy.
2. Populate URLs, versions and SHA-256 values from real release metadata. Reject placeholder or mismatched values.
3. Validate with the channel's current tooling and submit/publish through the approved release process.
4. Confirm registry availability and perform a clean installation from that public entry point.
5. Exercise the intended installed-service/application journey and record source, package/artifact identity, result and cleanup in [the launch ledger](../fleet/launch/LEDGER.md).

Do not advertise an installation command before those facts exist. Packaging checks and provenance attestations establish different facts from native service acceptance. Keep operator selection explicit where installation cannot recover the interactive user's identity; never make a package guess or publish a daemon token.
