# winget manifests — notes for release day (ADR-034 D6)

winget-pkgs requires multi-file YAML manifests (version / installer /
defaultLocale) under `manifests/s/sylin-org/koi/<version>/`. Generate rather
than hand-write:

    winget install wingetcreate
    wingetcreate new <signed-installer-or-archive-url>

Policy checkpoints that fail validation if missed (measured against the
published policies):

- InstallerUrl must be the direct GitHub Release asset (HTTPS, no redirector).
- InstallerSha256 must match the exact bytes — take it from the release manifest.
- Silent install must work unattended: NSIS `/S`, or use the portable zip with
  `InstallerType: portable` (then `ElevationRequirement` is not needed).
- A service-installing exe needs `ElevationRequirement: elevationRequired`.
- Windows release executables are unsigned. Validate package-manager acceptance against the real
  release artifacts and do not claim an established SmartScreen reputation.

Submission is an external action: PR to microsoft/winget-pkgs, automated
validation, moderator review. Record the PR in SESSION-HANDOFF.md.
