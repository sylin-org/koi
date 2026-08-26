# Packaging channel scaffolds (ADR-034 D6)

Drafts for the ratified package-manager channels, in implementation order.
**Every version string and SHA-256 here is a placeholder by design**: these
channels debut at stable `1.0.0` (prereleases do not belong in them), and
hashes are computed from the real release artifacts at release time — never
guessed (RL-2: registries are immutable; a wrong pin is forever).

| Channel | File | Fill at release with |
|---|---|---|
| Homebrew tap | [`homebrew/Formula/koi.rb`](homebrew/Formula/koi.rb) | archive URLs + sha256 per macOS/Linux target from the release manifest; push to `sylin-org/homebrew-tap` repo under `Formula/koi.rb` |
| winget | [`winget/README.md`](winget/README.md) | generate the three manifests with `wingetcreate new <installer-url>` against the signed NSIS/archive URL, then PR to `microsoft/winget-pkgs` |
| AUR | [`aur/PKGBUILD`](aur/PKGBUILD) | `pkgver=1.0.0`, sha256sums from the Linux archives; publish as `koi-bin` (or hand to a community maintainer) |
| Scoop | [`scoop/koi.json`](scoop/koi.json) | Windows archive URLs + hashes into a `sylin-org/scoops`-style bucket |

## Release-day checklist (per channel)

1. Tag → hosted release workflow produces archives + checksums + manifest + attestations.
2. Copy each artifact's exact URL and SHA-256 **from the release manifest** into the
   channel file (never re-type a hash).
3. Push/submit; record the submission in SESSION-HANDOFF.md.
4. Verify an end-to-end install (`brew install sylin/tap/koi`, `winget install ...`,
   `yay -S koi-bin`, `scoop install koi`) before flipping the landing page state
   from *planned* to *available* (ADR-025 §6 honesty states).
