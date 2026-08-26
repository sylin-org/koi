# sylin.org Koi landing page — draft (ADR-034 D2)

`index.html` is the ready-to-serve draft for the operator's Koi page. Static,
dependency-free, no build step; visual tokens match the workbench (ground
`#0f0e12`, accent `#60a5fa`, light `#93c5fd`).

## Hosting contract

Canonical paths on the operator's site (ADR-034 D2):

- `<koi-page>/`            → `index.html`
- `<koi-page>/install.sh`  → copy of the repo-root `install.sh`
- `<koi-page>/install.ps1` → copy of the repo-root `install.ps1`

Sync rule: the served scripts must be byte-identical to a tagged release's
scripts, or a 302 to
`https://raw.githubusercontent.com/sylin-org/koi/<tag>/<file>` so they can
never drift from the release manifest (which pins their SHA-256 digests).
Prefer the redirect: one source of truth, no sync job.

The page's commands assume those canonical paths. If the page lives at a
different path than the scripts, adjust the two `cmd-*` code lines.

## Channel states on the page follow ADR-025 §6

- **available** — verified and publicly installable now.
- **prepared** — merged and exercised, registry not activated (npm today).
- **planned** — needs engineering or operational ownership (brew/winget/AUR/
  Scoop/Nix today).

Flip a state only after the channel is independently verified end to end.
