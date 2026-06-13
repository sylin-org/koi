# P02 — CI & Release Truth Pass

> Paste this entire file as the task for a fresh agent session in the Koi repo.
> Size: M · Prereqs: none · Read `docs/prompts/CHARTER.md` first and follow its
> session protocol.

## Mission

The release machinery currently lies: the weekly QA workflow has failed every run for
months (it invokes shell scripts deleted in February), and crates.io publishing reports
green while silently failing (missing `pipefail` makes the error handler dead code; the
publish list omits three crates that published crates depend on; `koi-net` has been
stale on crates.io since Feb 12 while lib crates moved on — making the documented
`cargo install koi-net` a trap). Replace decayed automation with a small set of honest,
watchable pipelines, and reset versioning to plain pre-1.0 SemVer.

## Load context first

1. `docs/prompts/CHARTER.md`
2. `docs/assessment/findings/verification-2026-06.md` — claims 4 and 5 (re-verify).
3. `.github/workflows/ci.yml`, `qa.yml`, `release.yml`; `build.ps1`; `version.json`;
   `tests/` (only `integration.ps1` + `concurrency.ps1` exist); workspace `Cargo.toml`.

## Research phase

- Confirm: which qa.yml jobs reference `tests/integration.sh` / `concurrency.sh`
  (expect lines ~21, 43, 65, 76, 87) vs the three Windows jobs that reference real
  files.
- Confirm: the publish step has no `shell:` key → GitHub Actions default `bash -e {0}`
  (no pipefail) → `cargo publish | tee` masks failures. Confirm the `CRATES` list
  (~lines 218–231) omits `koi-udp`, `koi-runtime`, `command-surface` while
  `crates/koi/Cargo.toml` and `koi-embedded` depend on them.
- Confirm release.yml triggers on every push to main and deletes/re-creates tags
  (~lines 189–196), and that `build.ps1` mutates the workspace version with a wall-clock
  timestamp.
- Check whether pwsh is available on ubuntu/macos GitHub runners (it is) — the .sh
  twins were never necessary.

## Target experience (north star)

```
# A release is a deliberate act:
$ git tag v0.3.0 && git push --tags        # ← the ONLY thing that builds a release
# CI on every push/PR: build + test (3 OS) + clippy -D warnings + fmt + MSRV + audit
# QA weekly: only jobs that can actually pass; failures notify, not rot
# CHANGELOG.md: Keep-a-Changelog format, one entry per tag
```

Versioning: replace `0.2.YYYYMMDDHHMM` with `0.3.0` (workspace + all internal dep
requirements pinned `=0.3.0` or `0.3` consistently — pick one and say why in the plan).
`build.ps1` stops mutating Cargo.toml; `version.json` is deleted or reduced to a build
metadata artifact. Publishing: **suspend the 12-crate pipeline** — keep a
`workflow_dispatch`-only publish job, fixed (pipefail set explicitly, complete
dependency-ordered crate list including the three missing crates, post-publish
verification step that queries crates.io and fails loudly on mismatch). Do not run it;
launching is a later decision. Update README's install section to point at GitHub
Releases instead of `cargo install koi-net` until publishing resumes.

## Plan, then implement

Plan per charter. Keep changes reviewable: (1) qa.yml fix, (2) release trigger +
version reset, (3) publish-job repair + suspension, (4) CI additions (MSRV check via a
pinned-toolchain job, `cargo-audit` or `cargo-deny` job, Dependabot config),
(5) CHANGELOG.md seeded with an honest 0.3.0 entry summarizing the security overhaul
and consolidation, (6) README install-section truth.

## Acceptance criteria

- [ ] qa.yml contains zero references to nonexistent files; remaining jobs either run
      `pwsh` cross-platform or are Windows-only by declaration.
- [ ] release.yml triggers on tag push only; no tag deletion/re-creation remains.
- [ ] Publish job: explicit `set -euo pipefail`, complete CRATES list (15 or a
      deliberate binary-only subset — document the choice), post-publish verification,
      `workflow_dispatch` only.
- [ ] Workspace version is `0.3.0`; no timestamp-version machinery remains; CHANGELOG.md
      exists and explains the versioning reset.
- [ ] New CI jobs: MSRV check (rust 1.92 toolchain build), cargo-audit/deny, Dependabot
      config present.
- [ ] README install instructions no longer recommend the broken `cargo install koi-net`
      path.
- [ ] `gh workflow list` / `act`-style dry validation: every workflow parses
      (`gh workflow view` or YAML lint), and `cargo build --locked` still succeeds.

## Verification

`cargo check && cargo test && cargo clippy -- -D warnings && cargo fmt --check`; YAML
validity for all three workflows; grep proves no `integration.sh` references and no
timestamp-version writes remain.

## Do NOT

- Actually publish anything to crates.io or push tags.
- Port the 3,496-line integration.ps1 to Rust (separate effort; out of scope).
- Add signing/SLSA/packaging — launch-stage work, not truth-stage.
