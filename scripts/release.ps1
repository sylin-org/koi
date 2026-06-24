<#
.SYNOPSIS
  Tag the current Koi workspace version as a release.

.DESCRIPTION
  Reads the version `scripts/bump-version.ps1` last set (the `[workspace.package]
  version` in Cargo.toml) and creates the annotated git tag `v<version>`, then pushes
  it. Pushing a `v*` tag is what fires `.github/workflows/release.yml` (build the
  targets -> attest provenance -> GitHub Release -> GHCR image -> crates.io publish).

  Guardrails before it tags:
    - the CHANGELOG must carry a `## [<version>]` section (i.e. bump-version ran and
      the entry is stamped, not still `[Unreleased]`);
    - the tag must not already exist (locally or on the remote);
    - the working tree must be clean.

  Run it on the commit you want released. The repo's flow tags the dev->main MERGE on
  `main` (checkout main and run this, or pass -Ref <merge-sha>); -Ref defaults to HEAD.

.PARAMETER Ref
  The commit to tag (default: HEAD).
.PARAMETER Remote
  The remote to push the tag to (default: origin).
.PARAMETER NoPush
  Create the tag locally but do not push it (no release is triggered).

.EXAMPLE
  ./scripts/release.ps1            # tag v<version> at HEAD and push (cuts the release)
.EXAMPLE
  ./scripts/release.ps1 -NoPush    # create the tag locally only
.EXAMPLE
  ./scripts/release.ps1 -Ref main  # tag the tip of main
#>
[CmdletBinding()]
param(
    [string] $Ref = 'HEAD',
    [string] $Remote = 'origin',
    [switch] $NoPush
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot   # scripts/ -> repo root
Set-Location $repo

# Version bump-version last set.
$m = [regex]::Match((Get-Content -Raw 'Cargo.toml'), '(?m)^\s*version\s*=\s*"(\d+\.\d+\.\d+)"\s*$')
if (-not $m.Success) { throw 'could not find [workspace.package] version in Cargo.toml' }
$version = $m.Groups[1].Value
$tag = "v$version"

# Guard: the CHANGELOG must carry a stamped section for this version (bump-version ran).
if ((Get-Content -Raw 'CHANGELOG.md') -notmatch [regex]::Escape("## [$version]")) {
    throw "CHANGELOG.md has no '## [$version]' section - run scripts/bump-version.ps1 first."
}

# Guard: the tag must not already exist (locally or on the remote).
if (& git tag --list $tag) { throw "tag $tag already exists locally - bump the version first." }
if (& git ls-remote --tags $Remote "refs/tags/$tag") {
    throw "tag $tag already exists on $Remote - bump the version first."
}

# Guard: clean working tree.
if (& git status --porcelain) { throw 'working tree is dirty - commit or stash before tagging a release.' }

$sha = (& git rev-parse --short $Ref).Trim()
Write-Host ">> tagging $tag at $Ref ($sha)" -ForegroundColor Cyan
& git tag -a $tag $Ref -m "koi $tag"
if ($LASTEXITCODE -ne 0) { throw "git tag failed ($LASTEXITCODE)" }

if ($NoPush) {
    Write-Host ">> created $tag locally (NOT pushed). Push to release with:" -ForegroundColor Yellow
    Write-Host "   git push $Remote $tag"
    return
}

Write-Host ">> pushing $tag to $Remote (fires release.yml: build + GitHub Release + GHCR + crates.io)" -ForegroundColor Cyan
& git push $Remote $tag
if ($LASTEXITCODE -ne 0) { throw "git push of $tag failed ($LASTEXITCODE)" }
Write-Host ">> $tag pushed. Watch the run: gh run list --workflow release.yml" -ForegroundColor Green
