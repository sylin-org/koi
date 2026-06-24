<#
.SYNOPSIS
  Bump the Koi workspace version everywhere, then commit + push, in one shot.

.DESCRIPTION
  The mechanical half of a release version bump:
    - Cargo: the `[workspace.package] version` and every `=X` inter-crate pin
    - Cargo.lock: refreshed to the new member versions (external deps held)
    - CHANGELOG: stamps `## [Unreleased]` -> `## [<version>] - <date>`
    - Docs: the current-version strings in the SHIPPED docs only —
      capability-card `koi_version:` frontmatter, the install / `gh attestation`
      examples, the `koi-embedded = "X.Y"` dependency recipes, the `koi status`
      sample, the http-api `version` field, and the CLI `KOI_VERSION` example.

  It then **commits ALL working-tree changes** as `chore(release): prep <version>`
  (the commit body is pulled from the CHANGELOG section) and **pushes**.

  It deliberately does NOT touch historical version references (past CHANGELOG
  entries, past `upgrading.md` sections, ADRs, `SURFACES.md` shipped-markers,
  docs/assessment, docs/prompts) — only the curated current-version surfaces.

  Per-release PROSE is yours to write, and because the commit sweeps the whole tree
  you should write it BEFORE running so it lands in the release commit: the CHANGELOG
  `[Unreleased]` entry body, a `The <version> upgrade` section in
  docs/guides/upgrading.md, and the README "latest release" blurb. Use -NoCommit to
  do the mechanical bump only and review first.

.PARAMETER NewVersion
  The new semver version, e.g. 0.9.0. OPTIONAL — if omitted, the minor version is
  auto-incremented and the patch reset to 0 (0.8.0 -> 0.9.0 -> 0.10.0).
.PARAMETER Date
  CHANGELOG release date (default: today, yyyy-MM-dd).
.PARAMETER SkipLock
  Skip the `cargo update --workspace` Cargo.lock refresh.
.PARAMETER NoCommit
  Do the mechanical bump only — do not commit or push.
.PARAMETER NoPush
  Commit, but do not push.

.EXAMPLE
  ./scripts/bump-version.ps1          # auto: bump the minor (e.g. 0.8.0 -> 0.9.0), commit + push
.EXAMPLE
  ./scripts/bump-version.ps1 1.0.0    # an explicit version (e.g. a major bump)
.EXAMPLE
  ./scripts/bump-version.ps1 -NoCommit  # mechanical bump only, review before committing
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string] $NewVersion,
    [string] $Date = (Get-Date -Format 'yyyy-MM-dd'),
    [switch] $SkipLock,
    [switch] $NoCommit,
    [switch] $NoPush
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot   # scripts/ -> repo root
Set-Location $repo

# Current workspace version (the single source of truth for what we're bumping FROM).
$cargoText = Get-Content -Raw 'Cargo.toml'
$m = [regex]::Match($cargoText, '(?m)^\s*version\s*=\s*"(\d+\.\d+\.\d+)"\s*$')
if (-not $m.Success) { throw 'could not find [workspace.package] version in Cargo.toml' }
$Old = $m.Groups[1].Value

# No version given -> auto-increment the minor, reset the patch (0.8.0 -> 0.9.0 -> 0.10.0).
if (-not $NewVersion) {
    $p = $Old -split '\.'
    $NewVersion = '{0}.{1}.0' -f $p[0], ([int]$p[1] + 1)
    Write-Host ">> no version given - auto-incrementing minor" -ForegroundColor Cyan
}

if ($NewVersion -notmatch '^\d+\.\d+\.\d+$') { throw "version must be X.Y.Z, got '$NewVersion'" }
if ($Old -eq $NewVersion) { Write-Host "Already at $NewVersion - nothing to do."; exit 0 }
$NewMinor = ($NewVersion -split '\.')[0, 1] -join '.'
Write-Host ">> bump $Old -> $NewVersion  (dependency recipes -> $NewMinor)" -ForegroundColor Cyan

$script:total = 0
function Swap($path, $from, $to) {
    if (-not (Test-Path $path)) { Write-Warning "missing: $path"; return }
    $c = Get-Content -Raw $path
    if (-not $c.Contains($from)) { return }
    $cnt = ([regex]::Matches($c, [regex]::Escape($from))).Count
    [System.IO.File]::WriteAllText((Convert-Path $path), $c.Replace($from, $to))
    Write-Host ("   {0,-42} {1}x  {2} -> {3}" -f $path, $cnt, $from, $to)
    $script:total += $cnt
}
function SwapRegex($path, $pattern, $replacement) {
    if (-not (Test-Path $path)) { Write-Warning "missing: $path"; return }
    $c = Get-Content -Raw $path
    $cnt = ([regex]::Matches($c, $pattern)).Count
    if ($cnt -eq 0) { return }
    [System.IO.File]::WriteAllText((Convert-Path $path), [regex]::Replace($c, $pattern, $replacement))
    Write-Host ("   {0,-42} {1}x  /{2}/ -> {3}" -f $path, $cnt, $pattern, $replacement)
    $script:total += $cnt
}

# 1) Cargo.toml: workspace version + the inter-crate `=X` pins.
Swap 'Cargo.toml' "version = `"$Old`"" "version = `"$NewVersion`""
Swap 'Cargo.toml' "version = `"=$Old`"" "version = `"=$NewVersion`""

# 2) CHANGELOG: stamp the Unreleased section (author the body first).
if ((Get-Content -Raw 'CHANGELOG.md') -match '(?m)^##\s*\[Unreleased\]') {
    Swap 'CHANGELOG.md' '## [Unreleased]' "## [$NewVersion] - $Date"
}
else {
    Write-Warning "CHANGELOG.md has no '## [Unreleased]' header - add the entry, then stamp it by hand."
}

# 3) Capability cards: koi_version frontmatter.
Get-ChildItem 'docs/reference/cards' -Filter '*.md' | ForEach-Object {
    Swap $_.FullName "koi_version: v$Old" "koi_version: v$NewVersion"
}

# 4) Install / attestation / status / api version strings (current-version-only files).
Swap 'docs/reference/cards/install-and-verify.md' "v$Old" "v$NewVersion"
Swap 'docs/reference/cards/install-and-verify.md' ":$Old" ":$NewVersion"
Swap 'README.md' "koi-v$Old" "koi-v$NewVersion"
Swap 'README.md' "ghcr.io/sylin-org/koi:$Old" "ghcr.io/sylin-org/koi:$NewVersion"
Swap 'docs/guides/install-and-service.md' "v$Old" "v$NewVersion"
Swap 'docs/guides/mdns.md' "Koi v$Old" "Koi v$NewVersion"
Swap 'docs/reference/cli.md' "v$Old" "v$NewVersion"
Swap 'docs/reference/http-api.md' "`"version`": `"$Old`"" "`"version`": `"$NewVersion`""

# 5) `koi-embedded = "X.Y"` dependency recipes (any current minor -> new minor; also
#    heals a recipe left stale by an earlier release).
foreach ($f in @('README.md', 'docs/guides/embedded.md')) {
    SwapRegex $f '(?<=koi-embedded = ")\d+\.\d+(?=")' $NewMinor
    SwapRegex $f '(?<=koi-embedded = \{ version = ")\d+\.\d+(?=")' $NewMinor
}

# 6) Cargo.lock: refresh the workspace member versions (holds external deps).
if (-not $SkipLock) {
    Write-Host ">> cargo update --workspace (refresh Cargo.lock)" -ForegroundColor Cyan
    & cargo update --workspace
    if ($LASTEXITCODE -ne 0) { throw "cargo update --workspace failed ($LASTEXITCODE)" }
}

Write-Host ""
Write-Host ">> mechanical bump done: $($script:total) version string(s) + Cargo + Cargo.lock." -ForegroundColor Green

if ($NoCommit) {
    Write-Host ">> -NoCommit: not committing. Author the prose (if you haven't), then commit + push:" -ForegroundColor Yellow
    Write-Host "     CHANGELOG [$NewVersion] body / docs/guides/upgrading.md 'The $NewVersion upgrade' / README blurb"
    return
}

# 7) Commit ALL working-tree changes (the bump + whatever release prose you wrote first)
#    and push. The commit body is the CHANGELOG section's lead paragraph.
if (-not (& git status --porcelain)) { Write-Host ">> nothing to commit (tree clean)."; return }

$summary = "See CHANGELOG.md [$NewVersion]."
$sec = [regex]::Match((Get-Content -Raw 'CHANGELOG.md'),
    "(?ms)^##\s*\[$([regex]::Escape($NewVersion))\][^\n]*\n+(.+?)(?=\n##\s|\Z)")
if ($sec.Success) {
    $lead = (($sec.Groups[1].Value.Trim()) -split '(?:\r?\n){2,}')[0].Trim()
    if ($lead) { $summary = "$lead`n`nSee CHANGELOG.md [$NewVersion]." }
}

Write-Host ">> committing all changes  (chore(release): prep $NewVersion)" -ForegroundColor Cyan
& git add -A
& git status --short
& git commit -q -m "chore(release): prep $NewVersion" -m $summary
if ($LASTEXITCODE -ne 0) { throw "git commit failed ($LASTEXITCODE)" }

if ($NoPush) {
    Write-Host ">> committed; NOT pushed (-NoPush). Push with: git push" -ForegroundColor Yellow
    return
}
Write-Host ">> pushing..." -ForegroundColor Cyan
& git push
if ($LASTEXITCODE -ne 0) { throw "git push failed ($LASTEXITCODE) - resolve and push manually" }
Write-Host ">> prep $NewVersion committed + pushed.  Cut the release: scripts/release.ps1" -ForegroundColor Green
