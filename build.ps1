<#
.SYNOPSIS
    Build Koi from the workspace SemVer version, for the host or a named target.

.DESCRIPTION
    Reads the version from Cargo.toml [workspace.package] and builds the `koi`
    binary.

    Default (no -Target): builds for the host (release by default), runs the test
    suite (certmesh single-threaded, then the rest of the workspace), and copies the
    binary to dist/.

    With -Target <triple>: cross/target build that MIRRORS the release pipeline
    (.github/workflows/release.yml). Linux-musl targets build via `cross` (Docker);
    macOS/Windows targets build natively with `cargo build --target`. Uses --locked,
    skips the test gate (a foreign binary can't run on the build host), and copies the
    binary to dist/<triple>/. Run `build.ps1` without -Target for the test run.

    Cargo.toml is never modified; the version is plain SemVer (see CHANGELOG.md).

.PARAMETER Target
    Rust target triple to build for. One of the release matrix targets (see -List).
    Omit to build for the host.

.PARAMETER DebugBuild
    Build debug binaries instead of release.

.PARAMETER SkipTests
    Skip running tests (host build only; -Target builds never run tests).

.PARAMETER List
    List the supported target triples and exit.

.EXAMPLE
    .\build.ps1
    Build the host release binary and run tests.

.EXAMPLE
    .\build.ps1 -Target x86_64-unknown-linux-musl
    Cross-build the Linux x86_64 (musl, static) release binary via `cross`.

.EXAMPLE
    .\build.ps1 -List
    Show the supported target triples.
#>

[CmdletBinding()]
param(
    [string]$Target,
    [switch]$DebugBuild,
    [switch]$SkipTests,
    [switch]$List
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = $PSScriptRoot

# Supported targets — mirrors the build matrix in .github/workflows/release.yml.
# UseCross: build via `cross` (Docker) so the aws-lc-sys C deps cross-compile cleanly.
# Os:       the platform the release pipeline builds this target on.
$Targets = [ordered]@{
    'x86_64-unknown-linux-musl'  = @{ UseCross = $true;  Os = 'linux'   }
    'aarch64-unknown-linux-musl' = @{ UseCross = $true;  Os = 'linux'   }
    'x86_64-apple-darwin'        = @{ UseCross = $false; Os = 'macos'   }
    'aarch64-apple-darwin'       = @{ UseCross = $false; Os = 'macos'   }
    'x86_64-pc-windows-msvc'     = @{ UseCross = $false; Os = 'windows' }
    'aarch64-pc-windows-msvc'    = @{ UseCross = $false; Os = 'windows' }
}

if ($List) {
    Write-Host ""
    Write-Host "  Supported targets (mirrors release.yml):" -ForegroundColor Cyan
    foreach ($t in $Targets.Keys) {
        $how = if ($Targets[$t].UseCross) { "cross (Docker)" } else { "cargo --target" }
        Write-Host ("    {0,-30} {1}" -f $t, $how)
    }
    Write-Host ""
    Write-Host "  Usage: .\build.ps1 -Target <triple>   (omit -Target to build for the host + run tests)"
    Write-Host ""
    exit 0
}

function Test-Cmd([string]$Name) {
    [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

# Read version from Cargo.toml
$cargoToml = Join-Path $Root "Cargo.toml"
$content = Get-Content $cargoToml -Raw
if ($content -match '\[workspace\.package\][\s\S]*?version\s*=\s*"([^"]+)"') {
    $version = $Matches[1]
} else {
    throw "Could not parse version from Cargo.toml [workspace.package]"
}

if (-not (Test-Cmd 'cargo')) {
    throw "cargo not found on PATH. Install Rust (https://rustup.rs)."
}

$targetDir = if ($DebugBuild) { "debug" } else { "release" }

$IsWin = ($IsWindows -eq $true) -or ($env:OS -eq 'Windows_NT')

# ── Host build (default) ───────────────────────────────────────────────────────
if (-not $Target) {
    Write-Host ""
    Write-Host "  Building Koi $version (host)" -ForegroundColor Cyan
    Write-Host ""

    $buildArgs = @('build')
    if (-not $DebugBuild) { $buildArgs += '--release' }
    cargo @buildArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "  BUILD FAILED" -ForegroundColor Red
        exit $LASTEXITCODE
    }

    if (-not $SkipTests) {
        Write-Host ""
        Write-Host "  Running tests..." -ForegroundColor Cyan
        Write-Host ""

        $cmTestArgs = @('test')
        if (-not $DebugBuild) { $cmTestArgs += '--release' }
        $cmTestArgs += @('-p', 'koi-certmesh', '--', '--test-threads=1')
        cargo @cmTestArgs
        if ($LASTEXITCODE -ne 0) { throw "Certmesh tests failed." }
        $wsTestArgs = @('test')
        if (-not $DebugBuild) { $wsTestArgs += '--release' }
        $wsTestArgs += @('--workspace', '--exclude', 'koi-certmesh')
        cargo @wsTestArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Host ""
            Write-Host "  TESTS FAILED" -ForegroundColor Red
            exit $LASTEXITCODE
        }
    }

    $distDir = Join-Path $Root "dist"
    if (-not (Test-Path $distDir)) { New-Item -ItemType Directory -Path $distDir | Out-Null }

    $binName = if ($IsWin) { "koi.exe" } else { "koi" }
    $binary = Join-Path $Root "target" $targetDir $binName
    Copy-Item $binary (Join-Path $distDir $binName) -Force

    Write-Host ""
    Write-Host "  Build complete." -ForegroundColor Green
    Write-Host "  Binary:  dist\$binName"
    Write-Host "  Version: $version"
    Write-Host ""
    exit 0
}

# ── Target build (cross / cargo --target) ──────────────────────────────────────
if (-not $Targets.Contains($Target)) {
    Write-Host ""
    Write-Host "  Unsupported target: $Target" -ForegroundColor Red
    Write-Host "  Run '.\build.ps1 -List' for supported targets." -ForegroundColor Yellow
    exit 1
}

$spec = $Targets[$Target]

if ($spec.UseCross) {
    if (-not (Test-Cmd 'cross')) {
        throw "Target '$Target' needs 'cross'. Install: cargo install cross --locked  (requires Docker or Podman)."
    }
    if (-not (Test-Cmd 'docker') -and -not (Test-Cmd 'podman')) {
        throw "'cross' needs a container engine (Docker or Podman) on PATH to build '$Target'."
    }
    $tool = 'cross'
} else {
    $tool = 'cargo'
    if (Test-Cmd 'rustup') {
        Write-Host "  Ensuring rustup target '$Target' is installed..." -ForegroundColor DarkGray
        rustup target add $Target | Out-Null
    }
    $curOs = if ($IsWin) { 'windows' } elseif ($IsMacOS) { 'macos' } else { 'linux' }
    if ($spec.Os -ne $curOs) {
        Write-Warning "Target '$Target' is built on $($spec.Os) in the release pipeline; building on $curOs may fail without a matching cross toolchain."
    }
}

Write-Host ""
Write-Host "  Building Koi $version for $Target via $tool" -ForegroundColor Cyan
Write-Host ""

$cargoArgs = @('build')
if (-not $DebugBuild) { $cargoArgs += '--release' }
$cargoArgs += @('--locked', '--target', $Target)
& $tool @cargoArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "  BUILD FAILED ($Target)" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "  (Tests skipped for -Target builds — run '.\build.ps1' to build + test on the host.)" -ForegroundColor DarkGray

$binName = if ($spec.Os -eq 'windows') { "koi.exe" } else { "koi" }
$binary = Join-Path $Root "target" $Target $targetDir $binName
if (-not (Test-Path $binary)) {
    throw "Expected binary not found: $binary"
}

$outDir = Join-Path (Join-Path $Root "dist") $Target
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$outBin = Join-Path $outDir $binName
Copy-Item $binary $outBin -Force

Write-Host ""
Write-Host "  Build complete." -ForegroundColor Green
Write-Host "  Target:  $Target"
Write-Host "  Binary:  dist/$Target/$binName"
Write-Host "  Version: $version"
Write-Host ""
