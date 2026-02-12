<#
.SYNOPSIS
    Build Koi with timestamp versioning.

.DESCRIPTION
    Reads version.json for major.minor, appends a timestamp build number,
    patches Cargo.toml permanently, builds, tests, and copies the binary to dist/.

    Cargo.toml keeps the real version after each build — no restore.

    Version format: major.minor.YYYYMMDDHHmm
    Example: 0.1.202502071430

.PARAMETER DebugBuild
    Build debug binaries instead of release

.PARAMETER SkipTests
    Skip running tests

.EXAMPLE
    .\build.ps1
    Build release binary with timestamp version
#>

[CmdletBinding()]
param(
    [switch]$DebugBuild,
    [switch]$SkipTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = $PSScriptRoot

# Read version.json
$versionFile = Join-Path $Root "version.json"
$versionData = Get-Content $versionFile | ConvertFrom-Json
$buildNumber = Get-Date -Format "yyyyMMddHHmm"
$version = "$($versionData.major).$($versionData.minor).$buildNumber"

Write-Host ""
Write-Host "  Building Koi $version" -ForegroundColor Cyan
Write-Host ""

# Patch Cargo.toml version (permanent — no restore)
$cargoToml = Join-Path $Root "Cargo.toml"
$content = Get-Content $cargoToml -Raw
$content = $content -replace '(?m)^version\s*=\s*"[^"]*"', "version = `"$version`""
Set-Content $cargoToml -Value $content -NoNewline

# Build
if ($DebugBuild) {
    $targetDir = "debug"
    cargo build
} else {
    $targetDir = "release"
    cargo build --release
}
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "  BUILD FAILED" -ForegroundColor Red
    exit $LASTEXITCODE
}

# Tests
if (-not $SkipTests) {
    Write-Host ""
    Write-Host "  Running tests..." -ForegroundColor Cyan
    Write-Host ""

    if ($DebugBuild) {
        cargo test -p koi-certmesh -- --test-threads=1
        if ($LASTEXITCODE -ne 0) { throw "Certmesh tests failed." }
        cargo test --workspace --exclude koi-certmesh
    } else {
        cargo test --release -p koi-certmesh -- --test-threads=1
        if ($LASTEXITCODE -ne 0) { throw "Certmesh tests failed." }
        cargo test --release --workspace --exclude koi-certmesh
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "  TESTS FAILED" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

# Copy to dist
$distDir = Join-Path $Root "dist"
if (-not (Test-Path $distDir)) { New-Item -ItemType Directory -Path $distDir | Out-Null }

$binary = Join-Path $Root "target" $targetDir "koi.exe"
Copy-Item $binary (Join-Path $distDir "koi.exe") -Force

Write-Host ""
Write-Host "  Build complete." -ForegroundColor Green
Write-Host "  Binary:  dist\koi.exe"
Write-Host "  Version: $version"
Write-Host ""
