<#
.SYNOPSIS
    Koi installer for Windows (PowerShell 5.1+).

.DESCRIPTION
    Downloads the latest (or a pinned) release archive for this architecture
    from GitHub Releases, verifies its SHA-256 checksum, and installs koi.exe
    onto your PATH. It never compiles anything and never needs Administrator
    for the default per-user install location.

    One-liner:
        irm https://raw.githubusercontent.com/sylin-org/koi/main/install.ps1 | iex

    With options, set an env var first:
        $env:KOI_VERSION = 'v0.4.2'
        irm https://raw.githubusercontent.com/sylin-org/koi/main/install.ps1 | iex

.PARAMETER Version
    Pin a release tag, e.g. v0.4.2. Defaults to the latest release, or the
    KOI_VERSION environment variable.

.PARAMETER InstallDir
    Install location. Defaults to %LOCALAPPDATA%\Programs\koi, or the
    KOI_INSTALL_DIR environment variable.

.PARAMETER NoModifyPath
    Do not add the install directory to your user PATH.
#>
[CmdletBinding()]
param(
    [string]$Version = $env:KOI_VERSION,
    [string]$InstallDir = $env:KOI_INSTALL_DIR,
    [switch]$NoModifyPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = 'sylin-org/koi'
$BinName = 'koi'

# TLS 1.2 for older Windows PowerShell hosts that still default to TLS 1.0.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {}

function Say($msg) { Write-Host "koi: $msg" }

# ── Detect architecture → release target triple ───────────────────
# PS 5.1 on ARM64 Windows runs as an emulated x64 process and reports AMD64 in
# PROCESSOR_ARCHITECTURE. Resolve the true machine arch via the WoW64 hint, then
# the registry, before falling back to the process arch.
function Get-NativeArch {
    if ($env:PROCESSOR_ARCHITEW6432) { return $env:PROCESSOR_ARCHITEW6432 }
    try {
        $native = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -ErrorAction Stop).PROCESSOR_ARCHITECTURE
        if ($native) { return $native }
    } catch {}
    return $env:PROCESSOR_ARCHITECTURE
}

$archEnv = Get-NativeArch
$arch = switch ($archEnv) {
    'AMD64' { 'x86_64' }
    'ARM64' { 'aarch64' }
    'x86'   { throw "koi: 32-bit Windows is not supported" }
    default { throw "koi: unsupported architecture '$archEnv'" }
}
$target = "$arch-pc-windows-msvc"

# ── Resolve the release tag (latest unless pinned) ─────────────────
if (-not $Version) {
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
            -Headers @{ 'User-Agent' = 'koi-install' }
    } catch {
        throw "koi: could not fetch the latest release from GitHub (rate-limited or offline?). Set -Version or `$env:KOI_VERSION to pin a tag. $_"
    }
    $Version = $rel.tag_name
}
if (-not $Version) { throw "koi: could not determine the latest release (set -Version to pin one)" }
if ($Version -notmatch '^v') { $Version = "v$Version" }
# Reject a tag that could escape a path or inject into a URL.
if ($Version -notmatch '^v[0-9A-Za-z._-]+$') { throw "koi: unexpected version tag '$Version'" }

# ── Resolve the install directory ──────────────────────────────────
if (-not $InstallDir) {
    $localAppData = [Environment]::GetFolderPath('LocalApplicationData')
    if (-not $localAppData) { throw "koi: cannot resolve LocalApplicationData; pass -InstallDir explicitly" }
    $InstallDir = Join-Path $localAppData 'Programs\koi'
}

$archive = "$BinName-$Version-$target.zip"
$baseUrl = "https://github.com/$Repo/releases/download/$Version"

Say "installing $BinName $Version ($target) to $InstallDir"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("koi-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $zipPath = Join-Path $tmp $archive
    $shaPath = "$zipPath.sha256"

    Say "downloading $archive"
    try {
        Invoke-WebRequest -Uri "$baseUrl/$archive" -OutFile $zipPath -UseBasicParsing
        Invoke-WebRequest -Uri "$baseUrl/$archive.sha256" -OutFile $shaPath -UseBasicParsing
    } catch {
        throw "koi: download failed — does $Version have a $target build? See https://github.com/$Repo/releases"
    }

    # ── Verify checksum ───────────────────────────────────────────
    # TrimStart strips a UTF-8 BOM if a regenerated checksum file carries one.
    $expected = ((Get-Content $shaPath -Raw).TrimStart([char]0xFEFF).Trim() -split '\s+')[0].ToLower()
    $actual = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower()
    if (-not $expected) { throw "koi: checksum file was empty" }
    if ($expected -ne $actual) {
        throw "koi: checksum mismatch for $archive (expected $expected, got $actual)"
    }
    Say "checksum verified"

    # ── Extract and install ───────────────────────────────────────
    $unpack = Join-Path $tmp 'unpack'
    Expand-Archive -Path $zipPath -DestinationPath $unpack -Force
    $exe = Join-Path $unpack "$BinName-$Version-$target\$BinName.exe"
    if (-not (Test-Path $exe)) { throw "koi: archive did not contain $BinName.exe" }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -Path $exe -Destination (Join-Path $InstallDir "$BinName.exe") -Force
    Say "installed $InstallDir\$BinName.exe"

    # ── PATH (user scope) ─────────────────────────────────────────
    if (-not $NoModifyPath) {
        $norm = $InstallDir.TrimEnd('\')
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
        # Compare against both scopes, normalising trailing backslashes, so a
        # re-run (or an existing machine-wide install) never double-appends.
        $entries = (($userPath, $machinePath) -join ';') -split ';' |
            ForEach-Object { $_.TrimEnd('\') }
        if ($entries -notcontains $norm) {
            $newPath = if ($userPath) { "$userPath;$InstallDir" } else { $InstallDir }
            [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
            $env:Path = "$env:Path;$InstallDir"
            Say "added $InstallDir to your user PATH (restart your shell to pick it up)"
        }
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

Write-Host ""
Say "koi $Version installed -> $InstallDir\$BinName.exe"
Write-Host ""
# Never leave the user at a blank prompt: show it actually runs (fast, local).
try { & (Join-Path $InstallDir "$BinName.exe") status } catch {}
Write-Host ""
Say "see your network:   $BinName mdns discover     # instant, no daemon"
Say "run as a service:   $BinName install           # as Administrator, then just run: $BinName"
Say "verify this build:  gh attestation verify $archive --repo $Repo   (optional)"
