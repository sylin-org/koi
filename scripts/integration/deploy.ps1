<#
.SYNOPSIS
  Build the freshest koi (static musl, via `cross`) and deploy it to the
  PRE-APPROVED Linux integration test servers. The ADR-020 real-world integration
  gate — see docs/testing/integration-hosts.md.

.DESCRIPTION
  Builds on THIS machine (powerful; already has cross + Docker), never on the test
  boxes. The result is a static x86_64 musl binary, so the boxes need no Rust/C
  toolchain. Copies it to each server's /home/stone/koi-test/koi via pscp.

  With -Setup, it also applies the per-host teardown (disable the conflicting
  garden-moss + avahi services so Koi owns its ports + mDNS) and installs the test
  instrumentation (jq, dnsutils, netcat).

  The server list is PRE-APPROVED (brook + granite) so a deploy can never
  accidentally target a non-test host; override with -Servers only deliberately.

.PARAMETER Servers
  IPs to deploy to. Default: the two dedicated test boxes.
.PARAMETER Release
  Build --release instead of debug.
.PARAMETER SkipBuild
  Reuse the existing binary (skip the cross build).
.PARAMETER Setup
  Also run per-host setup (disable garden-moss/avahi + install jq/dnsutils/nc).

.EXAMPLE
  ./scripts/integration/deploy.ps1 -Setup        # build, deploy, and set up both boxes
.EXAMPLE
  ./scripts/integration/deploy.ps1 -SkipBuild    # redeploy the current binary
#>
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Password',
    Justification = 'Deliberate throwaway creds (stone/stone) for dedicated, isolated LAN test boxes — not a secret.')]
param(
    # Pre-approved test servers: stone-platinum-brook, stone-granite-spring.
    [string[]] $Servers = @('192.168.1.44', '192.168.1.55'),
    [switch]   $Release,
    [switch]   $SkipBuild,
    [switch]   $Setup,
    [string]   $User = 'stone',
    [string]   $Password = 'stone',
    [string]   $RemoteDir = '/home/stone/koi-test'
)

$ErrorActionPreference = 'Stop'
$target = 'x86_64-unknown-linux-musl'
$profileDir = if ($Release) { 'release' } else { 'debug' }
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)  # scripts/integration -> repo root

function Say($msg) { Write-Host ">> $msg" -ForegroundColor Cyan }

# ── 1. Build the freshest static binary ──────────────────────────────
if (-not $SkipBuild) {
    Say "cross build ($profileDir) $target -p koi-net"
    Push-Location $repo
    try {
        $buildArgs = @('build', '--locked', '--target', $target, '-p', 'koi-net')
        if ($Release) { $buildArgs += '--release' }
        & cross @buildArgs
        if ($LASTEXITCODE -ne 0) { throw "cross build failed (exit $LASTEXITCODE)" }
    } finally { Pop-Location }
}

$bin = Join-Path $repo "target/$target/$profileDir/koi"
if (-not (Test-Path $bin)) { throw "binary not found: $bin (build first, or drop -SkipBuild)" }
$sizeMb = [math]::Round((Get-Item $bin).Length / 1MB, 1)
$built = (Get-Item $bin).LastWriteTime
Say "binary: $bin  ($sizeMb MB, built $built)"

# ── helpers ──────────────────────────────────────────────────────────
# Host keys are pinned by fingerprint rather than cached interactively: a `-batch`
# probe prints the server's key even as it aborts, and we feed that to `-hostkey`
# on every call. Fully non-interactive — `echo y | plink` to cache the key is
# unreliable across PuTTY/box versions (it hangs on some).
# Returns a SHA256:... fingerprint (key not yet trusted → pin it), '' (already
# cached + reachable → no -hostkey needed), or $null (SSH unreachable / auth failed).
function Get-HostKey($server) {
    $out = (cmd /c "plink -batch -ssh -pw $Password $User@$server exit 2>&1") -join "`n"
    if ($LASTEXITCODE -eq 0) { return '' }
    $m = [regex]::Match($out, 'SHA256:[A-Za-z0-9+/=]+')
    if ($m.Success) { return $m.Value } else { return $null }
}
function Remote($server, $hk, $cmd) {
    if ($hk) { & plink -batch -hostkey $hk -ssh -pw $Password "$User@$server" $cmd }
    else { & plink -batch -ssh -pw $Password "$User@$server" $cmd }
}

# ── 2. Deploy to each pre-approved server ────────────────────────────
$results = @()
foreach ($s in $Servers) {
    Say "deploy -> $s"
    try {
        $hk = Get-HostKey $s
        if ($null -eq $hk) { throw "could not reach SSH (host down / auth failed)" }
        Remote $s $hk "mkdir -p $RemoteDir/data"
        if ($hk) { & pscp -batch -q -hostkey $hk -pw $Password $bin "${User}@${s}:$RemoteDir/koi" }
        else { & pscp -batch -q -pw $Password $bin "${User}@${s}:$RemoteDir/koi" }
        if ($LASTEXITCODE -ne 0) { throw "pscp failed (exit $LASTEXITCODE)" }
        $ver = Remote $s $hk "chmod +x $RemoteDir/koi; $RemoteDir/koi version 2>&1 | head -1"

        if ($Setup) {
            Say "setup -> $s (disable garden-moss/avahi; install jq/dnsutils/nc)"
            Remote $s $hk "echo $Password | sudo -S systemctl disable --now garden-moss.service avahi-daemon.service avahi-daemon.socket 2>/dev/null; echo $Password | sudo -S apt-get install -y -qq jq dnsutils netcat-openbsd 2>/dev/null | tail -1; echo setup-ok" | Out-Null
        }
        $results += [pscustomobject]@{ Server = $s; Status = 'OK'; Version = ($ver | Select-Object -Last 1) }
    } catch {
        Write-Warning "deploy to ${s} failed: $_"
        $results += [pscustomobject]@{ Server = $s; Status = 'FAILED'; Version = "$_" }
    }
}

Write-Host ""
Say "deploy summary"
$results | Format-Table -AutoSize
if ($results.Status -contains 'FAILED') { exit 1 }
