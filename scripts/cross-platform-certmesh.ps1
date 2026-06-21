<#
.SYNOPSIS
  ADR-018 Tier 4 - Windows <-> Linux cross-PLATFORM certmesh exchange.

.DESCRIPTION
  A genuine cross-platform participant exchange on ONE host that has both a native
  Windows koi.exe and Docker (Linux containers):

    - Linux container = CA     (the Tier-3 musl image, published to 127.0.0.1)
    - Windows native  = member (koi.exe daemon, isolated data dir + breadcrumb)

  The Windows member JOINS the Linux CA over the loopback-published port (outbound from
  Windows, so no inbound-firewall dependency), proving create -> invite -> cross-platform
  join -> enrolled. This exercises the OS-crossing exchange the single-OS Tiers 1-3 cannot,
  and validates the certmesh CLI join fix across platforms.

  GitHub-hosted CI cannot pair a Windows and a Linux runner, so this is NOT a hosted CI
  gate - it is the local / self-hosted-runner validation for Tier 4.

.NOTES
  Requires: a built koi.exe (cargo build -p koi-net) and the Tier-3 image
  (scripts/cross-host-certmesh.sh builds koi-tier3:latest), or pass -Image / -KoiExe.
  ASCII-only on purpose so it runs under both Windows PowerShell 5.1 and pwsh 7.
#>
[CmdletBinding()]
param(
    [string]$KoiExe = "target\debug\koi.exe",
    [string]$Image = "koi-tier3:latest"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$koi = Join-Path $repo $KoiExe
if (-not (Test-Path $koi)) { throw ("koi.exe not found at {0}; build it: cargo build -p koi-net" -f $koi) }

function Get-FreePort {
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $l.Start(); $port = $l.LocalEndpoint.Port; $l.Stop(); return $port
}

$caPort = Get-FreePort
$memPort = Get-FreePort
$tmp = Join-Path $env:TEMP ("koi-xplat-" + [System.Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$caName = "koi-xplat-ca"

# Save env we override so we can restore it.
$savedProgramData = $env:ProgramData
$savedDataDir = $env:KOI_DATA_DIR
$savedNoCred = $env:KOI_NO_CREDENTIAL_STORE
$savedLog = $env:KOI_LOG
$daemon = $null

try {
    # Linux container = CA (published to loopback so the Windows member dials out).
    Write-Host ">> starting Linux CA container"
    docker rm -f $caName 2>$null | Out-Null
    docker run -d --name $caName --hostname linux-ca `
        -p ("127.0.0.1:{0}:5641" -f $caPort) `
        -e KOI_HTTP_BIND=0.0.0.0 -e KOI_NO_CREDENTIAL_STORE=1 `
        $Image | Out-Null

    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
        docker exec $caName koi status *> $null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { docker logs $caName; throw "Linux CA did not become ready" }

    Write-Host ">> Linux CA: certmesh create"
    docker exec $caName koi certmesh create --json --profile just-me --passphrase 'xplat-pass' | Out-Null

    # Windows native = member (isolated data dir + breadcrumb via ProgramData).
    $env:KOI_DATA_DIR = $tmp
    $env:ProgramData = $tmp          # Windows breadcrumb lives at %ProgramData%\koi\koi.endpoint
    $env:KOI_NO_CREDENTIAL_STORE = "1"
    $env:KOI_LOG = "warn"

    Write-Host ">> starting Windows member daemon (koi.exe)"
    $daemon = Start-Process -FilePath $koi -PassThru -WindowStyle Hidden -ArgumentList @(
        "--daemon", "--port", "$memPort",
        "--no-mdns", "--no-dns", "--no-health", "--no-proxy",
        "--no-udp", "--no-runtime", "--no-acme", "--no-mcp-http", "--no-ipc"
    )

    $memBase = "http://127.0.0.1:$memPort"
    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "$memBase/healthz" -UseBasicParsing -TimeoutSec 2
            if ($r.StatusCode -eq 200) { $ready = $true; break }
        } catch { Start-Sleep -Seconds 1 }
    }
    if (-not $ready) { throw "Windows member daemon did not become ready on $memBase" }

    # The member's hostname is whatever hostname::get() returns - read it from the daemon so
    # the invite is bound to the EXACT string the join will present.
    $winHost = (Invoke-RestMethod -Uri "$memBase/v1/host" -TimeoutSec 5).hostname
    Write-Host ">> Windows member hostname = $winHost"

    Write-Host ">> Linux CA: mint invite for $winHost"
    $inviteJson = docker exec $caName koi certmesh invite $winHost --ttl 60 --json | Out-String
    $invite = ($inviteJson | ConvertFrom-Json).token
    if ([string]::IsNullOrWhiteSpace($invite)) { throw "empty invite token" }

    Write-Host ">> Windows member: join the Linux CA across platforms"
    & $koi certmesh join ("http://127.0.0.1:{0}" -f $caPort) --invite $invite --json
    if ($LASTEXITCODE -ne 0) { throw "cross-platform join failed (exit $LASTEXITCODE)" }

    Write-Host ">> Linux CA: assert the Windows member is enrolled"
    $status = docker exec $caName koi certmesh status --json | Out-String | ConvertFrom-Json
    $member = $status.members | Where-Object { $_.hostname -eq $winHost }
    if (-not $member) { throw "Windows member '$winHost' not found in the Linux CA roster" }
    if ([string]::IsNullOrWhiteSpace($member.cert_fingerprint)) { throw "member has no cert fingerprint" }

    Write-Host "OK: Windows<->Linux cross-platform certmesh exchange (create -> invite -> join -> enrolled) passed."
    exit 0
}
finally {
    if ($daemon) { try { Stop-Process -Id $daemon.Id -Force -ErrorAction SilentlyContinue } catch {} }
    docker rm -f $caName 2>$null | Out-Null
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    $env:ProgramData = $savedProgramData
    $env:KOI_DATA_DIR = $savedDataDir
    $env:KOI_NO_CREDENTIAL_STORE = $savedNoCred
    $env:KOI_LOG = $savedLog
}
