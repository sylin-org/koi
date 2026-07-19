<#
.SYNOPSIS
  Compatibility entry point for the run-scoped koi-lab deploy controller.

.DESCRIPTION
  Linux artifacts are built on this workstation through cross + Docker, then staged
  under /home/stone/koi-test/runs/<run-id>/ on both pinned test hosts. The controller
  verifies one SHA-256 on both nodes, owns a distributed lock, records a redacted local
  manifest, and never stops or overwrites a pre-existing Koi service or fixed binary.

  New automation should call `cargo run -p koi-lab -- <command>` directly. This wrapper
  remains only for the established deploy.ps1 operator habit; all policy evaluation lives
  in koi-lab.

.PARAMETER SkipBuild
  Reuse the configured local release-musl artifact instead of rebuilding it.
.PARAMETER Setup
  Retired. Persistent service/package mutation is deliberately not part of deployment.
.PARAMETER Password
  Throwaway password for the dedicated test hosts. Defaults to KOI_LAB_PASSWORD.
#>
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Password',
    Justification = 'Dedicated isolated lab credentials; passed to koi-lab only through its environment contract.')]
param(
    [switch] $SkipBuild,
    [switch] $Setup,
    [string] $Password = $env:KOI_LAB_PASSWORD
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if ($Setup) {
    throw '-Setup is retired: use koi-lab preflight and an explicit run-scoped mutation lane.'
}
if ([string]::IsNullOrWhiteSpace($Password)) {
    throw 'Set KOI_LAB_PASSWORD or pass -Password for the dedicated test hosts.'
}

$env:KOI_LAB_PASSWORD = $Password
Push-Location $repo
try {
    if (-not $SkipBuild) {
        & cargo run -p koi-lab --locked -- build
        if ($LASTEXITCODE -ne 0) { throw "koi-lab build failed (exit $LASTEXITCODE)" }
    }
    & cargo run -p koi-lab --locked -- deploy
    if ($LASTEXITCODE -ne 0) { throw "koi-lab deploy failed (exit $LASTEXITCODE)" }
}
finally {
    Pop-Location
}
