#Requires -Version 7.2

<#
.SYNOPSIS
  Run the mesh health collector on every Linux host in the lab catalog and show
  each host's evidence line.

.DESCRIPTION
  Thin controller-side adapter for scripts/lab/mesh/mesh-status.sh (ADR-029
  standing-mesh snapshots). Stages the collector to /tmp on each putty_linux
  catalog node, executes it under sh regardless of login shell (RL-4/RL-5), and
  lets the script self-remove. Each host appends one JSON line to its own
  ~/koi-dogfood/evidence.jsonl; this script only prints what came back.
  Per-host failure or skip is reported but does not stop the remaining hosts;
  the script exits non-zero if any host did not produce a line.

  Credential resolution mirrors tools/koi-lab (schema 2): a node's password_env
  names the environment variable holding ITS password; nodes without one share
  KOI_LAB_PASSWORD.

.EXAMPLE
  pwsh scripts/lab/mesh/mesh-status-all.ps1
#>

[CmdletBinding()]
param(
    [string] $RepoRoot = (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'The mesh status driver drives PuTTY transports and requires Windows.'
}

$catalogPath = Join-Path $RepoRoot 'tools/koi-lab/lab.json'
$collector = Join-Path $PSScriptRoot 'mesh-status.sh'
foreach ($required in @($catalogPath, $collector)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required file is absent: $required"
    }
}

$catalog = Get-Content -LiteralPath $catalogPath -Raw | ConvertFrom-Json
$stagedName = '/tmp/koi-mesh-status.sh'
$failed = 0

foreach ($node in $catalog.nodes) {
    if ($node.kind -ne 'putty_linux') { continue }

    $passwordProperty = $node.PSObject.Properties['password_env']
    $envName = if ($null -ne $passwordProperty -and $passwordProperty.Value) {
        [string] $passwordProperty.Value
    } else {
        'KOI_LAB_PASSWORD'
    }
    $password = [Environment]::GetEnvironmentVariable($envName)
    $target = '{0}@{1}' -f $node.user, $node.address
    if ([string]::IsNullOrEmpty($password)) {
        Write-Output ("SKIP  {0,-8} {1} is not set" -f $node.id, $envName)
        $failed++
        continue
    }

    & pscp -batch -q -hostkey $node.host_key -pw $password $collector "$target`:$stagedName"
    if ($LASTEXITCODE -ne 0) {
        Write-Output ("FAIL  {0,-8} staging failed (pscp exit {1})" -f $node.id, $LASTEXITCODE)
        $failed++
        continue
    }

    # Same interpreter pinning as PuttyTransport::run: the harness owns sh.
    $output = & plink -batch -ssh -hostkey $node.host_key -pw $password $target "sh -c 'sh $stagedName'" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Output ("FAIL  {0,-8} collector failed (plink exit {1}): {2}" -f $node.id, $LASTEXITCODE, ($output -join ' '))
        $failed++
        continue
    }

    foreach ($line in @($output | Where-Object { $_ -match '^\{' })) {
        Write-Output ("OK    {0,-8} {1}" -f $node.id, $line)
    }
}

if ($failed -ne 0) {
    Write-Output ("SUMMARY {0} host(s) did not record evidence" -f $failed)
    exit 1
}
Write-Output 'SUMMARY all Linux hosts recorded evidence'
