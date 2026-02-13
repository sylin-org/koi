param(
    [switch]$NoBuild,
    [int]$Requests = 50,
    [int]$Parallel = 10
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$TestPort = 16000 + (Get-Random -Minimum 1 -Maximum 2000)
$DnsPort = 17000 + (Get-Random -Minimum 1 -Maximum 2000)
$TestDir = Join-Path $env:TEMP "koi-concurrency-$PID-$(Get-Random)"
$TestLog = Join-Path $TestDir 'koi-concurrency.log'
$BreadcrumbDir = Join-Path $TestDir 'breadcrumb'
$DataDir = Join-Path $TestDir 'data'
$KoiBin = Join-Path $PSScriptRoot '..\target\release\koi.exe'
$Endpoint = "http://127.0.0.1:$TestPort"
$script:daemonProc = $null

function Cleanup {
    if ($script:daemonProc -and -not $script:daemonProc.HasExited) {
        try {
            Invoke-WebRequest -Method POST -Uri "$Endpoint/v1/admin/shutdown" -TimeoutSec 5 -UseBasicParsing | Out-Null
        } catch {}
        try { Stop-Process -Id $script:daemonProc.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
    if (Test-Path $TestDir) {
        Remove-Item -Recurse -Force $TestDir -ErrorAction SilentlyContinue
    }
}

trap { Cleanup; break }

if (-not $NoBuild) {
    & cargo build --release 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error 'Build failed.'
        exit 1
    }
}

if (-not (Test-Path $KoiBin)) {
    Write-Error "Binary not found at $KoiBin"
    exit 1
}

New-Item -ItemType Directory -Path $TestDir -Force | Out-Null
New-Item -ItemType Directory -Path $BreadcrumbDir -Force | Out-Null
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $KoiBin
$psi.Arguments = "--daemon --port $TestPort --dns-port $DnsPort --no-ipc --log-file `"$TestLog`" -v"
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true
$psi.EnvironmentVariables['ProgramData'] = $BreadcrumbDir
$psi.EnvironmentVariables['KOI_DATA_DIR'] = $DataDir

$script:daemonProc = [System.Diagnostics.Process]::Start($psi)
$null = $script:daemonProc.StandardOutput.ReadToEndAsync()
$null = $script:daemonProc.StandardError.ReadToEndAsync()

# Wait for health
$healthy = $false
$deadline = [DateTime]::Now.AddSeconds(10)
while ([DateTime]::Now -lt $deadline) {
    try {
        $resp = Invoke-WebRequest -Uri "$Endpoint/healthz" -TimeoutSec 2 -UseBasicParsing
        if ($resp.StatusCode -eq 200) { $healthy = $true; break }
    } catch {}
    Start-Sleep -Milliseconds 200
}

if (-not $healthy) {
    Write-Error 'Daemon failed to start.'
    Cleanup
    exit 1
}

function Invoke-ParallelRequests {
    param(
        [int]$Count,
        [int]$Throttle,
        [scriptblock]$Action
    )

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        return 1..$Count | ForEach-Object -Parallel $Action -ThrottleLimit $Throttle
    }

    $results = @()
    foreach ($i in 1..$Count) {
        $results += & $Action $i
    }
    return $results
}

# Register services concurrently
$registerResults = Invoke-ParallelRequests -Count $Requests -Throttle $Parallel -Action {
    param($i)
    $client = [System.Net.Http.HttpClient]::new()
    $body = @{ name = "Burst$i"; type = "_http._tcp"; port = 18000 + $i; lease_secs = 0 } | ConvertTo-Json -Compress
    $content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, 'application/json')
    $resp = $client.PostAsync("$using:Endpoint/v1/mdns/announce", $content).GetAwaiter().GetResult()
    $json = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    $client.Dispose()
    return $json
}

$ids = @()
foreach ($json in $registerResults) {
    try {
        $parsed = $json | ConvertFrom-Json
        if ($parsed.registered.id) { $ids += $parsed.registered.id }
    } catch {}
}

if ($ids.Count -ne $Requests) {
    Write-Error "Expected $Requests registrations, got $($ids.Count)."
    Cleanup
    exit 1
}

$unique = $ids | Select-Object -Unique
if ($unique.Count -ne $Requests) {
    Write-Error "Expected $Requests unique IDs, got $($unique.Count)."
    Cleanup
    exit 1
}

Write-Host "Registered $Requests services ($($unique.Count) unique IDs)."

# Heartbeat concurrently
$null = Invoke-ParallelRequests -Count $ids.Count -Throttle $Parallel -Action {
    param($i)
    $idsLocal = $using:ids
    $id = $idsLocal[$i - 1]
    $client = [System.Net.Http.HttpClient]::new()
    $null = $client.PutAsync("$using:Endpoint/v1/mdns/heartbeat/$id", $null).GetAwaiter().GetResult()
    $client.Dispose()
    return $true
}

Write-Host 'Heartbeat completed.'

# Unregister concurrently
$null = Invoke-ParallelRequests -Count $ids.Count -Throttle $Parallel -Action {
    param($i)
    $idsLocal = $using:ids
    $id = $idsLocal[$i - 1]
    $client = [System.Net.Http.HttpClient]::new()
    $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Delete, "$using:Endpoint/v1/mdns/unregister/$id")
    $null = $client.SendAsync($req).GetAwaiter().GetResult()
    $client.Dispose()
    return $true
}

Write-Host 'Unregister completed.'

Cleanup
exit 0
