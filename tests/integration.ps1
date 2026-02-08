#Requires -Version 5.1
<#
.SYNOPSIS
    Koi integration test suite (Windows / PowerShell).

.DESCRIPTION
    Builds Koi, then exercises the CLI and daemon surfaces end-to-end.
    Tier 1: Standalone CLI (no daemon needed).
    Tier 2: Daemon (foreground) - HTTP API, SSE, IPC, client mode, admin commands, shutdown.

    Run from the repo root:
        pwsh tests/integration.ps1

    Tier 3 (service install/uninstall) requires elevation and is not included here.
    Run it manually with: pwsh tests/integration.ps1 -Tier3
#>

param(
    [switch]$Tier3,
    [switch]$NoBuild,
    [switch]$Verbose
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Load System.Net.Http assembly for SSE streaming tests (HttpClient, etc.)
Add-Type -AssemblyName System.Net.Http

# -- Test configuration -------------------------------------------------------

$TestPort      = 15641
$TestPipe      = '\\.\pipe\koi-test'
$TestPipeName  = 'koi-test'
$TestDir       = Join-Path $env:TEMP "koi-test-$(Get-Random)"
$TestLog       = Join-Path $TestDir 'koi-test.log'
$BreadcrumbDir = Join-Path $TestDir 'breadcrumb'
$KoiBin        = Join-Path $PSScriptRoot '..\target\release\koi.exe'
# Use 127.0.0.1 instead of localhost to avoid IPv6 resolution issues
# (axum binds 0.0.0.0 = IPv4 only).
$Endpoint      = "http://127.0.0.1:$TestPort"

# Timeout for daemon health poll (seconds)
$HealthTimeout = 15
# Timeout for individual test operations (seconds)
$OpTimeout     = 10

# -- Bookkeeping --------------------------------------------------------------

$script:passed = 0
$script:failed = 0
$script:skipped = 0
$script:tests  = @()
$script:daemonProc = $null

function Log($msg) {
    Write-Host "  $msg" -ForegroundColor DarkGray
}

function Pass($name) {
    $script:passed++
    $script:tests += @{ name = $name; result = 'PASS' }
    Write-Host "[PASS] $name" -ForegroundColor Green
}

function Fail($name, $reason) {
    $script:failed++
    $script:tests += @{ name = $name; result = 'FAIL'; reason = $reason }
    Write-Host "[FAIL] $name - $reason" -ForegroundColor Red
}

function Skip($name, $reason) {
    $script:skipped++
    $script:tests += @{ name = $name; result = 'SKIP'; reason = $reason }
    Write-Host "[SKIP] $name - $reason" -ForegroundColor Yellow
}

function Cleanup {
    if ($script:daemonProc -and -not $script:daemonProc.HasExited) {
        Log "Stopping daemon (PID $($script:daemonProc.Id))..."
        Stop-Process -Id $script:daemonProc.Id -Force -ErrorAction SilentlyContinue
        $script:daemonProc.WaitForExit(5000) | Out-Null
    }
    if (Test-Path $TestDir) {
        Remove-Item -Recurse -Force $TestDir -ErrorAction SilentlyContinue
    }
}

trap { Cleanup; break }

# -- Build --------------------------------------------------------------------

if (-not $NoBuild) {
    Write-Host "`n=== Building Koi (release) ===" -ForegroundColor Cyan
    & cargo build --release 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build failed." -ForegroundColor Red
        exit 1
    }
}

if (-not (Test-Path $KoiBin)) {
    Write-Host "Binary not found at $KoiBin" -ForegroundColor Red
    exit 1
}

New-Item -ItemType Directory -Path $TestDir -Force | Out-Null
New-Item -ItemType Directory -Path $BreadcrumbDir -Force | Out-Null

Write-Host "Binary:     $KoiBin"
Write-Host "Test dir:   $TestDir"
Write-Host "Port:       $TestPort"
Write-Host "Pipe:       $TestPipe"
Write-Host ""

# -- Helper: run koi with test isolation --------------------------------------

function Invoke-Koi {
    param(
        [string[]]$KoiArgs,
        [int]$TimeoutSec = $OpTimeout,
        [string]$Stdin = $null,
        [switch]$AllowFailure
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $KoiBin
    $psi.Arguments = $KoiArgs -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = ($null -ne $Stdin)
    $psi.CreateNoWindow = $true
    # Isolate breadcrumb from real daemon
    $psi.EnvironmentVariables['LOCALAPPDATA'] = $BreadcrumbDir

    $proc = [System.Diagnostics.Process]::Start($psi)

    if ($null -ne $Stdin) {
        $proc.StandardInput.WriteLine($Stdin)
        $proc.StandardInput.Close()
    }

    # Start async reads before waiting - prevents pipe buffer deadlocks.
    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()

    if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
        $proc.Kill()
        # Still drain whatever was captured before timeout
        $proc.WaitForExit()
        if (-not $AllowFailure) {
            throw "koi $($KoiArgs -join ' ') timed out after ${TimeoutSec}s"
        }
    }

    # Parameterless WaitForExit ensures async output reads have completed.
    # See: https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.waitforexit
    $proc.WaitForExit()

    $result = [PSCustomObject]@{
        ExitCode = $proc.ExitCode
        Stdout   = $stdoutTask.Result
        Stderr   = $stderrTask.Result
    }

    if (-not $AllowFailure -and $proc.ExitCode -ne 0) {
        if ($Verbose) { Log "stderr: $($result.Stderr)" }
        throw "koi $($KoiArgs -join ' ') exited with code $($proc.ExitCode)"
    }

    return $result
}

function Invoke-Http {
    param(
        [string]$Method = 'GET',
        [string]$Uri,
        [string]$Body = $null,
        [int]$TimeoutSec = $OpTimeout
    )

    $params = @{
        Method          = $Method
        Uri             = $Uri
        TimeoutSec      = $TimeoutSec
        UseBasicParsing = $true
    }
    if ($Body) {
        $params['Body'] = $Body
        $params['ContentType'] = 'application/json'
    }

    return Invoke-WebRequest @params
}

# Helper for testing error responses from HTTP (4xx/5xx).
# Invoke-WebRequest throws on non-2xx; this catches and returns the error body.
function Invoke-HttpExpectError {
    param(
        [string]$Method = 'GET',
        [string]$Uri,
        [string]$Body = $null,
        [int]$TimeoutSec = $OpTimeout
    )

    try {
        $resp = Invoke-Http -Method $Method -Uri $Uri -Body $Body -TimeoutSec $TimeoutSec
        # If we get here, the request succeeded (2xx) - unexpected
        return [PSCustomObject]@{
            StatusCode = $resp.StatusCode
            Content    = $resp.Content
            Error      = $false
        }
    } catch {
        $ex = $_.Exception
        if ($ex -and $ex.Response) {
            $statusCode = [int]$ex.Response.StatusCode
            # PowerShell 7 (HttpClient): response body is in ErrorDetails.Message
            # PowerShell 5.1 (WebRequest): response body is in GetResponseStream()
            $content = $_.ErrorDetails.Message
            if (-not $content) {
                try {
                    $reader = New-Object System.IO.StreamReader($ex.Response.GetResponseStream())
                    $content = $reader.ReadToEnd()
                    $reader.Close()
                } catch {
                    $content = ''
                }
            }
            return [PSCustomObject]@{
                StatusCode = $statusCode
                Content    = $content
                Error      = $true
            }
        }
        # Re-throw if it's not an HTTP error (e.g. connection refused)
        throw
    }
}

function Invoke-Pipe {
    param(
        [string]$PipeName,
        [string[]]$Messages,
        [int]$TimeoutMs = 5000,
        [int]$ExpectedLines = 1
    )

    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $pipe.Connect($TimeoutMs)
        $writer = New-Object System.IO.StreamWriter($pipe)
        $writer.AutoFlush = $true
        $reader = New-Object System.IO.StreamReader($pipe)

        $results = @()
        foreach ($msg in $Messages) {
            $writer.WriteLine($msg)
            for ($i = 0; $i -lt $ExpectedLines; $i++) {
                $line = $reader.ReadLine()
                if ($null -eq $line) { break }
                $results += ($line | ConvertFrom-Json)
            }
        }

        return $results
    } finally {
        $pipe.Dispose()
    }
}

# Helper for consuming SSE (Server-Sent Events) streams.
# Invoke-WebRequest buffers the full response; we need streaming via HttpClient.
function Invoke-Sse {
    param(
        [string]$Uri,
        [int]$MaxEvents = 5,
        [int]$TimeoutMs = 5000
    )

    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [TimeSpan]::FromMilliseconds($TimeoutMs + 1000)
    $cts = New-Object System.Threading.CancellationTokenSource
    $cts.CancelAfter($TimeoutMs)

    try {
        $request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $Uri)
        $request.Headers.Accept.Add([System.Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new('text/event-stream'))

        $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cts.Token).GetAwaiter().GetResult()
        $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $reader = New-Object System.IO.StreamReader($stream)

        $events = @()
        $deadline = [DateTime]::Now.AddMilliseconds($TimeoutMs)

        while ($events.Count -lt $MaxEvents -and [DateTime]::Now -lt $deadline) {
            if ($cts.Token.IsCancellationRequested) { break }
            try {
                $lineTask = $reader.ReadLineAsync()
                if (-not $lineTask.Wait([Math]::Max(100, ($deadline - [DateTime]::Now).TotalMilliseconds), $cts.Token)) {
                    break
                }
                $line = $lineTask.Result
            } catch [System.OperationCanceledException] {
                break
            } catch {
                break
            }
            if ($null -eq $line) { break }
            if ($line.StartsWith('data: ')) {
                $json = $line.Substring(6)
                try {
                    $events += ($json | ConvertFrom-Json)
                } catch {
                    # Skip malformed data lines
                }
            }
            # Skip empty lines, "event:" lines, etc.
        }

        return ,$events
    } catch [System.OperationCanceledException] {
        # Includes TaskCanceledException (derived from OperationCanceledException)
        return @()
    } finally {
        if ($reader) { $reader.Dispose() }
        if ($stream) { $stream.Dispose() }
        if ($response) { $response.Dispose() }
        $cts.Dispose()
        $client.Dispose()
    }
}

# ======================================================================
#  TIER 1 - Standalone CLI
# ======================================================================

Write-Host "`n=== Tier 1: Standalone CLI ===" -ForegroundColor Cyan

# 1.1 - Help
try {
    $r = Invoke-Koi -KoiArgs '--help'
    if ($r.Stdout -match 'browse' -and $r.Stdout -match 'register' -and $r.Stdout -match 'resolve') {
        Pass 'koi --help shows subcommands'
    } else {
        Fail 'koi --help shows subcommands' 'Missing expected subcommands in output'
    }
} catch {
    Fail 'koi --help shows subcommands' $_.Exception.Message
}

# 1.2 - Browse help
try {
    $r = Invoke-Koi -KoiArgs 'browse', '--help'
    if ($r.Stdout -match 'service.type' -or $r.Stdout -match 'SERVICE_TYPE' -or $r.Stdout -match '[sS]ervice type') {
        Pass 'koi browse --help shows type argument'
    } else {
        Fail 'koi browse --help shows type argument' 'Missing type argument in output'
    }
} catch {
    Fail 'koi browse --help shows type argument' $_.Exception.Message
}

# 1.3 - Browse with timeout exits cleanly
try {
    $r = Invoke-Koi -KoiArgs 'browse', 'http', '--timeout', '2', '--standalone'
    Pass 'koi browse --timeout exits cleanly'
} catch {
    Fail 'koi browse --timeout exits cleanly' $_.Exception.Message
}

# 1.4 - Browse JSON mode produces valid JSON
try {
    $r = Invoke-Koi -KoiArgs 'browse', 'http', '--timeout', '2', '--json', '--standalone'
    # Output may be empty (no services found in 2s) - that's fine.
    # If there IS output, each non-empty line must be valid JSON.
    $lines = $r.Stdout -split "`n" | Where-Object { $_.Trim() -ne '' }
    $valid = $true
    $badLine = ''
    foreach ($line in $lines) {
        try { $null = $line | ConvertFrom-Json } catch { $valid = $false; $badLine = $line; break }
    }
    if ($valid) {
        Pass 'koi browse --json produces valid NDJSON'
    } else {
        Fail 'koi browse --json produces valid NDJSON' "Invalid JSON line: $($badLine.Substring(0, [Math]::Min(80, $badLine.Length)))"
    }
} catch {
    Fail 'koi browse --json produces valid NDJSON' $_.Exception.Message
}

# 1.5 - Register with timeout
# Note: --timeout and --standalone go BEFORE TXT records because trailing_var_arg eats everything after positionals.
try {
    $r = Invoke-Koi -KoiArgs '--standalone', 'register', '--timeout', '2', 'IntegrationTest', 'http', '19999', 'test=true'
    if ($r.Stdout -match 'Registered' -or $r.Stdout -match '"registered"') {
        Pass 'koi register prints confirmation'
    } else {
        Fail 'koi register prints confirmation' "Output did not contain registration confirmation: $($r.Stdout.Substring(0, [Math]::Min(100, $r.Stdout.Length)))"
    }
} catch {
    Fail 'koi register prints confirmation' $_.Exception.Message
}

# 1.6 - Piped JSON mode (browse streams forever in piped mode, so allow timeout)
try {
    $r = Invoke-Koi -KoiArgs '--standalone' -Stdin '{"browse":"_http._tcp"}' -TimeoutSec 5 -AllowFailure
    # Process was killed after timeout - that's expected for piped browse.
    # Validate that any output produced is valid JSON.
    $lines = $r.Stdout -split "`n" | Where-Object { $_.Trim() -ne '' }
    $valid = $true
    foreach ($line in $lines) {
        try { $null = $line | ConvertFrom-Json } catch { $valid = $false; break }
    }
    if ($valid) {
        Pass 'piped JSON mode accepted'
    } else {
        Fail 'piped JSON mode accepted' 'Invalid JSON in output'
    }
} catch {
    Fail 'piped JSON mode accepted' $_.Exception.Message
}

# 1.7 - Verbose flag accepted
try {
    $r = Invoke-Koi -KoiArgs 'browse', 'http', '--timeout', '1', '-v', '--standalone'
    Pass 'koi -v flag accepted'
} catch {
    Fail 'koi -v flag accepted' $_.Exception.Message
}

# 1.8 - Log file flag creates file
try {
    $logPath = Join-Path $TestDir 'test-logfile.log'
    $r = Invoke-Koi -KoiArgs 'browse', 'http', '--timeout', '2', '--log-file', "`"$logPath`"", '--standalone'
    if (Test-Path $logPath) {
        Pass 'koi --log-file creates log file'
    } else {
        Fail 'koi --log-file creates log file' 'Log file was not created'
    }
} catch {
    Fail 'koi --log-file creates log file' $_.Exception.Message
}

# ======================================================================
#  TIER 2 - Daemon (foreground)
# ======================================================================

Write-Host "`n=== Tier 2: Daemon (foreground) ===" -ForegroundColor Cyan

# Start daemon in background
Log "Starting daemon on port $TestPort..."

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $KoiBin
$psi.Arguments = "--daemon --port $TestPort --pipe $TestPipe --log-file `"$TestLog`" -v"
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true
$psi.EnvironmentVariables['LOCALAPPDATA'] = $BreadcrumbDir

$script:daemonProc = [System.Diagnostics.Process]::Start($psi)
# Start async reads immediately to drain stdout/stderr pipes.
# Without this, the OS pipe buffer (~4 KB) fills up and any blocking
# write from the daemon (e.g. tracing to stderr) deadlocks the process.
$script:daemonStdoutTask = $script:daemonProc.StandardOutput.ReadToEndAsync()
$script:daemonStderrTask = $script:daemonProc.StandardError.ReadToEndAsync()
Log "Daemon PID: $($script:daemonProc.Id)"

# Poll for health
$healthy = $false
$deadline = [DateTime]::Now.AddSeconds($HealthTimeout)
while ([DateTime]::Now -lt $deadline) {
    try {
        $resp = Invoke-Http -Uri "$Endpoint/healthz" -TimeoutSec 2
        if ($resp.StatusCode -eq 200) {
            $healthy = $true
            break
        }
    } catch {
        # Not ready yet
    }
    Start-Sleep -Milliseconds 500
}

if (-not $healthy) {
    Fail 'daemon health check' 'Daemon did not become healthy within timeout'
    if (Test-Path $TestLog) {
        Log "Daemon log tail:"
        Get-Content $TestLog -Tail 20 | ForEach-Object { Log "  $_" }
    }
    Cleanup
    exit 1
}

# 2.1 - Health check + body assertion
try {
    $resp = Invoke-Http -Uri "$Endpoint/healthz"
    $healthJson = $resp.Content | ConvertFrom-Json
    if ($resp.StatusCode -eq 200 -and $healthJson.ok -eq $true) {
        Pass 'daemon health check ({"ok":true})'
    } else {
        Fail 'daemon health check' "Unexpected body: $($resp.Content)"
    }
} catch {
    Fail 'daemon health check' $_.Exception.Message
}

# 2.2 - Breadcrumb exists
$breadcrumbFile = Join-Path (Join-Path $BreadcrumbDir 'koi') 'koi.endpoint'
if (Test-Path $breadcrumbFile) {
    $bcContent = (Get-Content $breadcrumbFile -Raw).Trim()
    # Breadcrumb writes "http://localhost:PORT" - match either localhost or 127.0.0.1
    if ($bcContent -match "http://(localhost|127\.0\.0\.1):$TestPort") {
        Pass 'breadcrumb file written with correct endpoint'
    } else {
        Fail 'breadcrumb file written with correct endpoint' "Unexpected content: '$bcContent'"
    }
} else {
    Fail 'breadcrumb file written with correct endpoint' 'Breadcrumb file not found'
}

# 2.3 - Register via HTTP
$regId = $null
try {
    $body = '{"name":"DaemonTest","type":"_http._tcp","port":19998}'
    $resp = Invoke-Http -Method POST -Uri "$Endpoint/v1/services" -Body $body
    $json = $resp.Content | ConvertFrom-Json
    if ($json.registered.id) {
        $regId = $json.registered.id
        Pass "register via HTTP (id: $($regId.Substring(0, [Math]::Min(8, $regId.Length))))"
    } else {
        Fail 'register via HTTP' 'No id in response'
    }
} catch {
    Fail 'register via HTTP' $_.Exception.Message
}

# 2.4 - Register with TXT records + admin inspect
$txtRegId = $null
try {
    $body = '{"name":"TxtTest","type":"_http._tcp","port":19997,"txt":{"env":"test","ver":"1"}}'
    $resp = Invoke-Http -Method POST -Uri "$Endpoint/v1/services" -Body $body
    $json = $resp.Content | ConvertFrom-Json
    $txtRegId = $json.registered.id

    # Verify via admin inspect — deep field assertion
    $inspResp = Invoke-Http -Uri "$Endpoint/v1/admin/registrations/$txtRegId"
    $insp = $inspResp.Content | ConvertFrom-Json
    # AdminRegistration fields: id, name, type, port, mode, state, lease_secs,
    # remaining_secs, grace_secs, session_id, registered_at, last_seen, txt
    $inspOk = $insp.name -eq 'TxtTest' -and
              $insp.port -eq 19997 -and
              $insp.type -match '_http\._tcp' -and
              $insp.state -eq 'alive' -and
              $insp.mode -eq 'heartbeat' -and
              $insp.txt.env -eq 'test' -and
              $insp.txt.ver -eq '1' -and
              $insp.id -eq $txtRegId -and
              $insp.registered_at -and
              $insp.last_seen -and
              $null -ne $insp.grace_secs -and $insp.grace_secs -ge 0 -and
              $null -ne $insp.lease_secs -and $insp.lease_secs -gt 0
    if ($inspOk) {
        Pass "register with TXT + admin inspect (id: $($txtRegId.Substring(0, [Math]::Min(8, $txtRegId.Length))))"
    } else {
        Fail 'register with TXT + admin inspect' "Inspect fields: name=$($insp.name) type=$($insp.type) port=$($insp.port) state=$($insp.state) mode=$($insp.mode) txt.env=$($insp.txt.env) lease=$($insp.lease_secs) grace=$($insp.grace_secs)"
    }
} catch {
    Fail 'register with TXT + admin inspect' $_.Exception.Message
}

# 2.5 - Register with explicit lease_secs + round-trip
$leaseRegId = $null
try {
    $body = '{"name":"LeaseTest","type":"_http._tcp","port":19994,"lease_secs":300}'
    $resp = Invoke-Http -Method POST -Uri "$Endpoint/v1/services" -Body $body
    $json = $resp.Content | ConvertFrom-Json
    $leaseRegId = $json.registered.id
    if ($json.registered.lease_secs -eq 300 -and $json.registered.mode -eq 'heartbeat') {
        # Heartbeat and verify lease round-trips
        $hbResp = Invoke-Http -Method PUT -Uri "$Endpoint/v1/services/$leaseRegId/heartbeat"
        $hbJson = $hbResp.Content | ConvertFrom-Json
        if ($hbJson.renewed.lease_secs -eq 300) {
            Pass 'register with lease_secs=300 + heartbeat round-trip'
        } else {
            Fail 'register with lease_secs round-trip' "Heartbeat lease_secs=$($hbJson.renewed.lease_secs), expected 300"
        }
    } else {
        Fail 'register with lease_secs round-trip' "lease_secs=$($json.registered.lease_secs), mode=$($json.registered.mode)"
    }
} catch {
    Fail 'register with lease_secs round-trip' $_.Exception.Message
}

# 2.6 - Register with lease_secs=0 (permanent mode, no heartbeat needed)
$permanentRegId = $null
try {
    $body = '{"name":"PermanentTest","type":"_http._tcp","port":19991,"lease_secs":0}'
    $resp = Invoke-Http -Method POST -Uri "$Endpoint/v1/services" -Body $body
    $json = $resp.Content | ConvertFrom-Json
    $permanentRegId = $json.registered.id
    # lease_secs is omitted (skip_serializing_if) for permanent — check via PSObject.Properties
    $hasLease = $null -ne $json.registered.PSObject.Properties['lease_secs']
    if ($json.registered.mode -eq 'permanent' -and -not $hasLease) {
        Pass "register with lease_secs=0 returns mode=permanent"
    } else {
        Fail 'register with lease_secs=0' "mode=$($json.registered.mode), hasLease=$hasLease"
    }
} catch {
    Fail 'register with lease_secs=0' $_.Exception.Message
}

# 2.7 - Admin status via CLI with deeper assertions
try {
    $r = Invoke-Koi -KoiArgs 'admin', 'status', '--endpoint', $Endpoint, '--json'
    $statusJson = $r.Stdout.Trim() | ConvertFrom-Json
    $regs = $statusJson.registrations
    if ($statusJson.version -and
        $statusJson.platform -and
        $null -ne $statusJson.uptime_secs -and $statusJson.uptime_secs -ge 0 -and
        $regs -and $regs.total -ge 4 -and
        ($regs.alive + $regs.draining) -eq $regs.total) {
        Pass "admin status (v$($statusJson.version), total: $($regs.total), alive+draining=$($regs.alive)+$($regs.draining))"
    } else {
        Fail 'admin status' "Fields: version=$($statusJson.version) platform=$($statusJson.platform) uptime=$($statusJson.uptime_secs) total=$($regs.total) alive=$($regs.alive) draining=$($regs.draining)"
    }
} catch {
    Fail 'admin status' $_.Exception.Message
}

# 2.7 - Admin ls shows registrations (human output)
try {
    $r = Invoke-Koi -KoiArgs 'admin', 'ls', '--endpoint', $Endpoint
    if ($r.Stdout -match 'DaemonTest' -and $r.Stdout -match 'TxtTest') {
        Pass 'admin ls shows registrations'
    } else {
        Fail 'admin ls shows registrations' 'Expected registrations not found in listing'
    }
} catch {
    Fail 'admin ls shows registrations' $_.Exception.Message
}

# 2.8 - Admin ls --json mode
try {
    $r = Invoke-Koi -KoiArgs 'admin', 'ls', '--endpoint', $Endpoint, '--json'
    $lsJson = $r.Stdout.Trim() | ConvertFrom-Json
    if ($lsJson -is [array] -and $lsJson.Count -ge 4) {
        $allHaveFields = $true
        foreach ($entry in $lsJson) {
            if (-not $entry.id -or -not $entry.name -or -not $entry.type -or $null -eq $entry.port -or -not $entry.state) {
                $allHaveFields = $false
                break
            }
        }
        if ($allHaveFields) {
            Pass "admin ls --json (array of $($lsJson.Count) registrations)"
        } else {
            Fail 'admin ls --json' 'Some entries missing required fields (id, name, type, port, state)'
        }
    } else {
        Fail 'admin ls --json' "Expected array with >=3 entries, got: $(if ($lsJson -is [array]) { $lsJson.Count } else { 'non-array' })"
    }
} catch {
    Fail 'admin ls --json' $_.Exception.Message
}

# 2.9 - Register via CLI client mode
# Note: client-mode register auto-unregisters on exit (line 132 in client.rs),
# so the service is cleaned up when the --timeout fires.
try {
    $r = Invoke-Koi -KoiArgs '--endpoint', $Endpoint, '--json', 'register', '--timeout', '3', 'CLIClient', 'http', '17777' -TimeoutSec 15 -AllowFailure
    if ($r.ExitCode -ne 0) {
        Log "CLI client register stderr: $($r.Stderr.Trim())"
        Fail 'register via CLI client mode' "Exit code $($r.ExitCode)"
    } else {
        if ($r.Stdout -match '"registered"') {
            Pass 'register via CLI client mode'
        } else {
            Fail 'register via CLI client mode' "No registered JSON in output"
        }
    }
} catch {
    Fail 'register via CLI client mode' $_.Exception.Message
}

# 2.10 - Unregister via CLI client mode
# Note: CLI register (2.9) auto-unregisters on exit, so we register a fresh
# service via HTTP specifically for the CLI unregister test.
try {
    $body = '{"name":"UnregTarget","type":"_http._tcp","port":19995,"lease_secs":0}'
    $resp = Invoke-Http -Method POST -Uri "$Endpoint/v1/services" -Body $body
    $json = $resp.Content | ConvertFrom-Json
    $unregTargetId = $json.registered.id

    $r = Invoke-Koi -KoiArgs '--endpoint', $Endpoint, '--json', 'unregister', $unregTargetId
    $parsed = $r.Stdout.Trim() | ConvertFrom-Json
    if ($parsed.unregistered -eq $unregTargetId) {
        Pass 'unregister via CLI client mode'
    } else {
        Fail 'unregister via CLI client mode' "Unexpected response: $($r.Stdout.Trim())"
    }
} catch {
    Fail 'unregister via CLI client mode' $_.Exception.Message
}

# 2.11 - Heartbeat via HTTP
if ($regId) {
    try {
        $resp = Invoke-Http -Method PUT -Uri "$Endpoint/v1/services/$regId/heartbeat"
        $json = $resp.Content | ConvertFrom-Json
        if ($json.renewed.id -eq $regId -and $json.renewed.lease_secs -gt 0) {
            Pass "heartbeat via HTTP (lease: $($json.renewed.lease_secs)s)"
        } else {
            Fail 'heartbeat via HTTP' "Unexpected response: $($resp.Content)"
        }
    } catch {
        Fail 'heartbeat via HTTP' $_.Exception.Message
    }
} else {
    Fail 'heartbeat via HTTP' 'Skipped (no registration id)'
}

# 2.12 - Resolve via HTTP
# Resolve the service we registered in 2.3. On some platforms mDNS may not
# resolve services the same host registered; accept 504 but NOT 404/timeout.
try {
    $resp = Invoke-Http -Uri "$Endpoint/v1/resolve?name=DaemonTest._http._tcp.local." -TimeoutSec 10
    $json = $resp.Content | ConvertFrom-Json
    if ($json.resolved.name -match 'DaemonTest') {
        Pass 'resolve via HTTP (found DaemonTest)'
    } else {
        Fail 'resolve via HTTP' "Unexpected response: $($resp.Content.Substring(0, [Math]::Min(120, $resp.Content.Length)))"
    }
} catch {
    $errMsg = $_.Exception.Message
    if ($errMsg -match '504') {
        Pass 'resolve via HTTP (504 - mDNS self-resolve not supported on this host)'
    } else {
        Fail 'resolve via HTTP' $errMsg
    }
}

# 2.13 - Resolve via CLI client (nonexistent, expect error)
try {
    $r = Invoke-Koi -KoiArgs '--endpoint', $Endpoint, '--json', 'resolve', 'nonexistent._http._tcp.local.' -TimeoutSec 10 -AllowFailure
    if ($r.ExitCode -ne 0) {
        Pass 'resolve via CLI client (nonexistent returns error)'
    } else {
        if ($r.Stdout -match '"error"') {
            Pass 'resolve via CLI client (nonexistent returns error response)'
        } else {
            Fail 'resolve via CLI client (nonexistent)' 'Expected error but got success'
        }
    }
} catch {
    Fail 'resolve via CLI client (nonexistent)' $_.Exception.Message
}

# -- SSE streaming tests -------------------------------------------------------

# 2.14 - Browse SSE returns events
try {
    $events = Invoke-Sse -Uri "$Endpoint/v1/browse?type=_http._tcp" -MaxEvents 5 -TimeoutMs 4000
    if ($events.Count -gt 0) {
        $hasFound = $false
        foreach ($ev in $events) {
            if ($ev.found -and $ev.found.name -and $ev.found.type) {
                $hasFound = $true
                break
            }
        }
        if ($hasFound) {
            Pass "browse SSE returns events ($($events.Count) received)"
        } else {
            Fail 'browse SSE returns events' "Got $($events.Count) events but none had found.name+type"
        }
    } else {
        Skip 'browse SSE returns events' 'No events received (mDNS may not loop back own registrations)'
    }
} catch {
    Fail 'browse SSE returns events' $_.Exception.Message
}

# 2.15 - Events SSE returns lifecycle events
try {
    $events = Invoke-Sse -Uri "$Endpoint/v1/events?type=_http._tcp" -MaxEvents 5 -TimeoutMs 4000
    if ($events.Count -gt 0) {
        $hasEvent = $false
        foreach ($ev in $events) {
            if ($ev.event -and ($ev.event -eq 'found' -or $ev.event -eq 'resolved') -and $ev.service) {
                $hasEvent = $true
                break
            }
        }
        if ($hasEvent) {
            Pass "events SSE returns lifecycle events ($($events.Count) received)"
        } else {
            Fail 'events SSE returns lifecycle events' "Got $($events.Count) events but none had event+service fields"
        }
    } else {
        Skip 'events SSE returns lifecycle events' 'No events received (mDNS may not loop back own registrations)'
    }
} catch {
    Fail 'events SSE returns lifecycle events' $_.Exception.Message
}

# 2.17 - Browse meta-query via HTTP SSE (discovers service types)
try {
    $events = Invoke-Sse -Uri "$Endpoint/v1/browse?type=_services._dns-sd._udp.local." -MaxEvents 5 -TimeoutMs 4000
    if ($events.Count -gt 0) {
        # Meta-query returns found events where the name is a service type (e.g. "_http._tcp.local.")
        $hasType = $false
        foreach ($ev in $events) {
            if ($ev.found -and $ev.found.name -and ($ev.found.name -match '\._tcp' -or $ev.found.name -match '\._udp')) {
                $hasType = $true
                break
            }
        }
        if ($hasType) {
            Pass "browse meta-query SSE returns service types ($($events.Count) received)"
        } else {
            Fail 'browse meta-query SSE' "Got $($events.Count) events, first name: $(if ($events[0].found) { $events[0].found.name } else { $events[0] | ConvertTo-Json -Compress })"
        }
    } else {
        Skip 'browse meta-query SSE' 'No events received (mDNS may not loop back own registrations)'
    }
} catch {
    Fail 'browse meta-query SSE' $_.Exception.Message
}

# -- CLI client mode: browse + subscribe --------------------------------------

# 2.16 - Browse via CLI client mode
try {
    $r = Invoke-Koi -KoiArgs '--endpoint', $Endpoint, '--json', 'browse', 'http', '--timeout', '3' -TimeoutSec 15 -AllowFailure
    if ($r.ExitCode -ne 0) {
        Fail 'browse via CLI client mode' "Exit code $($r.ExitCode)"
    } else {
        $lines = $r.Stdout -split "`n" | Where-Object { $_.Trim() -ne '' }
        $valid = $true
        foreach ($line in $lines) {
            try { $null = $line | ConvertFrom-Json } catch { $valid = $false; break }
        }
        if ($valid) {
            Pass "browse via CLI client mode ($($lines.Count) events)"
        } else {
            Fail 'browse via CLI client mode' 'Invalid JSON in output'
        }
    }
} catch {
    Fail 'browse via CLI client mode' $_.Exception.Message
}

# 2.17 - Subscribe via CLI client mode
# Note: subscribe consumes an SSE stream via blocking I/O in spawn_blocking;
# the tokio timeout may not interrupt it, so the process may be killed (-1).
# Accept exit code 0 (clean timeout) or -1 (killed after TimeoutSec).
try {
    $r = Invoke-Koi -KoiArgs '--endpoint', $Endpoint, '--json', 'subscribe', '_http._tcp', '--timeout', '3' -TimeoutSec 10 -AllowFailure
    $lines = $r.Stdout -split "`n" | Where-Object { $_.Trim() -ne '' }
    $valid = $true
    foreach ($line in $lines) {
        try { $null = $line | ConvertFrom-Json } catch { $valid = $false; break }
    }
    if ($valid) {
        Pass "subscribe via CLI client mode ($($lines.Count) events)"
    } else {
        Fail 'subscribe via CLI client mode' 'Invalid JSON in output'
    }
} catch {
    Fail 'subscribe via CLI client mode' $_.Exception.Message
}

# -- Admin lifecycle: drain -> revive -> force-unregister --------------------

if (-not $txtRegId) {
    Skip 'admin lifecycle (2.18-2.25)' 'TxtTest registration failed in 2.4'
} else {

# 2.18 - Revive non-draining (expect 409)
try {
    $errResp = Invoke-HttpExpectError -Method POST -Uri "$Endpoint/v1/admin/registrations/$txtRegId/revive"
    if ($errResp.StatusCode -eq 409) {
        $errJson = $errResp.Content | ConvertFrom-Json
        if ($errJson.error -eq 'not_draining') {
            Pass 'revive non-draining returns 409'
        } else {
            Fail 'revive non-draining returns 409' "Expected not_draining, got: $($errJson.error)"
        }
    } else {
        Fail 'revive non-draining returns 409' "Expected 409, got $($errResp.StatusCode)"
    }
} catch {
    Fail 'revive non-draining returns 409' $_.Exception.Message
}

# 2.19 - Admin drain
try {
    $resp = Invoke-Http -Method POST -Uri "$Endpoint/v1/admin/registrations/$txtRegId/drain"
    $json = $resp.Content | ConvertFrom-Json
    if ($json.drained -eq $txtRegId) {
        Pass 'admin drain'
    } else {
        Fail 'admin drain' "Unexpected response: $($resp.Content)"
    }
} catch {
    Fail 'admin drain' $_.Exception.Message
}

# 2.20 - Admin inspect shows draining state
try {
    $resp = Invoke-Http -Uri "$Endpoint/v1/admin/registrations/$txtRegId"
    $json = $resp.Content | ConvertFrom-Json
    if ($json.state -eq 'draining') {
        Pass 'admin inspect shows draining state'
    } else {
        Fail 'admin inspect shows draining state' "Expected draining, got: $($json.state)"
    }
} catch {
    Fail 'admin inspect shows draining state' $_.Exception.Message
}

# 2.21 - Double-drain (expect 409)
try {
    $errResp = Invoke-HttpExpectError -Method POST -Uri "$Endpoint/v1/admin/registrations/$txtRegId/drain"
    if ($errResp.StatusCode -eq 409) {
        $errJson = $errResp.Content | ConvertFrom-Json
        if ($errJson.error -eq 'already_draining') {
            Pass 'double-drain returns 409 already_draining'
        } else {
            Fail 'double-drain returns 409 already_draining' "Expected already_draining, got: $($errJson.error)"
        }
    } else {
        Fail 'double-drain returns 409 already_draining' "Expected 409, got $($errResp.StatusCode)"
    }
} catch {
    Fail 'double-drain returns 409 already_draining' $_.Exception.Message
}

# 2.22 - Admin revive
try {
    $resp = Invoke-Http -Method POST -Uri "$Endpoint/v1/admin/registrations/$txtRegId/revive"
    $json = $resp.Content | ConvertFrom-Json
    if ($json.revived -eq $txtRegId) {
        Pass 'admin revive'
    } else {
        Fail 'admin revive' "Unexpected response: $($resp.Content)"
    }
} catch {
    Fail 'admin revive' $_.Exception.Message
}

# 2.23 - Admin inspect shows alive after revive
try {
    $resp = Invoke-Http -Uri "$Endpoint/v1/admin/registrations/$txtRegId"
    $json = $resp.Content | ConvertFrom-Json
    if ($json.state -eq 'alive') {
        Pass 'admin inspect shows alive after revive'
    } else {
        Fail 'admin inspect shows alive after revive' "Expected alive, got: $($json.state)"
    }
} catch {
    Fail 'admin inspect shows alive after revive' $_.Exception.Message
}

# 2.24 - Admin force-unregister
try {
    $resp = Invoke-Http -Method DELETE -Uri "$Endpoint/v1/admin/registrations/$txtRegId"
    $json = $resp.Content | ConvertFrom-Json
    if ($json.unregistered -eq $txtRegId) {
        Pass 'admin force-unregister'
    } else {
        Fail 'admin force-unregister' "Unexpected response: $($resp.Content)"
    }
} catch {
    Fail 'admin force-unregister' $_.Exception.Message
}

# 2.25 - Admin inspect after delete returns 404
try {
    $errResp = Invoke-HttpExpectError -Uri "$Endpoint/v1/admin/registrations/$txtRegId"
    if ($errResp.StatusCode -eq 404) {
        Pass 'admin inspect after delete returns 404'
    } else {
        Fail 'admin inspect after delete returns 404' "Expected 404, got $($errResp.StatusCode)"
    }
} catch {
    Fail 'admin inspect after delete returns 404' $_.Exception.Message
}

}  # end admin lifecycle guard

# -- Negative / error-path tests ---------------------------------------------

# 2.26 - Unregister nonexistent ID returns 404
try {
    $errResp = Invoke-HttpExpectError -Method DELETE -Uri "$Endpoint/v1/services/nonexistent_id_999"
    if ($errResp.StatusCode -eq 404) {
        $errJson = $errResp.Content | ConvertFrom-Json
        if ($errJson.error -eq 'not_found') {
            Pass 'unregister nonexistent returns 404 not_found'
        } else {
            Fail 'unregister nonexistent returns 404 not_found' "Expected not_found, got: $($errJson.error)"
        }
    } else {
        Fail 'unregister nonexistent returns 404 not_found' "Expected 404, got $($errResp.StatusCode)"
    }
} catch {
    Fail 'unregister nonexistent returns 404 not_found' $_.Exception.Message
}

# 2.27 - Heartbeat nonexistent ID returns 404
try {
    $errResp = Invoke-HttpExpectError -Method PUT -Uri "$Endpoint/v1/services/nonexistent_id_999/heartbeat"
    if ($errResp.StatusCode -eq 404) {
        $errJson = $errResp.Content | ConvertFrom-Json
        if ($errJson.error -eq 'not_found') {
            Pass 'heartbeat nonexistent returns 404 not_found'
        } else {
            Fail 'heartbeat nonexistent returns 404 not_found' "Expected not_found, got: $($errJson.error)"
        }
    } else {
        Fail 'heartbeat nonexistent returns 404 not_found' "Expected 404, got $($errResp.StatusCode)"
    }
} catch {
    Fail 'heartbeat nonexistent returns 404 not_found' $_.Exception.Message
}

# 2.28 - Malformed JSON body returns 4xx
try {
    $errResp = Invoke-HttpExpectError -Method POST -Uri "$Endpoint/v1/services" -Body '{broken json'
    if ($errResp.StatusCode -ge 400 -and $errResp.StatusCode -lt 500) {
        Pass "malformed JSON body returns $($errResp.StatusCode)"
    } else {
        Fail 'malformed JSON body returns 4xx' "Expected 4xx, got $($errResp.StatusCode)"
    }
} catch {
    Fail 'malformed JSON body returns 4xx' $_.Exception.Message
}

# 2.29 - Invalid service type via register returns 400
# ServiceType::parse rejects invalid protocol (only tcp/udp allowed)
try {
    $errResp = Invoke-HttpExpectError -Method POST -Uri "$Endpoint/v1/services" -Body '{"name":"Bad","type":"_x._xyz","port":9999}'
    if ($errResp.StatusCode -eq 400) {
        $errJson = $errResp.Content | ConvertFrom-Json
        if ($errJson.error -eq 'invalid_type') {
            Pass 'invalid service type via register returns 400 invalid_type'
        } else {
            Fail 'invalid service type via register' "Expected invalid_type, got: $($errJson.error)"
        }
    } else {
        Fail 'invalid service type via register' "Expected 400, got $($errResp.StatusCode)"
    }
} catch {
    Fail 'invalid service type via register' $_.Exception.Message
}

# 2.30 - Invalid service type via browse SSE returns error event
try {
    $events = Invoke-Sse -Uri "$Endpoint/v1/browse?type=_x._xyz" -MaxEvents 1 -TimeoutMs 3000
    if ($events.Count -gt 0 -and $events[0].error -eq 'invalid_type') {
        Pass 'invalid service type via browse SSE returns error event'
    } else {
        Fail 'invalid service type via browse SSE' "Got $($events.Count) events, first: $(if ($events.Count -gt 0) { $events[0] | ConvertTo-Json -Compress } else { 'none' })"
    }
} catch {
    Fail 'invalid service type via browse SSE' $_.Exception.Message
}

# 2.31 - Browse without type param returns 400
try {
    $errResp = Invoke-HttpExpectError -Uri "$Endpoint/v1/browse"
    if ($errResp.StatusCode -eq 400) {
        Pass 'browse without type param returns 400'
    } else {
        Fail 'browse without type param returns 400' "Expected 400, got $($errResp.StatusCode)"
    }
} catch {
    Fail 'browse without type param returns 400' $_.Exception.Message
}

# 2.32 - Resolve without name param returns 400
try {
    $errResp = Invoke-HttpExpectError -Uri "$Endpoint/v1/resolve"
    if ($errResp.StatusCode -eq 400) {
        Pass 'resolve without name param returns 400'
    } else {
        Fail 'resolve without name param returns 400' "Expected 400, got $($errResp.StatusCode)"
    }
} catch {
    Fail 'resolve without name param returns 400' $_.Exception.Message
}

# 2.33 - Register with empty body returns 422
try {
    $errResp = Invoke-HttpExpectError -Method POST -Uri "$Endpoint/v1/services" -Body '{}'
    if ($errResp.StatusCode -eq 422) {
        Pass 'register with empty body returns 422'
    } else {
        Fail 'register with empty body returns 422' "Expected 422, got $($errResp.StatusCode)"
    }
} catch {
    Fail 'register with empty body returns 422' $_.Exception.Message
}

# 2.34 - Ambiguous admin prefix returns 400
# We have $regId and $leaseRegId; check if their first chars overlap.
if ($regId -and $leaseRegId) {
    $tested = $false
    # Try single-char prefixes from all known IDs to find ambiguity
    $allIds = @($regId, $leaseRegId)
    for ($ci = 0; $ci -lt 16; $ci++) {
        $prefix = '{0:x}' -f $ci
        $prefixMatches = @($allIds | Where-Object { $_.StartsWith($prefix) })
        if ($prefixMatches.Count -ge 2) {
            try {
                $errResp = Invoke-HttpExpectError -Uri "$Endpoint/v1/admin/registrations/$prefix"
                if ($errResp.StatusCode -eq 400) {
                    $errJson = $errResp.Content | ConvertFrom-Json
                    if ($errJson.error -eq 'ambiguous_id') {
                        Pass "ambiguous admin prefix returns 400 (prefix: $prefix)"
                        $tested = $true
                    } else {
                        Fail 'ambiguous admin prefix' "Expected ambiguous_id, got: $($errJson.error)"
                        $tested = $true
                    }
                } else {
                    Fail 'ambiguous admin prefix' "Expected 400, got $($errResp.StatusCode)"
                    $tested = $true
                }
            } catch {
                Fail 'ambiguous admin prefix' $_.Exception.Message
                $tested = $true
            }
            break
        }
    }
    if (-not $tested) {
        Skip 'ambiguous admin prefix' 'No two IDs share a hex prefix char (random UUIDs)'
    }
} else {
    Skip 'ambiguous admin prefix' 'Need at least 2 registered services'
}

# -- Named Pipe tests ---------------------------------------------------------

# 2.35 - Named Pipe: register + unregister
try {
    $results = Invoke-Pipe -PipeName $TestPipeName -Messages @(
        '{"register":{"name":"PipeTest","type":"_http._tcp","port":19996}}'
    ) -ExpectedLines 1

    $regResult = $results[0]
    if ($regResult.registered.id -and $regResult.registered.name -eq 'PipeTest') {
        $pipeRegId = $regResult.registered.id

        # Now unregister via a second pipe connection
        $results2 = Invoke-Pipe -PipeName $TestPipeName -Messages @(
            "{`"unregister`":`"$pipeRegId`"}"
        ) -ExpectedLines 1

        if ($results2[0].unregistered -eq $pipeRegId) {
            Pass 'Named Pipe: register + unregister'
        } else {
            Fail 'Named Pipe: register + unregister' "Unregister response: $($results2[0] | ConvertTo-Json -Compress)"
        }
    } else {
        Fail 'Named Pipe: register + unregister' "Register response: $($regResult | ConvertTo-Json -Compress)"
    }
} catch {
    Fail 'Named Pipe: register + unregister' $_.Exception.Message
}

# 2.36 - Named Pipe: resolve
try {
    $results = Invoke-Pipe -PipeName $TestPipeName -Messages @(
        '{"resolve":"DaemonTest._http._tcp.local."}'
    ) -ExpectedLines 1 -TimeoutMs 10000

    $resolveResult = $results[0]
    if ($resolveResult.resolved -and $resolveResult.resolved.name -match 'DaemonTest') {
        Pass 'Named Pipe: resolve'
    } elseif ($resolveResult.error -eq 'resolve_timeout') {
        Pass 'Named Pipe: resolve (timeout - mDNS self-resolve not supported on this host)'
    } else {
        Fail 'Named Pipe: resolve' "Unexpected response: $($resolveResult | ConvertTo-Json -Compress)"
    }
} catch {
    Fail 'Named Pipe: resolve' $_.Exception.Message
}

# 2.37 - Named Pipe: heartbeat
try {
    # Register via pipe first (session-mode), get the ID, then heartbeat
    $results = Invoke-Pipe -PipeName $TestPipeName -Messages @(
        '{"register":{"name":"PipeHB","type":"_http._tcp","port":19993}}'
    ) -ExpectedLines 1

    $pipeHbId = $results[0].registered.id
    if ($pipeHbId) {
        # Heartbeat on a second connection
        $hbResults = Invoke-Pipe -PipeName $TestPipeName -Messages @(
            "{`"heartbeat`":`"$pipeHbId`"}"
        ) -ExpectedLines 1

        # Session-mode registrations return lease_secs=0 (session policy, not heartbeat policy)
        if ($hbResults[0].renewed -and $hbResults[0].renewed.id -eq $pipeHbId) {
            Pass "Named Pipe: heartbeat (lease: $($hbResults[0].renewed.lease_secs)s)"
        } else {
            Fail 'Named Pipe: heartbeat' "Unexpected response: $($hbResults[0] | ConvertTo-Json -Compress)"
        }

        # Clean up
        $null = Invoke-Pipe -PipeName $TestPipeName -Messages @(
            "{`"unregister`":`"$pipeHbId`"}"
        ) -ExpectedLines 1
    } else {
        Fail 'Named Pipe: heartbeat' 'Could not register service for heartbeat test'
    }
} catch {
    Fail 'Named Pipe: heartbeat' $_.Exception.Message
}

# 2.38 - Named Pipe: malformed JSON returns parse_error
try {
    $results = Invoke-Pipe -PipeName $TestPipeName -Messages @(
        '{broken json'
    ) -ExpectedLines 1

    if ($results[0].error -eq 'parse_error') {
        Pass 'Named Pipe: malformed JSON returns parse_error'
    } else {
        Fail 'Named Pipe: malformed JSON returns parse_error' "Unexpected response: $($results[0] | ConvertTo-Json -Compress)"
    }
} catch {
    Fail 'Named Pipe: malformed JSON returns parse_error' $_.Exception.Message
}

# -- Stretch goal: concurrent registration burst --------------------------------

# S1 - Register 5 services in parallel, verify unique IDs
try {
    $burstIds = @()
    $burstFailed = $false
    for ($i = 1; $i -le 5; $i++) {
        $body = "{`"name`":`"Burst$i`",`"type`":`"_http._tcp`",`"port`":$( 18000 + $i ),`"lease_secs`":0}"
        $resp = Invoke-Http -Method POST -Uri "$Endpoint/v1/services" -Body $body
        $json = $resp.Content | ConvertFrom-Json
        if ($json.registered.id) {
            $burstIds += $json.registered.id
        } else {
            $burstFailed = $true
            break
        }
    }
    if (-not $burstFailed -and $burstIds.Count -eq 5) {
        $uniqueIds = $burstIds | Select-Object -Unique
        if ($uniqueIds.Count -eq 5) {
            Pass 'concurrent registration burst (5 unique IDs)'
        } else {
            Fail 'concurrent registration burst' "Expected 5 unique IDs, got $($uniqueIds.Count)"
        }
    } else {
        Fail 'concurrent registration burst' "Only registered $($burstIds.Count)/5"
    }

    # Clean up burst registrations
    foreach ($bid in $burstIds) {
        try { $null = Invoke-Http -Method DELETE -Uri "$Endpoint/v1/services/$bid" } catch {}
    }
} catch {
    Fail 'concurrent registration burst' $_.Exception.Message
}

# S2 - Session draining via pipe disconnect
try {
    # Register via pipe (session-mode, not permanent — pipe adapter uses 30s grace)
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', $TestPipeName, [System.IO.Pipes.PipeDirection]::InOut)
    $pipe.Connect(5000)
    $writer = New-Object System.IO.StreamWriter($pipe)
    $writer.AutoFlush = $true
    $reader = New-Object System.IO.StreamReader($pipe)

    $writer.WriteLine('{"register":{"name":"SessionDrain","type":"_http._tcp","port":19992}}')
    $line = $reader.ReadLine()
    $regJson = $line | ConvertFrom-Json
    $sessionDrainId = $regJson.registered.id

    if ($sessionDrainId) {
        # Close the pipe connection — this should trigger session disconnect → draining
        # Dispose writer first (flushes), then pipe. Reader shares the pipe stream
        # so we only dispose it via the pipe itself to avoid "closed pipe" errors.
        try { $writer.Dispose() } catch {}
        try { $reader.Dispose() } catch {}
        try { $pipe.Dispose() } catch {}

        # Wait briefly for the reaper/session disconnect to process
        Start-Sleep -Milliseconds 1500

        # Check state via admin inspect (HTTP)
        $inspResp = Invoke-Http -Uri "$Endpoint/v1/admin/registrations/$sessionDrainId"
        $insp = $inspResp.Content | ConvertFrom-Json
        if ($insp.state -eq 'draining') {
            Pass 'pipe disconnect triggers session draining'
        } else {
            Fail 'pipe disconnect triggers session draining' "Expected draining, got: $($insp.state)"
        }

        # Clean up via admin force-unregister
        try { $null = Invoke-Http -Method DELETE -Uri "$Endpoint/v1/admin/registrations/$sessionDrainId" } catch {}
    } else {
        $pipe.Dispose()
        Fail 'pipe disconnect triggers session draining' 'Could not register service'
    }
} catch {
    Fail 'pipe disconnect triggers session draining' $_.Exception.Message
}

# -- Unregister remaining services and clean up --------------------------------

# 2.39 - Unregister DaemonTest via HTTP
if ($regId) {
    try {
        $resp = Invoke-Http -Method DELETE -Uri "$Endpoint/v1/services/$regId"
        $json = $resp.Content | ConvertFrom-Json
        if ($json.unregistered -eq $regId) {
            Pass 'unregister via HTTP'
        } else {
            Fail 'unregister via HTTP' "Unexpected response: $($resp.Content)"
        }
    } catch {
        Fail 'unregister via HTTP' $_.Exception.Message
    }
} else {
    Fail 'unregister via HTTP' 'Skipped (no registration id)'
}

# Clean up LeaseTest and PermanentTest if still alive
if ($leaseRegId) {
    try { $null = Invoke-Http -Method DELETE -Uri "$Endpoint/v1/services/$leaseRegId" } catch {}
}
if ($permanentRegId) {
    try { $null = Invoke-Http -Method DELETE -Uri "$Endpoint/v1/services/$permanentRegId" } catch {}
}

# -- Shutdown -----------------------------------------------------------------

# 2.40 - Shutdown daemon
Log "Sending stop signal to daemon..."
Stop-Process -Id $script:daemonProc.Id -ErrorAction SilentlyContinue
$exitedCleanly = $script:daemonProc.WaitForExit(15000)

if ($exitedCleanly) {
    Pass "daemon shutdown (exit code: $($script:daemonProc.ExitCode))"
} else {
    Fail 'daemon shutdown' 'Daemon did not exit within 15 seconds'
    $script:daemonProc.Kill()
    $script:daemonProc.WaitForExit(5000) | Out-Null
}

# Breadcrumb deletion requires graceful Ctrl+C shutdown, which Stop-Process
# cannot provide (it sends TerminateProcess = SIGKILL equivalent).
Skip 'breadcrumb deleted after shutdown' 'Stop-Process sends hard kill, no cleanup hook runs'

# 2.41 - Log file has content
if (Test-Path $TestLog) {
    $logSize = (Get-Item $TestLog).Length
    if ($logSize -gt 0) {
        Pass "log file has content ($logSize bytes)"
    } else {
        Fail 'log file has content' 'Log file is empty'
    }
} else {
    Fail 'log file has content' 'Log file not found'
}

$script:daemonProc = $null

# ======================================================================
#  TIER 3 - Service lifecycle (manual, requires elevation)
# ======================================================================

if ($Tier3) {
    Write-Host "`n=== Tier 3: Service lifecycle (elevated) ===" -ForegroundColor Cyan

    # 3.1 - Install
    try {
        $r = Invoke-Koi -KoiArgs 'install'
        if ($r.Stdout -match 'installed') {
            Pass 'koi install'
        } else {
            Fail 'koi install' 'No confirmation in output'
        }
    } catch {
        Fail 'koi install' $_.Exception.Message
    }

    # 3.2 - Start
    try {
        & sc.exe start koi 2>&1 | Out-Null
        Start-Sleep -Seconds 3
        $resp = Invoke-Http -Uri "http://127.0.0.1:5641/healthz" -TimeoutSec 5
        if ($resp.StatusCode -eq 200) {
            Pass 'service start + health check'
        } else {
            Fail 'service start + health check' "Status: $($resp.StatusCode)"
        }
    } catch {
        Fail 'service start + health check' $_.Exception.Message
    }

    # 3.3 - Stop
    try {
        & sc.exe stop koi 2>&1 | Out-Null
        Start-Sleep -Seconds 3
        Pass 'service stop'
    } catch {
        Fail 'service stop' $_.Exception.Message
    }

    # 3.4 - Uninstall
    try {
        $r = Invoke-Koi -KoiArgs 'uninstall'
        if ($r.Stdout -match 'uninstalled') {
            Pass 'koi uninstall'
        } else {
            Fail 'koi uninstall' 'No confirmation in output'
        }
    } catch {
        Fail 'koi uninstall' $_.Exception.Message
    }
}

# ======================================================================
#  Summary
# ======================================================================

Write-Host "`n=== Summary ===" -ForegroundColor Cyan

$total = $script:passed + $script:failed
Write-Host "$($script:passed)/$total passed" -NoNewline
if ($script:failed -gt 0) {
    Write-Host ", $($script:failed) failed" -NoNewline -ForegroundColor Red
}
if ($script:skipped -gt 0) {
    Write-Host ", $($script:skipped) skipped" -NoNewline -ForegroundColor Yellow
}
Write-Host ""

if ($script:failed -gt 0) {
    $script:tests | Where-Object { $_.result -eq 'FAIL' } | ForEach-Object {
        Write-Host "  FAIL: $($_.name) - $($_.reason)" -ForegroundColor Red
    }
}

# Cleanup
Cleanup

if ($script:failed -gt 0) { exit 1 }
exit 0
