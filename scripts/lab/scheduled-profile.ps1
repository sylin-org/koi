#Requires -Version 7.2

<#
.SYNOPSIS
  Install or run Koi's weekly physical-lab release gate on Windows.

.DESCRIPTION
  This script is deliberately a thin operating-system adapter. It builds Koi locally, then
  delegates the complete hardware policy to `koi-lab run-profile full`. Test membership,
  assertions, deployment, cleanup, baseline comparison, and evidence publication remain in
  koi-lab.

  Install stores the dedicated lab password as a CurrentUser DPAPI ciphertext outside the
  repository and registers one highest-privilege Task Scheduler task for the same interactive
  Windows user. The password is never written to the task definition, scheduler action arguments,
  repository, transcript, or Koi evidence. The existing PuTTY transport still receives the
  throwaway lab credential through KOI_LAB_PASSWORD. Because the task uses the existing interactive
  token, that user must be logged on when the trigger fires.

.EXAMPLE
  pwsh scripts/lab/scheduled-profile.ps1 -Plan

.EXAMPLE
  # Run from an elevated PowerShell session. Prompts once for the lab password.
  pwsh scripts/lab/scheduled-profile.ps1 -Install

.EXAMPLE
  # Exact, explicit removal. Existing scheduler logs and Koi evidence are retained.
  pwsh scripts/lab/scheduled-profile.ps1 -Remove
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Plan')]
    [switch] $Plan,

    [Parameter(Mandatory = $true, ParameterSetName = 'Install')]
    [switch] $Install,

    [Parameter(Mandatory = $true, ParameterSetName = 'Run')]
    [switch] $Run,

    [Parameter(Mandatory = $true, ParameterSetName = 'Remove')]
    [switch] $Remove,

    [Parameter(ParameterSetName = 'Plan')]
    [Parameter(ParameterSetName = 'Install')]
    [System.DayOfWeek] $DayOfWeek = [System.DayOfWeek]::Monday,

    [Parameter(ParameterSetName = 'Plan')]
    [Parameter(ParameterSetName = 'Install')]
    [TimeSpan] $At = ([TimeSpan]::FromHours(3))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:TaskName = 'Koi v1 full profile'
$script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:StateRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Koi\lab-scheduler'
$script:CredentialPath = Join-Path $script:StateRoot 'lab-password.dpapi'
$script:LogRoot = Join-Path $script:StateRoot 'logs'

function Assert-Windows {
    if (-not $IsWindows) {
        throw 'The physical-lab scheduler adapter requires Windows and Task Scheduler.'
    }
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-AccountSid {
    param([Parameter(Mandatory = $true)][string] $Account)

    if ($Account.StartsWith('S-1-', [StringComparison]::OrdinalIgnoreCase)) {
        return $Account
    }
    ([Security.Principal.NTAccount]::new($Account)).Translate(
        [Security.Principal.SecurityIdentifier]
    ).Value
}

function Assert-Administrator {
    if (-not (Test-Administrator)) {
        throw 'This operation requires an elevated PowerShell process.'
    }
}

function Assert-Schedule {
    if ($At -lt [TimeSpan]::Zero -or $At -ge [TimeSpan]::FromDays(1)) {
        throw '-At must be a time between 00:00:00 and 23:59:59.'
    }
}

function Get-TaskActionArguments {
    $scriptPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($scriptPath) -or $scriptPath.Contains('"')) {
        throw 'The scheduler script path is unavailable or cannot be safely quoted.'
    }
    '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Run' -f $scriptPath
}

function Get-ScheduleDescription {
    Assert-Schedule
    $clock = ([DateTime]::Today + $At).ToString('HH:mm:ss')
    "Every $DayOfWeek at $clock local time"
}

function Show-Plan {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $pwshPath = (Get-Process -Id $PID).Path
    [pscustomobject]@{
        TaskName           = $script:TaskName
        Schedule           = Get-ScheduleDescription
        RunAs              = $identity
        RunLevel           = 'Highest'
        LogonRequirement   = 'The same Windows user must be logged on'
        PowerShell         = $pwshPath
        Repository         = $script:RepoRoot
        CredentialStorage  = "$($script:CredentialPath) (CurrentUser DPAPI ciphertext)"
        TranscriptStorage  = $script:LogRoot
        EvaluationBoundary = 'koi-lab recover-profile, then run-profile full --allow-system-mutation'
        BuildBoundary      = 'koi-lab build (Windows native + Linux cross/Docker, both local)'
    }
}

function Install-LabTask {
    Assert-Administrator
    Assert-Schedule

    $existing = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        throw "Scheduled task '$($script:TaskName)' already exists; remove it explicitly before reinstalling."
    }

    $description = Get-ScheduleDescription
    if (-not $PSCmdlet.ShouldProcess($script:TaskName, "store a DPAPI credential and register: $description")) {
        return
    }

    $securePassword = Read-Host 'Dedicated Koi lab password' -AsSecureString
    if ($securePassword.Length -eq 0) {
        $securePassword.Dispose()
        throw 'The dedicated lab password cannot be empty.'
    }

    $stateRootExisted = Test-Path -LiteralPath $script:StateRoot -PathType Container
    $credentialCreated = $false
    $taskRegistered = $false
    try {
        New-Item -ItemType Directory -Path $script:StateRoot -Force | Out-Null
        New-Item -ItemType Directory -Path $script:LogRoot -Force | Out-Null

        $ciphertext = ConvertFrom-SecureString -SecureString $securePassword
        Set-Content -LiteralPath $script:CredentialPath -Value $ciphertext -Encoding utf8NoBOM -NoNewline
        $credentialCreated = $true

        $pwshPath = (Get-Process -Id $PID).Path
        $action = New-ScheduledTaskAction `
            -Execute $pwshPath `
            -Argument (Get-TaskActionArguments) `
            -WorkingDirectory $script:RepoRoot
        $trigger = New-ScheduledTaskTrigger `
            -Weekly `
            -WeeksInterval 1 `
            -DaysOfWeek $DayOfWeek `
            -At ([DateTime]::Today + $At)
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-ScheduledTaskPrincipal `
            -UserId $identity.User.Value `
            -LogonType Interactive `
            -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet `
            -StartWhenAvailable `
            -ExecutionTimeLimit ([TimeSpan]::FromHours(6)) `
            -MultipleInstances IgnoreNew `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries
        $task = New-ScheduledTask `
            -Action $action `
            -Trigger $trigger `
            -Principal $principal `
            -Settings $settings `
            -Description 'Build Koi locally and run the centralized three-machine full profile. Requires the user to be logged on.'

        Register-ScheduledTask -TaskName $script:TaskName -InputObject $task | Out-Null
        $taskRegistered = $true

        $registered = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction Stop
        $registeredAction = @($registered.Actions)
        $mismatches = [Collections.Generic.List[string]]::new()
        if ($registeredAction.Count -ne 1) {
            $mismatches.Add('action count')
        }
        else {
            if (-not [StringComparer]::OrdinalIgnoreCase.Equals($registeredAction[0].Execute, $pwshPath)) {
                $mismatches.Add('PowerShell executable')
            }
            if ($registeredAction[0].Arguments -cne (Get-TaskActionArguments)) {
                $mismatches.Add('secret-free arguments')
            }
            if (-not [StringComparer]::OrdinalIgnoreCase.Equals(
                $registeredAction[0].WorkingDirectory.TrimEnd('\'),
                $script:RepoRoot.TrimEnd('\')
            )) {
                $mismatches.Add('working directory')
            }
        }
        if ((Resolve-AccountSid $registered.Principal.UserId) -ne $identity.User.Value) {
            $mismatches.Add('interactive user SID')
        }
        if ([string]$registered.Principal.RunLevel -ne 'Highest') {
            $mismatches.Add('highest run level')
        }
        if ([string]$registered.Principal.LogonType -ne 'Interactive') {
            $mismatches.Add('interactive-token logon')
        }
        if ($mismatches.Count -ne 0) {
            throw "Task Scheduler changed the registration contract: $($mismatches -join ', ')."
        }
        Write-Output "Installed '$($script:TaskName)': $description."
        Write-Output 'The task runs elevated only while this Windows user is logged on.'
    }
    catch {
        if ($taskRegistered) {
            Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        if ($credentialCreated -and (Test-Path -LiteralPath $script:CredentialPath -PathType Leaf)) {
            Remove-Item -LiteralPath $script:CredentialPath -Force
        }
        if (-not $stateRootExisted -and (Test-Path -LiteralPath $script:StateRoot -PathType Container)) {
            $children = Get-ChildItem -LiteralPath $script:StateRoot -Force
            if ($children.Count -eq 0) {
                Remove-Item -LiteralPath $script:StateRoot
            }
        }
        throw
    }
    finally {
        $securePassword.Dispose()
    }
}

function Assert-CleanWorktree {
    $changes = @(& git -C $script:RepoRoot status --porcelain=v1 --untracked-files=normal)
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect the Git worktree (exit $LASTEXITCODE)."
    }
    if ($changes.Count -ne 0) {
        throw 'Scheduled release evidence requires a clean Git worktree.'
    }
}

function Invoke-Cargo {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Arguments,
        [Parameter(Mandatory = $true)]
        [string] $Description
    )

    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed (exit $LASTEXITCODE)."
    }
}

function Invoke-LabProfile {
    Assert-Administrator
    Assert-CleanWorktree

    if (-not (Test-Path -LiteralPath $script:CredentialPath -PathType Leaf)) {
        throw "The DPAPI lab credential is absent: $($script:CredentialPath)"
    }

    New-Item -ItemType Directory -Path $script:LogRoot -Force | Out-Null
    $logPath = Join-Path $script:LogRoot ("full-{0}.log" -f [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
    $transcriptStarted = $false
    $securePassword = $null
    $plainPassword = $null
    try {
        Start-Transcript -LiteralPath $logPath -Force | Out-Null
        $transcriptStarted = $true
        Push-Location $script:RepoRoot
        try {
            $ciphertext = Get-Content -LiteralPath $script:CredentialPath -Raw
            $securePassword = ConvertTo-SecureString -String $ciphertext
            $credential = [PSCredential]::new('koi-lab', $securePassword)
            $plainPassword = $credential.GetNetworkCredential().Password
            if ([string]::IsNullOrEmpty($plainPassword)) {
                throw 'The DPAPI lab credential decrypted to an empty value.'
            }

            $env:KOI_LAB_PASSWORD = $plainPassword
            try {
                Invoke-Cargo `
                    -Arguments @('run', '-p', 'koi-lab', '--locked', '--', 'recover-profile') `
                    -Description 'Interrupted Koi lab profile recovery'
            }
            finally {
                Remove-Item Env:KOI_LAB_PASSWORD -ErrorAction SilentlyContinue
            }

            Invoke-Cargo `
                -Arguments @('run', '-p', 'koi-lab', '--locked', '--', 'build') `
                -Description 'Local Koi lab build'

            $env:KOI_LAB_PASSWORD = $plainPassword
            Invoke-Cargo `
                -Arguments @('run', '-p', 'koi-lab', '--locked', '--', 'run-profile', 'full', '--allow-system-mutation') `
                -Description 'Koi full physical-lab profile'
        }
        finally {
            Remove-Item Env:KOI_LAB_PASSWORD -ErrorAction SilentlyContinue
            $plainPassword = $null
            $credential = $null
            Pop-Location
        }
        Write-Output "Scheduled full profile passed. Transcript: $logPath"
    }
    finally {
        if ($null -ne $securePassword) {
            $securePassword.Dispose()
        }
        if ($transcriptStarted) {
            Stop-Transcript | Out-Null
        }
    }
}

function Remove-LabTask {
    Assert-Administrator
    if (-not $PSCmdlet.ShouldProcess($script:TaskName, 'unregister the task and delete its exact DPAPI credential')) {
        return
    }

    $existing = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false
    }
    if (Test-Path -LiteralPath $script:CredentialPath -PathType Leaf) {
        Remove-Item -LiteralPath $script:CredentialPath -Force
    }
    Write-Output "Removed task '$($script:TaskName)' and its exact DPAPI credential. Logs and .lab-runs evidence were retained."
}

try {
    Assert-Windows
    if ($Plan) {
        Show-Plan
    }
    elseif ($Install) {
        Install-LabTask
    }
    elseif ($Run) {
        Invoke-LabProfile
    }
    elseif ($Remove) {
        Remove-LabTask
    }
}
catch {
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    exit 1
}
