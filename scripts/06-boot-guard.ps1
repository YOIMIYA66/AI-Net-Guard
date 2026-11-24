<#
.SYNOPSIS
    AI-Net-Guard v5.9.3 - cross-reboot safety net for the restart drill.

.DESCRIPTION
    After 08-commit.ps1 the normal auto-rollback task is gone, which is what
    makes the reboot test meaningful. To keep a safety net across the reboot,
    arm this boot guard BEFORE rebooting:

        .\06-boot-guard.ps1 -Arm -WindowMinutes 30 -WaitMinutes 10

    It registers a task that runs at startup, waits WaitMinutes, and then:
      * inside the armed window  -> runs 09-rollback.ps1 -Auto
      * outside the window       -> does nothing
    Either way it removes itself, so it cannot fire on a later boot.

    After the reboot verification passes, disarm it:

        .\06-boot-guard.ps1 -Remove

    -Status prints what is armed right now.

.NOTES
    Must be elevated. The guard is deliberately simple and self-deleting; it is
    not a replacement for having physical access to the machine.
#>

[CmdletBinding()]
param(
    [string]$Root = $(if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\AI-Net-Guard' }),
    [switch]$Arm,
    [switch]$Remove,
    [switch]$Status,
    [switch]$RunIfArmed,
    [int]$WindowMinutes = 30,
    [int]$WaitMinutes = 10
)

$ErrorActionPreference = 'Stop'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'ERROR: run this script in an elevated PowerShell.' -ForegroundColor Red
    exit 1
}

$TaskName = 'AI-Guard-Boot-Guard'
$Dir = Join-Path $Root 'backup'
$Marker = Join-Path $Dir 'boot-guard.json'
$Self = $MyInvocation.MyCommand.Path

if (-not $Self) { $Self = if (Test-Path (Join-Path (Join-Path $Root 'scripts') '06-boot-guard.ps1')) { Join-Path (Join-Path $Root 'scripts') '06-boot-guard.ps1' } else { Join-Path $Root '06-boot-guard.ps1' } }

$libCommonBg = ''
foreach ($cand in @((Join-Path $PSScriptRoot 'lib-guard-common.ps1'), (Join-Path (Join-Path $Root 'scripts') 'lib-guard-common.ps1'), (Join-Path $Root 'lib-guard-common.ps1'))) {
    if ($cand -and (Test-Path -LiteralPath $cand)) { $libCommonBg = $cand; break }
}
if (-not $libCommonBg) {
    Write-Host '[!] lib-guard-common.ps1 missing - cannot verify install ACL before registering boot guard' -ForegroundColor Red
    exit 1
}
. $libCommonBg

function Show-State {
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($t) { Write-Host ('task: REGISTERED (' + $t.State + ')') -ForegroundColor Yellow }
    else { Write-Host 'task: not registered' -ForegroundColor DarkGray }
    if (Test-Path $Marker) {
        $m = Get-Content -LiteralPath $Marker -Raw -Encoding UTF8 | ConvertFrom-Json
        Write-Host ('armed until: ' + $m.ArmedUntil + '  wait: ' + $m.WaitMinutes + ' min') -ForegroundColor Yellow
    }
    else { Write-Host 'marker: none' -ForegroundColor DarkGray }
}

# ------------------------------------------------------------------ boot-run mode
# When the scheduled task calls this script it passes -RunIfArmed; no prompts.
if ($RunIfArmed) {
    $wait = 10
    if (Test-Path $Marker) {
        try { $wait = [int](Get-Content -LiteralPath $Marker -Raw -Encoding UTF8 | ConvertFrom-Json).WaitMinutes } catch { }
    }
    Start-Sleep -Minutes $wait
    $armed = $false
    if (Test-Path $Marker) {
        try {
            $m = Get-Content -LiteralPath $Marker -Raw -Encoding UTF8 | ConvertFrom-Json
            if ((Get-Date) -lt ([datetime]$m.ArmedUntil)) { $armed = $true }
        }
        catch { }
    }
    $bootGuardExit = 0
    if ($armed) {
        Write-Host 'boot guard: armed window still open, rolling back' -ForegroundColor Yellow
        $rbPath = if (Test-Path (Join-Path (Join-Path $Root 'scripts') '09-rollback.ps1')) { Join-Path (Join-Path $Root 'scripts') '09-rollback.ps1' } else { Join-Path $Root '09-rollback.ps1' }
        $global:LASTEXITCODE = 0
        try {
            & $rbPath -Auto -Root $Root
            if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {
                $bootGuardExit = [int]$LASTEXITCODE
                Write-Host ('[!] boot guard: rollback returned non-zero exit code ' + $bootGuardExit) -ForegroundColor Red
            }
        }
        catch {
            $bootGuardExit = 1
            Write-Host ('[!] boot guard: rollback threw an error: ' + $_.Exception.Message) -ForegroundColor Red
        }
    }
    else {
        Write-Host 'boot guard: window expired or marker missing, doing nothing'
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue
    exit $bootGuardExit
}

# ------------------------------------------------------------------ interactive modes
if ($Status -or (-not $Arm -and -not $Remove)) {
    Show-State
    if (-not $Arm -and -not $Remove) {
        Write-Host ''
        Write-Host 'usage: -Arm | -Remove | -Status'
    }
    return
}

if ($Remove) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue
    Write-Host '[+] boot guard removed' -ForegroundColor Green
    return
}

if ($Arm) {
    $aclIssues = @(Get-GuardInstallAclIssues -Path $Root)
    if ($aclIssues.Count -gt 0) {
        throw ('Refusing to register SYSTEM boot-guard task on untrusted install ACL: ' + ($aclIssues -join '; ') + '. Run 13-harden-acl.ps1 first.')
    }

    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    [pscustomobject]@{
        ArmedUntil  = ((Get-Date).AddMinutes($WindowMinutes)).ToString('o')
        WaitMinutes = $WaitMinutes
        Created     = (Get-Date).ToString('o')
    } | ConvertTo-Json | Set-Content -LiteralPath $Marker -Encoding UTF8

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $Self + '" -RunIfArmed -Root "' + $Root + '"')
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null

    Write-Host '[+] boot guard armed' -ForegroundColor Green
    Write-Host ('    window: ' + $WindowMinutes + ' min, rollback runs ' + $WaitMinutes + ' min after boot')
    Write-Host '    Now reboot, verify, then run: .\06-boot-guard.ps1 -Remove'
    Write-Host '    If the machine is broken after reboot it restores itself automatically.' -ForegroundColor Yellow
}
