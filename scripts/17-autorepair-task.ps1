<#
.SYNOPSIS
    AI-Net-Guard v5.8.5 - network auto-repair scheduled tasks (status / install / remove / self-test).

.DESCRIPTION
    Windows can invalidate part of the static guard without any user action: a NIC
    is re-enumerated after docking or a Wi-Fi switch, the TUN adapter comes back
    with a new ifIndex, a sleep / modern-standby resume drops the DNS baseline, or
    a third-party installer adds an Outbound Allow rule. Two zero-resident tasks
    repair that drift and this script owns them:

      AI-Guard-Mode-Event
          Boot + NetworkProfile Event ID 10000/10001 (TUN or NIC connect and
          disconnect) + sleep / modern-standby resume (Power-Troubleshooter 1,
          Kernel-Power 107 and 507). Event driven: there is no polling loop and
          no idle RAM cost.

      AI-Guard-Mode-Fallback
          Periodic check, default every 60 minutes. A healthy run costs one
          PowerShell start-up plus the guard's zero-CIM fast path; measured 5.1 s
          of wall clock per fire on this machine in SYSTEM context (2026-11-22,
          after the v5.8.0 drift-gate rebuild; it was ~17 s before that).

      The event task deliberately does more than the periodic one: it re-verifies
      the whole guard, re-syncs node rules and TUN allowances, and waits an extra
      800 ms for Wintun to settle. Both paths now land at ~5 s on this class of
      hardware - the difference is the extra work, not the process start-up, since
      a bare PowerShell process plus the 148 KB script parse already costs 1.3 s.
      The event task runs only on an actual network transition or wake, never on a
      timer.

    Both tasks invoke 07-mode.ps1, so repair logic is never duplicated here.

    Modes (-Status is the default):
        .\17-autorepair-task.ps1                      task state and last result
        .\17-autorepair-task.ps1 -Install             (re)register and verify
        .\17-autorepair-task.ps1 -Install -SelfTest   fire the event task twice and
                                                      the fallback once, require exit 0
        .\17-autorepair-task.ps1 -Remove              remove every AI-Guard-Mode-* task

.PARAMETER Root
    Install root that owns scripts\07-mode.ps1. Defaults to the parent of this
    script directory when the script lives in scripts\, otherwise C:\AI-Net-Guard.

.PARAMETER IntervalMinutes
    Repetition period of AI-Guard-Mode-Fallback. Clamped to 5..1440, default 60.

.PARAMETER TimeoutSeconds
    Upper bound for one -SelfTest event run. Default 180.

.PARAMETER SelfTest
    After -Install, start AI-Guard-Mode-Event twice (first fire repairs, second
    measures the steady state) and AI-Guard-Mode-Fallback once, wait for each to
    finish and require exit code 0 from all three. Prints the measured wall-clock
    duration of every run.

.NOTES
    -Install / -Remove / -SelfTest require an elevated shell because the tasks run
    as SYSTEM with RunLevel Highest.

    -Status does run unelevated, but a standard user token cannot enumerate these
    SYSTEM task objects at all (that is also why C:\Windows\System32\Tasks looks
    empty), so an unelevated -Status reports INCONCLUSIVE instead of guessing.
    Always confirm with an elevated -Status.

    Exit codes:
        0 ok or inconclusive | 1 not elevated | 2 task missing | 3 install or remove failed | 4 self-test failed
#>

[CmdletBinding()]
param(
    [string]$Root = '',
    [switch]$Install,
    [switch]$Remove,
    [switch]$Status,
    [switch]$SelfTest,
    [int]$IntervalMinutes = 60,
    [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'

$EventTask = 'AI-Guard-Mode-Event'
$FallbackTask = 'AI-Guard-Mode-Fallback'

if (-not $Root) {
    $selfDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    if ((Split-Path -Leaf $selfDir) -eq 'scripts') { $Root = Split-Path -Parent $selfDir }
    else { $Root = $selfDir }
}
$Root = $Root.TrimEnd('\')

# ------------------------------------------------------------------ helpers
function Test-Elevated {
    try {
        $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
        $wp = New-Object Security.Principal.WindowsPrincipal($wi)
        return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Get-ModeScriptPath {
    foreach ($p in @((Join-Path $Root 'scripts\07-mode.ps1'), (Join-Path $Root '07-mode.ps1'))) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return ''
}

$script:IsElevated = Test-Elevated

function Format-TaskResult($code) {
    if ($null -eq $code) { return 'n/a' }
    switch ([int64]$code) {
        0 { return '0 (success)' }
        267008 { return '267008 (still running)' }
        267009 { return '267009 (still running)' }
        267011 { return '267011 (never ran yet)' }
        267014 { return '267014 (terminated by user or policy)' }
        default { return ([string]$code) }
    }
}

function Get-TaskSnapshot([string]$Name) {
    $t = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if (-not $t) { return $null }
    $info = $null
    try { $info = Get-ScheduledTaskInfo -TaskName $Name -ErrorAction SilentlyContinue } catch { $info = $null }
    $kinds = @()
    foreach ($tg in @($t.Triggers)) {
        $cn = [string]$tg.CimClass.CimClassName
        $cn = $cn -replace '^MSFT_Task', ''
        $cn = $cn -replace 'Trigger$', ''
        if ($cn -and ($kinds -notcontains $cn)) { $kinds += $cn }
    }
    $lastRun = $null
    $result = $null
    $nextRun = $null
    if ($info) {
        if ($info.LastRunTime -and $info.LastRunTime.Year -gt 1999) { $lastRun = $info.LastRunTime }
        $result = $info.LastTaskResult
        $nextRun = $info.NextRunTime
    }
    return [pscustomobject]@{
        Name     = $Name
        State    = [string]$t.State
        Triggers = ($kinds -join '+')
        LastRun  = $lastRun
        Result   = $result
        NextRun  = $nextRun
    }
}

function Show-Tasks {
    Write-Host ' '
    Write-Host '=== AI-Net-Guard auto-repair tasks (read-only) ===' -ForegroundColor Cyan
    Write-Host ('root : ' + $Root)
    $mode = Get-ModeScriptPath
    if ($mode) { Write-Host ('mode : ' + $mode) }
    else { Write-Host 'mode : 07-mode.ps1 NOT FOUND (repair task would fail)' -ForegroundColor Red }
    if ($script:IsElevated) {
        Write-Host 'session: elevated (task visibility complete)' -ForegroundColor DarkGray
    }
    else {
        Write-Host 'session: NOT elevated - SYSTEM task objects are not enumerable here,' -ForegroundColor Yellow
        Write-Host '         so a MISSING line below can be a false negative. Verify elevated.' -ForegroundColor Yellow
    }
    Write-Host ' '

    $found = 0
    foreach ($name in @($EventTask, $FallbackTask)) {
        $snap = Get-TaskSnapshot $name
        if (-not $snap) {
            Write-Host ('  ' + $name.PadRight(24) + ' MISSING') -ForegroundColor Red
            Write-Host '      run: .\17-autorepair-task.ps1 -Install' -ForegroundColor DarkGray
            continue
        }
        $found++
        $color = if ($snap.State -eq 'Ready' -or $snap.State -eq 'Running') { 'Green' } else { 'Yellow' }
        Write-Host ('  ' + $name.PadRight(24) + ' ' + $snap.State.ToUpper()) -ForegroundColor $color
        Write-Host ('      triggers : ' + $snap.Triggers)
        $lastTxt = if ($snap.LastRun) { $snap.LastRun.ToString('yyyy-MM-dd HH:mm:ss') } else { 'never' }
        $nextTxt = if ($snap.NextRun -and $snap.NextRun.Year -gt 1999) { $snap.NextRun.ToString('yyyy-MM-dd HH:mm:ss') } else { 'on event' }
        Write-Host ('      last run : ' + $lastTxt + '   result: ' + (Format-TaskResult $snap.Result))
        Write-Host ('      next run : ' + $nextTxt)
    }

    Write-Host ' '
    if ($found -eq 2) {
        Write-Host 'verdict: OK - network / wake / periodic auto-repair is armed' -ForegroundColor Green
    }
    elseif ($found -eq 1) {
        Write-Host 'verdict: DEGRADED - 1 of 2 tasks registered' -ForegroundColor Yellow
    }
    elseif (-not $script:IsElevated) {
        Write-Host 'verdict: INCONCLUSIVE - re-run in an elevated shell (Win+X, Terminal (Admin))' -ForegroundColor Yellow
    }
    else {
        Write-Host 'verdict: OFF - no auto-repair task registered (drift stays until you repair manually)' -ForegroundColor Red
    }
    Write-Host 'cost   : 0 MB idle RAM, 0 % idle CPU ; fires only on boot / network change / wake + a 60-min timer' -ForegroundColor DarkGray
    Write-Host '         (no wall-clock guess here on purpose - measure it with -Install -SelfTest)' -ForegroundColor DarkGray
    Write-Host ' '
    return $found
}

function Invoke-ModeChild([string[]]$ExtraArgs) {
    $mode = Get-ModeScriptPath
    if (-not $mode) { return 127 }
    $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $mode, '-Root', $Root) + $ExtraArgs
    & powershell.exe @argv | Out-Host
    return $LASTEXITCODE
}

function Invoke-TaskSelfTest([string]$TaskName) {
    $before = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
    $beforeRun = [datetime]::MinValue
    if ($before -and $before.LastRunTime.Year -gt 1999) { $beforeRun = $before.LastRunTime }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop }
    catch {
        $sw.Stop()
        Write-Host ('[!] could not start ' + $TaskName + ': ' + $_.Exception.Message) -ForegroundColor Red
        return $null
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $done = $false
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 300
        $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if (-not $info -or -not $task) { break }
        $st = [string]$task.State
        if ($info.LastRunTime -gt $beforeRun -and $st -ne 'Running' -and $st -ne 'Queued') { $done = $true; break }
    }
    $sw.Stop()

    $final = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
    $code = if ($final) { $final.LastTaskResult } else { $null }
    return [pscustomobject]@{
        Completed = $done
        Seconds   = [math]::Round($sw.Elapsed.TotalSeconds, 2)
        Result    = $code
    }
}

# ------------------------------------------------------------------ dispatch
if ($Remove) {
    if (-not (Test-Elevated)) {
        Write-Host 'ERROR: -Remove needs an elevated shell (tasks are owned by SYSTEM).' -ForegroundColor Red
        exit 1
    }
    Write-Host '=== AI-Net-Guard auto-repair tasks: remove ===' -ForegroundColor Cyan
    $rc = Invoke-ModeChild @('-RemoveTasks')
    if ($rc -ne 0) {
        Write-Host ('[!] 07-mode.ps1 -RemoveTasks returned ' + $rc) -ForegroundColor Red
        exit 3
    }
    $left = @(Get-ScheduledTask -TaskName 'AI-Guard-Mode-*' -ErrorAction SilentlyContinue)
    if ($left.Count -gt 0) {
        Write-Host ('[!] still registered: ' + (($left | ForEach-Object { $_.TaskName }) -join ', ')) -ForegroundColor Red
        exit 3
    }
    Write-Host '[+] all AI-Guard-Mode-* tasks removed' -ForegroundColor Green
    exit 0
}

if (-not $Install) {
    $foundCount = Show-Tasks
    if ($script:IsElevated -and $foundCount -lt 2) { exit 2 }
    exit 0
}

# ------------------------------------------------------------------ install
Write-Host ' '
Write-Host '=== AI-Net-Guard auto-repair tasks: install ===' -ForegroundColor Cyan
if (-not (Test-Elevated)) {
    Write-Host 'ERROR: -Install needs an elevated shell. Open PowerShell as administrator, then:' -ForegroundColor Red
    Write-Host ('  powershell -NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Install -SelfTest')
    exit 1
}
if (-not (Get-ModeScriptPath)) {
    Write-Host ('ERROR: 07-mode.ps1 not found under ' + $Root) -ForegroundColor Red
    exit 3
}

$iv = [math]::Min(1440, [math]::Max(5, $IntervalMinutes))
if ($iv -ne $IntervalMinutes) {
    Write-Host ('[i] interval clamped to ' + $iv + ' minutes (allowed 5..1440)') -ForegroundColor Yellow
}

Write-Host ('[*] registering: ' + $EventTask + ' (boot + network change + wake)') -ForegroundColor DarkGray
Write-Host ('[*] registering: ' + $FallbackTask + ' (every ' + $iv + ' min)') -ForegroundColor DarkGray
$rc = Invoke-ModeChild @('-InstallTasks', '-FallbackMinutes', [string]$iv)
if ($rc -ne 0) {
    Write-Host ('[!] 07-mode.ps1 -InstallTasks returned ' + $rc) -ForegroundColor Red
    exit 3
}

$event = Get-TaskSnapshot $EventTask
$fallback = Get-TaskSnapshot $FallbackTask
if (-not $event -or -not $fallback) {
    Write-Host '[!] registration reported success but a task is missing' -ForegroundColor Red
    exit 3
}
Write-Host ' '
Write-Host ('[+] ' + $EventTask + '     -> ' + $event.State + '  triggers: ' + $event.Triggers) -ForegroundColor Green
Write-Host ('[+] ' + $FallbackTask + '  -> ' + $fallback.State + '  triggers: ' + $fallback.Triggers) -ForegroundColor Green

if ($SelfTest) {
    Write-Host ' '
    Write-Host '[*] self-test: firing the event task once (this also repairs any live drift)' -ForegroundColor DarkGray
    $r1 = Invoke-TaskSelfTest $EventTask
    if (-not $r1) { exit 4 }
    $ok = ($r1.Completed -and [int64]$r1.Result -eq 0)
    Write-Host ('    run 1 : ' + $r1.Seconds + ' s   result: ' + (Format-TaskResult $r1.Result)) `
        -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })

    Write-Host '[*] self-test: second run measures the steady-state (nothing to repair) cost' -ForegroundColor DarkGray
    $r2 = Invoke-TaskSelfTest $EventTask
    if (-not $r2) { exit 4 }
    $ok2 = ($r2.Completed -and [int64]$r2.Result -eq 0)
    Write-Host ('    run 2 : ' + $r2.Seconds + ' s   result: ' + (Format-TaskResult $r2.Result)) `
        -ForegroundColor $(if ($ok2) { 'Green' } else { 'Red' })

    # The periodic path is a different invocation (-Mode Auto -Quiet, no Wintun settle) and
    # on a fresh install it has never run, so "never" is the only value it can report. Firing
    # it here proves the 60-minute safety net works instead of assuming it does.
    Write-Host '[*] self-test: firing the periodic fallback once (the 60-minute safety net)' -ForegroundColor DarkGray
    $r3 = Invoke-TaskSelfTest $FallbackTask
    if (-not $r3) { exit 4 }
    $ok3 = ($r3.Completed -and [int64]$r3.Result -eq 0)
    Write-Host ('    fallback: ' + $r3.Seconds + ' s   result: ' + (Format-TaskResult $r3.Result)) `
        -ForegroundColor $(if ($ok3) { 'Green' } else { 'Red' })

    if (-not ($ok -and $ok2 -and $ok3)) {
        Write-Host ' '
        Write-Host '[!] self-test failed - inspect: Get-ScheduledTaskInfo -TaskName AI-Guard-Mode-Event' -ForegroundColor Red
        Write-Host '    or: Get-ScheduledTaskInfo -TaskName AI-Guard-Mode-Fallback' -ForegroundColor Red
        exit 4
    }
}

Write-Host ' '
[void](Show-Tasks)
exit 0
