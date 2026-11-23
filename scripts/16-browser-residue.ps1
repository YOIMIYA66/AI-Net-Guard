<#
.SYNOPSIS
    AI-Net-Guard v5.8.4 - step 16: purge leftover browser residue (DCBrowser / Firefox).

.DESCRIPTION
    02-killswitch.ps1 / 07-mode.ps1 / 15-webrtc-browser-shield.ps1 only harden the
    browsers that are actually installed. A browser that was uninstalled but left
    its registration behind is a quieter problem: a dead StartMenuInternet entry
    can still be offered as a URL handler, and an orphaned Mozilla profile keeps a
    stale Gecko NSS store (%APPDATA%\Mozilla) on disk for nothing.

    This script removes residue for browsers that are NOT installed:

        Clients\StartMenuInternet\DCBrowser     HKLM 64 + HKLM WOW6432 + HKCU
        RegisteredApplications value DCBrowser  HKLM 64 + HKLM WOW6432
        Mozilla\Firefox                        HKCU + HKLM 64 + HKLM WOW6432
        Mozilla\SeaMonkey                      HKCU
        Mozilla\MaintenanceService             HKLM 64 (no service behind it)
        %APPDATA%\Mozilla                      moved into the backup folder

    Deliberately NOT touched, because they belong to other products rather than
    to Firefox itself:

        MozillaPlugins                  WPS PDF / Thunder / Adobe Acrobat plugins
        Mozilla\NativeMessagingHosts    IDM / Adobe / McAfee / Defender integrations

    Modes:
        (default)   same as -Verify: read-only report, changes nothing
        -DryRun     print the exact removal plan, still changes nothing
        -Apply      write a JSON backup, then remove      (needs elevation)
        -Restore    re-import a JSON backup               (needs elevation)

    The backup is a JSON tree of keys + values + value kinds rather than a .reg
    export, because reg.exe is on this machine's program blacklist.

.EXAMPLE
    .\16-browser-residue.ps1

.EXAMPLE
    .\16-browser-residue.ps1 -DryRun

.EXAMPLE
    .\16-browser-residue.ps1 -Apply

.EXAMPLE
    .\16-browser-residue.ps1 -Restore -BackupFile .\backup\browser-residue-20261122-213000.json

.NOTES
    -Apply and -Restore require an elevated PowerShell.
    Exit codes: 0 = clean, 1 = not elevated, 2 = residue still present, 3 = backup error.
#>

[CmdletBinding()]
param(
    [string]$Root = $(if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\AI-Net-Guard' }),
    [switch]$Apply,
    [switch]$DryRun,
    [switch]$Verify,
    [switch]$Restore,
    [string]$BackupFile = ''
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- setup
$script:Root = $Root
if ((Split-Path -Leaf $script:Root) -ieq 'scripts') { $script:Root = Split-Path -Parent $script:Root }
$script:BackupDir = Join-Path $script:Root 'backup'

$script:KeyTargets = @(
    'HKLM:\SOFTWARE\Clients\StartMenuInternet\DCBrowser',
    'HKLM:\SOFTWARE\WOW6432Node\Clients\StartMenuInternet\DCBrowser',
    'HKCU:\SOFTWARE\Clients\StartMenuInternet\DCBrowser',
    'HKLM:\SOFTWARE\Mozilla\Firefox',
    'HKLM:\SOFTWARE\Mozilla\MaintenanceService',
    'HKLM:\SOFTWARE\WOW6432Node\Mozilla\Firefox',
    'HKCU:\SOFTWARE\Mozilla\Firefox',
    'HKCU:\SOFTWARE\Mozilla\SeaMonkey'
)

$script:ValueTargets = @(
    [pscustomobject]@{ Sub = 'SOFTWARE\RegisteredApplications'; Name = 'DCBrowser' },
    [pscustomobject]@{ Sub = 'SOFTWARE\WOW6432Node\RegisteredApplications'; Name = 'DCBrowser' }
)

$script:ProfileDir = Join-Path $env:APPDATA 'Mozilla'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DriveSub([string]$PsPath) {
    # 'HKLM:\SOFTWARE\X' -> @{ Hive = 'LocalMachine'; Sub = 'SOFTWARE\X' }
    if ($PsPath -match '^(?i)HKLM:\\') { return [pscustomobject]@{ Hive = 'LocalMachine'; Sub = $PsPath.Substring(6) } }
    if ($PsPath -match '^(?i)HKCU:\\') { return [pscustomobject]@{ Hive = 'CurrentUser'; Sub = $PsPath.Substring(6) } }
    throw ('unsupported registry path: ' + $PsPath)
}

function Get-ValueTargetState([string]$Sub, [string]$Name) {
    $key = $null
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Sub, $false)
        if ($null -eq $key) { return $null }
        if ($key.GetValueNames() -contains $Name) { return [string]$key.GetValue($Name) }
        return $null
    }
    catch { return $null }
    finally { if ($null -ne $key) { $key.Close() } }
}

function Add-RegNode {
    param([string]$PsPath, [System.Collections.Generic.List[object]]$Acc)
    $key = Get-Item -LiteralPath $PsPath -ErrorAction Stop
    $vals = New-Object System.Collections.Generic.List[object]
    foreach ($n in $key.GetValueNames()) {
        $kind = $key.GetValueKind($n)
        $raw = $key.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $payload = $raw
        if ([string]$kind -eq 'Binary' -and $null -ne $raw) { $payload = [Convert]::ToBase64String([byte[]]$raw) }
        if ([string]$kind -eq 'MultiString') { $payload = @($raw) }
        $vals.Add([pscustomobject]@{ name = $n; kind = [string]$kind; value = $payload })
    }
    $Acc.Add([pscustomobject]@{ path = $PsPath; values = $vals.ToArray() })
    foreach ($child in @(Get-ChildItem -LiteralPath $PsPath -ErrorAction SilentlyContinue)) {
        Add-RegNode -PsPath $child.PSPath -Acc $Acc
    }
}

function Get-Residue {
    $report = New-Object System.Collections.Generic.List[object]
    foreach ($k in $script:KeyTargets) {
        $report.Add([pscustomobject]@{ Kind = 'key'; Name = $k; Present = (Test-Path -LiteralPath $k); Detail = '' })
    }
    foreach ($v in $script:ValueTargets) {
        $found = Get-ValueTargetState -Sub $v.Sub -Name $v.Name
        $report.Add([pscustomobject]@{ Kind = 'value'; Name = ('HKLM\' + $v.Sub + ' :: ' + $v.Name); Present = ($null -ne $found); Detail = ([string]$found) })
    }
    $report.Add([pscustomobject]@{ Kind = 'dir'; Name = $script:ProfileDir; Present = (Test-Path -LiteralPath $script:ProfileDir); Detail = '' })
    return $report.ToArray()
}

function Format-ResidueName([string]$Name) {
    # keep the report column narrow: %APPDATA%\Mozilla instead of the full drive path
    $ap = $env:APPDATA
    if ($ap -and $Name -and $Name.StartsWith($ap, [StringComparison]::OrdinalIgnoreCase)) {
        return ('%APPDATA%' + $Name.Substring($ap.Length))
    }
    return $Name
}

function Show-Residue([object[]]$Report) {
    $open = 0
    foreach ($r in $Report) {
        if ($r.Present) {
            $open++
            Write-Host ('  [FOUND ] ' + (Format-ResidueName $r.Name)) -ForegroundColor Yellow
        }
        else {
            Write-Host ('  [clean ] ' + (Format-ResidueName $r.Name)) -ForegroundColor DarkGray
        }
    }
    Write-Host ''
    if ($open -eq 0) { Write-Host '[+] no browser residue left' -ForegroundColor Green }
    else { Write-Host ('[!] ' + $open + ' residue item(s) present') -ForegroundColor Yellow }
    return $open
}

# ---------------------------------------------------------------- mode: restore
if ($Restore) {
    if (-not (Test-Admin)) {
        Write-Host 'ERROR: -Restore needs an elevated PowerShell (Run as Administrator).' -ForegroundColor Red
        exit 1
    }
    if (-not $BackupFile) {
        $cand = @(Get-ChildItem -LiteralPath $script:BackupDir -Filter 'browser-residue-*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        if ($cand.Count -eq 0) {
            Write-Host ('ERROR: no browser-residue-*.json in ' + $script:BackupDir) -ForegroundColor Red
            exit 3
        }
        $BackupFile = $cand[0].FullName
    }
    if (-not (Test-Path -LiteralPath $BackupFile)) {
        Write-Host ('ERROR: backup not found: ' + $BackupFile) -ForegroundColor Red
        exit 3
    }
    Write-Host ('=== restoring from ' + $BackupFile + ' ===') -ForegroundColor Cyan
    $doc = Get-Content -LiteralPath $BackupFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $made = 0
    $written = 0
    foreach ($node in $doc.nodes) {
        if (-not (Test-Path -LiteralPath $node.path)) {
            New-Item -Path $node.path -Force | Out-Null
            $made++
        }
        $key = Get-Item -LiteralPath $node.path
        foreach ($v in @($node.values)) {
            $payload = $v.value
            if ([string]$v.kind -eq 'Binary' -and $null -ne $payload) { $payload = [Convert]::FromBase64String([string]$payload) }
            if ([string]$v.kind -eq 'MultiString') { $payload = [string[]]@($payload) }
            if (([string]$v.kind -eq 'DWord') -or ([string]$v.kind -eq 'QWord')) { if ($null -ne $payload) { $payload = [int64]$payload } }
            $key.SetValue([string]$v.name, $payload, [Microsoft.Win32.RegistryValueKind]::$($v.kind))
            $written++
        }
        $key.Close()
    }
    if ($doc.profileDir -and $doc.profileDir.movedTo -and (Test-Path -LiteralPath $doc.profileDir.movedTo) -and -not (Test-Path -LiteralPath $doc.profileDir.source)) {
        Move-Item -LiteralPath $doc.profileDir.movedTo -Destination $doc.profileDir.source -Force
        Write-Host ('  restored profile dir -> ' + $doc.profileDir.source) -ForegroundColor Green
    }
    Write-Host ('[+] restored ' + $made + ' key(s) created, ' + $written + ' value(s) written') -ForegroundColor Green
    exit 0
}

# ---------------------------------------------------------------- mode: verify / dry-run
if (-not $Apply) {
    Write-Host ''
    Write-Host '=== 16-browser-residue: current state ===' -ForegroundColor Cyan
    $open = Show-Residue -Report (Get-Residue)
    if ($DryRun) {
        Write-Host ''
        Write-Host '=== plan (-Apply would do this) ===' -ForegroundColor Cyan
        foreach ($k in $script:KeyTargets) {
            if (Test-Path -LiteralPath $k) { Write-Host ('  remove key   ' + $k) -ForegroundColor Yellow }
        }
        foreach ($v in $script:ValueTargets) {
            $found = Get-ValueTargetState -Sub $v.Sub -Name $v.Name
            if ($null -ne $found) { Write-Host ('  remove value HKLM\' + $v.Sub + ' :: ' + $v.Name) -ForegroundColor Yellow }
        }
        if (Test-Path -LiteralPath $script:ProfileDir) { Write-Host ('  move dir     ' + $script:ProfileDir + ' -> ' + $script:BackupDir) -ForegroundColor Yellow }
        Write-Host ''
        Write-Host ('  backup: JSON under ' + $script:BackupDir) -ForegroundColor DarkGray
        Write-Host '  nothing was changed (-DryRun)' -ForegroundColor DarkGray
    }
    elseif ($open -eq 0) {
        Write-Host ''
        Write-Host '  nothing to do. -DryRun shows the plan, -Apply removes.' -ForegroundColor DarkGray
    }
    else {
        Write-Host ''
        Write-Host '  run with -Apply in an elevated PowerShell to remove, or -DryRun to preview.' -ForegroundColor DarkGray
    }
    exit $(if ($open -eq 0) { 0 } else { 2 })
}

# ---------------------------------------------------------------- mode: apply
if (-not (Test-Admin)) {
    Write-Host 'ERROR: -Apply needs an elevated PowerShell (Run as Administrator).' -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host '=== 16-browser-residue: removing ===' -ForegroundColor Cyan
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
New-Item -ItemType Directory -Path $script:BackupDir -Force | Out-Null
$jsonPath = Join-Path $script:BackupDir ('browser-residue-' + $ts + '.json')

# 1) backup every key that still exists, plus the values we are about to drop
$nodes = New-Object System.Collections.Generic.List[object]
foreach ($k in $script:KeyTargets) {
    if (Test-Path -LiteralPath $k) { Add-RegNode -PsPath $k -Acc $nodes }
}
$valueBackup = New-Object System.Collections.Generic.List[object]
foreach ($v in $script:ValueTargets) {
    $found = Get-ValueTargetState -Sub $v.Sub -Name $v.Name
    if ($null -ne $found) { $valueBackup.Add([pscustomobject]@{ sub = $v.Sub; name = $v.Name; value = [string]$found }) }
}
$profileInfo = $null
if (Test-Path -LiteralPath $script:ProfileDir) {
    $profileInfo = [pscustomobject]@{ source = $script:ProfileDir; movedTo = (Join-Path $script:BackupDir ('Roaming-Mozilla-' + $ts)) }
}
$doc = [pscustomobject]@{
    created    = (Get-Date).ToString('o')
    machine    = $env:COMPUTERNAME
    nodes      = $nodes.ToArray()
    values     = $valueBackup.ToArray()
    profileDir = $profileInfo
}
try {
    [IO.File]::WriteAllText($jsonPath, ($doc | ConvertTo-Json -Depth 12), (New-Object System.Text.UTF8Encoding($false)))
}
catch {
    Write-Host ('ERROR: cannot write backup: ' + $_.Exception.Message) -ForegroundColor Red
    exit 3
}
Write-Host ('  backup: ' + $jsonPath + '  (' + $nodes.Count + ' key node(s))') -ForegroundColor DarkGray

# 2) remove keys
$failed = 0
foreach ($k in $script:KeyTargets) {
    if (-not (Test-Path -LiteralPath $k)) { Write-Host ('  absent  ' + $k) -ForegroundColor DarkGray; continue }
    try {
        Remove-Item -LiteralPath $k -Recurse -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $k) { Write-Host ('  FAILED  ' + $k) -ForegroundColor Red; $failed++ }
        else { Write-Host ('  removed ' + $k) -ForegroundColor Green }
    }
    catch {
        Write-Host ('  FAILED  ' + $k + ' : ' + $_.Exception.Message) -ForegroundColor Red
        $failed++
    }
}

# 3) remove RegisteredApplications values
#    Get-Item hands back a READ-ONLY RegistryKey handle, so .DeleteValue() on it throws
#    UnauthorizedAccessException even when elevated. Open the key writable on purpose.
foreach ($v in $script:ValueTargets) {
    $key = $null
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($v.Sub, $true)
        if ($null -eq $key) { Write-Host ('  absent  HKLM\' + $v.Sub) -ForegroundColor DarkGray; continue }
        if (-not ($key.GetValueNames() -contains $v.Name)) { Write-Host ('  absent  HKLM\' + $v.Sub + ' :: ' + $v.Name) -ForegroundColor DarkGray; continue }
        $old = $key.GetValue($v.Name)
        $key.DeleteValue($v.Name, $false)
        Write-Host ('  removed HKLM\' + $v.Sub + ' :: ' + $v.Name + ' = ' + $old) -ForegroundColor Green
    }
    catch {
        Write-Host ('  FAILED  HKLM\' + $v.Sub + ' : ' + $_.Exception.Message) -ForegroundColor Red
        $failed++
    }
    finally { if ($null -ne $key) { $key.Close() } }
}

# 4) move the orphaned Mozilla profile into the backup folder (never deleted)
if ($profileInfo) {
    try {
        Move-Item -LiteralPath $profileInfo.source -Destination $profileInfo.movedTo -Force -ErrorAction Stop
        Write-Host ('  moved   ' + $profileInfo.source + ' -> ' + $profileInfo.movedTo) -ForegroundColor Green
    }
    catch {
        Write-Host ('  FAILED  move ' + $profileInfo.source + ' : ' + $_.Exception.Message) -ForegroundColor Red
        $failed++
    }
}
else { Write-Host ('  absent  ' + $script:ProfileDir) -ForegroundColor DarkGray }

# 5) verify
Write-Host ''
Write-Host '=== verification ===' -ForegroundColor Cyan
$left = 0
foreach ($r in (Get-Residue)) {
    if ($r.Present) { $left++; Write-Host ('  STILL PRESENT ' + (Format-ResidueName $r.Name)) -ForegroundColor Red }
}
Write-Host ''
if ($left -eq 0 -and $failed -eq 0) {
    Write-Host '[+] browser residue removed. rollback: .\16-browser-residue.ps1 -Restore' -ForegroundColor Green
    exit 0
}
Write-Host ('[!] left=' + $left + ' failed=' + $failed + ' - see lines above' + ' ; rollback: .\16-browser-residue.ps1 -Restore') -ForegroundColor Yellow
exit 2
