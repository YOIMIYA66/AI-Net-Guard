<#
.SYNOPSIS
    AI-Net-Guard v5.4 - lock the install directory ACL (O1) and run the first
    elevated v5.4 verification (O2).

.DESCRIPTION
    AI-Guard-Mode-Event / AI-Guard-Mode-Fallback run 07-mode.ps1 as SYSTEM, and
    07-mode.ps1 reads cn-ipv4.txt / backup\*.meta to build the allowlist. A folder
    created at the C:\ root inherits "Authenticated Users:(M)", so any unelevated
    process could rewrite these files and (a) gain SYSTEM, (b) silently disable or
    widen the guard. This script:

      1. saves the current ACL to backup\acl-before-<ts>.txt (icacls /save),
      2. sets owner = BUILTIN\Administrators on the folder and every child
         (a non-admin owner keeps implicit WRITE_DAC and could re-grant itself),
      3. replaces the folder DACL with Administrators=F, SYSTEM=F, Users=RX
         (inheritance from C:\ removed) and resets every child to inherit it,
      4. verifies that no non-admin SID holds any write / delete / ACL / owner right,
      5. runs .\07-mode.ps1 (applies the v5.4 hot-migration elevated) and
         .\12-regression.ps1 in child processes of the same PowerShell edition,
         then checks the migration postconditions.

    Undo:  .\13-harden-acl.ps1 -Undo   (re-inherits the default C:\ ACL)

    Side effect (intended): unelevated processes - including AI coding assistants -
    can no longer modify C:\AI-Net-Guard. Future updates must be copied from an
    elevated terminal.
#>

[CmdletBinding()]
param(
    [string]$Root = $(if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\AI-Net-Guard' }),
    [switch]$SyncWorkspace,
    [string]$WorkspaceRoot = $(if ($env:AI_GUARD_WORKSPACE) { $env:AI_GUARD_WORKSPACE } else { '' }),
    [switch]$Undo,
    [switch]$SkipVerification,
    [switch]$SkipRegression
)

$ErrorActionPreference = 'Stop'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'ERROR: run this script in an elevated PowerShell (Run as Administrator).' -ForegroundColor Red
    Write-Host ('       cd "' + $Root + '" ; .\13-harden-acl.ps1') -ForegroundColor Yellow
    exit 1
}

# ---------------------------------------------------------------- safety rails
$Root = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\')
if ($Root.Length -le 3 -or $Root -match '(?i)^[A-Z]:\\(Windows|Program Files|Program Files \(x86\)|Users|ProgramData)(\\|$)') {
    Write-Host ('ERROR: refusing to change ACLs on ' + $Root) -ForegroundColor Red
    exit 1
}
if (-not (Test-Path -LiteralPath (Join-Path $Root '07-mode.ps1'))) {
    Write-Host ('ERROR: ' + $Root + ' does not look like an AI-Net-Guard install (07-mode.ps1 missing)') -ForegroundColor Red
    exit 1
}

function Get-InstallAclIssues([string]$Path) {
    # Trusted writers: Administrators, SYSTEM, CREATOR OWNER (inherit-only), TrustedInstaller
    $trusted = @('S-1-5-32-544', 'S-1-5-18', 'S-1-3-0', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    # WriteData|AppendData|WriteEA|DeleteChild|WriteAttributes|Delete|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL
    $writeMask = [int64]0x500D0156
    $issues = New-Object System.Collections.Generic.List[string]
    $targets = @(Get-Item -LiteralPath $Path -Force)
    $targets += @(Get-ChildItem -LiteralPath $Path -Force -File -ErrorAction SilentlyContinue)
    foreach ($sub in @('backup', 'logs')) {
        $sp = Join-Path $Path $sub
        if (Test-Path -LiteralPath $sp) { $targets += @(Get-Item -LiteralPath $sp -Force) }
    }
    foreach ($t in $targets) {
        try {
            # .NET ACL API (Get-Acl needs Microsoft.PowerShell.Security, which may not autoload)
            $sections = [System.Security.AccessControl.AccessControlSections]'Owner, Access'
            $acl = if ($t.PSIsContainer) { New-Object System.Security.AccessControl.DirectorySecurity($t.FullName, $sections) }
                   else { New-Object System.Security.AccessControl.FileSecurity($t.FullName, $sections) }
            $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            if ($trusted -notcontains $owner) { $issues.Add($t.Name + ': owner=' + $owner) }
            foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                $sid = $ace.IdentityReference.Value
                if ($trusted -contains $sid) { continue }
                if (([int64]$ace.FileSystemRights -band $writeMask) -ne 0) {
                    $issues.Add($t.Name + ': ' + $sid + ' has ' + $ace.FileSystemRights)
                }
            }
        }
        catch { $issues.Add($t.Name + ': ACL unreadable (' + $_.Exception.Message + ')') }
    }
    # plain return (no leading comma) so callers can safely wrap with @()
    return $issues.ToArray()
}

function Invoke-Icacls([string[]]$IcaclsArgs) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & icacls.exe @IcaclsArgs 2>&1
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prev
    }
    if ($code -ne 0) {
        Write-Host ('    WARNING: icacls ' + ($IcaclsArgs -join ' ') + ' -> exit ' + $code) -ForegroundColor Yellow
        $out | Select-Object -Last 3 | ForEach-Object { Write-Host ('      ' + $_) -ForegroundColor DarkGray }
    }
}

# ---------------------------------------------------------------- optional workspace sync
if ($SyncWorkspace) {
    if (-not $WorkspaceRoot) {
        $cwd = (Get-Location).Path.TrimEnd('\')
        if ($cwd -ne $Root -and (Test-Path -LiteralPath (Join-Path $cwd '07-mode.ps1'))) {
            $WorkspaceRoot = $cwd
        }
        else {
            Write-Host 'ERROR: pass -WorkspaceRoot <path> or set $env:AI_GUARD_WORKSPACE (or run from your git clone directory).' -ForegroundColor Red
            exit 1
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $WorkspaceRoot '07-mode.ps1'))) {
        Write-Host ('ERROR: WorkspaceRoot missing 07-mode.ps1: ' + $WorkspaceRoot) -ForegroundColor Red
        exit 1
    }
    $synced = 0
    foreach ($pat in @('*.ps1', 'CURRENT-IMPLEMENTATION.md', 'README.md')) {
        foreach ($sf in @(Get-ChildItem -Path (Join-Path $WorkspaceRoot $pat) -File -ErrorAction SilentlyContinue)) {
            Copy-Item -LiteralPath $sf.FullName -Destination (Join-Path $Root $sf.Name) -Force
            $synced++
        }
    }
    Write-Host ('[+] synced ' + $synced + ' files from workspace -> ' + $Root) -ForegroundColor Green
}

# ---------------------------------------------------------------- undo
if ($Undo) {
    Write-Host ('[+] restoring inherited default ACL on ' + $Root) -ForegroundColor Cyan
    Invoke-Icacls @($Root, '/reset', '/T', '/C', '/Q')
    Write-Host '[+] done (owner stays BUILTIN\Administrators; DACL re-inherits from the parent)' -ForegroundColor Green
    exit 0
}

# ---------------------------------------------------------------- 1. ACL lock
Write-Host ''
Write-Host '=== AI-Net-Guard v5.4: install directory ACL hardening (O1) ===' -ForegroundColor Cyan
$before = @(Get-InstallAclIssues -Path $Root)
Write-Host ('    issues before: ' + $before.Count)
$before | Select-Object -First 6 | ForEach-Object { Write-Host ('      ' + $_) -ForegroundColor DarkGray }

$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupDir = Join-Path $Root 'backup'
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
$aclBackup = Join-Path $backupDir ('acl-before-' + $ts + '.txt')
Invoke-Icacls @($Root, '/save', $aclBackup, '/T', '/C', '/Q')
if (Test-Path -LiteralPath $aclBackup) { Write-Host ('    saved previous ACL: ' + $aclBackup) -ForegroundColor DarkGray }

Invoke-Icacls @($Root, '/setowner', '*S-1-5-32-544', '/T', '/C', '/Q')
Invoke-Icacls @($Root, '/inheritance:r', '/grant:r', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-545:(OI)(CI)RX')
Invoke-Icacls @($Root, '/remove:g', '*S-1-5-11', '*S-1-1-0', '*S-1-5-4', ('*' + $id.User.Value))
Invoke-Icacls @((Join-Path $Root '*'), '/reset', '/T', '/C', '/Q')

$after = @(Get-InstallAclIssues -Path $Root)
if ($after.Count -eq 0) {
    Write-Host '[+] ACL locked: owner=Administrators, Administrators/SYSTEM=Full, Users=Read+Execute' -ForegroundColor Green
}
else {
    Write-Host ('[!] ACL still has ' + $after.Count + ' issue(s):') -ForegroundColor Red
    $after | ForEach-Object { Write-Host ('      ' + $_) -ForegroundColor Red }
    exit 2
}

if ($SkipVerification) { exit 0 }

# ---------------------------------------------------------------- 2. first elevated v5.4 run (O2)
$psExe = (Get-Process -Id $PID).Path
Write-Host ''
Write-Host ('=== O2: elevated v5.4 run via ' + (Split-Path -Leaf $psExe) + ' ===') -ForegroundColor Cyan
& $psExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root '07-mode.ps1')
$modeCode = $LASTEXITCODE

$flagOk = Test-Path -LiteralPath (Join-Path $Root 'backup\v54-migrated.flag')
$smhnr = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue).DisableSmartNameResolution
$taskXml = ''
try { $taskXml = [string](Export-ScheduledTask -TaskName 'AI-Guard-Mode-Event' -ErrorAction Stop) } catch { }
if (-not $taskXml) {
    $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $taskXml = (& schtasks.exe /Query /TN 'AI-Guard-Mode-Event' /XML 2>$null) -join "`n" } catch { }
    finally { $ErrorActionPreference = $prevEap }
}
$sleepTrig = ($taskXml -match 'Kernel-Power') -and ($taskXml -match 'Power-Troubleshooter')

$regCode = $null
if (-not $SkipRegression) {
    Write-Host ''
    & $psExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root '12-regression.ps1')
    $regCode = $LASTEXITCODE
}

# ---------------------------------------------------------------- summary
Write-Host ''
Write-Host '=== 13-harden-acl summary ===' -ForegroundColor Cyan
function Show-Line([string]$Label, [bool]$Ok, [string]$Detail) {
    Write-Host ('  [{0}] {1} : {2}' -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Label, $Detail) -ForegroundColor $(if ($Ok) { 'Green' } else { 'Red' })
}
Show-Line 'O1 install ACL locked' ($after.Count -eq 0) ('issues ' + $before.Count + ' -> ' + $after.Count)
Show-Line 'O2 07-mode.ps1 elevated run' ($modeCode -eq 0) ('exit=' + $modeCode)
Show-Line 'O2 v54-migrated.flag written' $flagOk ([string]$flagOk)
Show-Line 'O2 SMHNR disabled' ($smhnr -eq 1) ('DisableSmartNameResolution=' + $smhnr)
Show-Line 'O2 sleep-resume trigger registered' $sleepTrig ('AI-Guard-Mode-Event XML has Kernel-Power/Power-Troubleshooter=' + $sleepTrig)
if ($null -ne $regCode) { Show-Line 'O2 12-regression.ps1' ($regCode -eq 0) ('exit=' + $regCode) }

$allOk = ($after.Count -eq 0) -and ($modeCode -eq 0) -and $flagOk -and ($smhnr -eq 1) -and $sleepTrig -and (($null -eq $regCode) -or ($regCode -eq 0))
exit $(if ($allOk) { 0 } else { 3 })
