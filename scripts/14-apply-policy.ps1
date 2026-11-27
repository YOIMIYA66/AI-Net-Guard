<#
.SYNOPSIS
    AI-Net-Guard v5.9.6 - idempotent policy orchestrator for GUI & CLI (fresh deploy + incremental toggle apply).

.DESCRIPTION
    Reads <Root>\backup\guard-policy.json (or -PolicyPath) and enforces all 16
    configurable AI-Net-Guard feature switches deterministically:

      * On a clean machine (no baseline.json yet): runs preflight checks,
        captures pristine DNS/IPv6/NTP/LLMNR/SMHNR + Firewall baselines via
        01-dns-hardening.ps1 and 02-killswitch.ps1 (with 30-min auto-rollback
        safety net), verifies live connectivity & core invariants, auto-commits,
        and configures tasks + ACL lock according to policy.
      * On an existing deployment (baseline.json already present): performs fast,
        non-destructive incremental reconfiguration of every toggled ON/OFF
        setting without overwriting baseline.json, restoring individual disabled
        features cleanly from the original baseline.

    Also provides -ClearSystemProxy to turn off HKCU/HKU WinINET system proxy
    and notify WinINET immediately so TUN toggle alone controls proxy routing.

.NOTES
    Windows 10/11, PowerShell 5.1 or 7.x. Must run elevated. Pure ASCII script.
#>

[CmdletBinding()]
param(
    [string]$Root = '',
    [string]$PolicyPath = '',
    [string]$V2rayNRoot = '',
    [string]$TunName = 'xray_tun',
    [switch]$SetSystemProxy,
    [switch]$ClearSystemProxy,
    [switch]$SyncNodeOnly,
    [switch]$ForceCommit,
    [ValidateSet('', 'On', 'Off')][string]$TemporaryIpv6 = ''
)

$ErrorActionPreference = 'Stop'
if (-not $Root) {
    $Root = if ($PSScriptRoot) { if ((Split-Path -Leaf $PSScriptRoot) -ieq 'scripts') { Split-Path -Parent $PSScriptRoot } else { $PSScriptRoot } } else { 'C:\AI-Net-Guard' }
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'ERROR: run 14-apply-policy.ps1 in an elevated session (Administrator).' -ForegroundColor Red
    exit 1
}

function Get-PolicyScriptPath([string]$name) {
    $sp = Join-Path (Join-Path $Root 'scripts') $name
    if (Test-Path -LiteralPath $sp) { return $sp }
    return (Join-Path $Root $name)
}

# The STUN/TURN port set is defined once, in lib-stun-guard.ps1. Resolved before any rule is
# touched: an empty port list would create a rule that blocks every port while claiming to
# block twelve.
$libStun = Get-PolicyScriptPath 'lib-stun-guard.ps1'
if (-not (Test-Path -LiteralPath $libStun)) {
    Write-Host ('[!] lib-stun-guard.ps1 not found: ' + $libStun) -ForegroundColor Red
    Write-Host '    refusing to apply the WebRTC block without the shared port list.' -ForegroundColor Red
    exit 1
}
. $libStun

$libCommon = Get-PolicyScriptPath 'lib-guard-common.ps1'
if (-not (Test-Path -LiteralPath $libCommon)) {
    Write-Host ('[!] lib-guard-common.ps1 not found: ' + $libCommon) -ForegroundColor Red
    exit 1
}
. $libCommon

function Write-Step([string]$msg) { Write-Host ('[+] ' + $msg) -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host ('    [OK] ' + $msg) -ForegroundColor Green }
function Write-Note([string]$msg) { Write-Host ('    [i]  ' + $msg) -ForegroundColor DarkGray }
function Write-Warn([string]$msg) { Write-Host ('    [!]  ' + $msg) -ForegroundColor Yellow }

function Invoke-GuardChild {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [string[]]$ChildArgs = @(),
        [string]$Label = '',
        [int[]]$AllowedExitCodes = @(0)
    )
    if (-not (Test-Path -LiteralPath $ScriptPath)) {
        throw ('required script missing: ' + $ScriptPath)
    }
    $desc = if ($Label) { $Label } else { Split-Path -Leaf $ScriptPath }
    & $psExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ScriptPath @ChildArgs
    $rc = $LASTEXITCODE
    if ($AllowedExitCodes -notcontains $rc) {
        throw ($desc + ' failed (exit=' + $rc + ')')
    }
}

# ------------------------------------------------------------------ SetSystemProxy action
if ($SetSystemProxy) {
    Write-Step 'configuring Windows WinINET system proxy to 127.0.0.1:10809 (standard Xray mode)'
    $configured = 0
    try {
        $hkcuKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        if (Test-Path -LiteralPath $hkcuKey) {
            Set-ItemProperty -LiteralPath $hkcuKey -Name 'ProxyEnable' -Value 1 -Type DWord
            Set-ItemProperty -LiteralPath $hkcuKey -Name 'ProxyServer' -Value '127.0.0.1:10809' -Type String
            $configured++
        }
        foreach ($hive in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
            if ($hive.PSChildName -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { continue }
            $ik = 'Registry::HKEY_USERS\' + $hive.PSChildName + '\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
            if (Test-Path -LiteralPath $ik) {
                Set-ItemProperty -LiteralPath $ik -Name 'ProxyEnable' -Value 1 -Type DWord -ErrorAction SilentlyContinue
                Set-ItemProperty -LiteralPath $ik -Name 'ProxyServer' -Value '127.0.0.1:10809' -Type String -ErrorAction SilentlyContinue
                $configured++
            }
        }
        $winInetDef = @'
using System;
using System.Runtime.InteropServices;
public static class AiGuardWinInet {
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
    public static void NotifyProxyChanged() {
        InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
    }
}
'@
        if (-not ('AiGuardWinInet' -as [type])) {
            Add-Type -TypeDefinition $winInetDef -ErrorAction SilentlyContinue | Out-Null
        }
        [AiGuardWinInet]::NotifyProxyChanged()
        if (-not $V2rayNRoot) {
            foreach ($cand in @('D:\v2rayN-windows-64-desktop\v2rayN-windows-64', 'D:\v2rayN-windows-64-desktop', 'C:\v2rayN-windows-64-desktop\v2rayN-windows-64', 'D:\v2rayN-windows-64', 'C:\v2rayN-windows-64', 'D:\v2rayN', 'C:\v2rayN', (Join-Path $env:LOCALAPPDATA 'v2rayN'), 'C:\Program Files\v2rayN')) {
                if ($cand -and (Test-Path -LiteralPath (Join-Path $cand 'guiConfigs\guiNConfig.json'))) { $V2rayNRoot = $cand; break }
            }
        }
        if ($V2rayNRoot -and (Test-Path -LiteralPath (Join-Path $V2rayNRoot 'guiConfigs\guiNConfig.json'))) {
            try {
                $guiCfgFile = Join-Path $V2rayNRoot 'guiConfigs\guiNConfig.json'
                $guiCfg = Get-Content -LiteralPath $guiCfgFile -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($guiCfg.SystemProxyItem) {
                    $guiCfg.SystemProxyItem.SysProxyType = 1
                    $guiCfg | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $guiCfgFile -Encoding UTF8
                    Write-Ok ('updated v2rayN config: SystemProxyItem.SysProxyType = 1 (Auto Config)')
                }
            } catch { }
        }
    }
    catch {
        Write-Warn ('WinINET update notice: ' + $_.Exception.Message)
    }
    Write-Ok ('system proxy set to 127.0.0.1:10809 (updated hives=' + $configured + ')')
    exit 0
}

# ------------------------------------------------------------------ ClearSystemProxy fast action
if ($ClearSystemProxy) {
    Write-Step 'turning off Windows WinINET system proxy (pure TUN single-switch mode)'
    $cleared = 0
    try {
        $hkcuKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        if (Test-Path -LiteralPath $hkcuKey) {
            $cur = Get-ItemProperty -LiteralPath $hkcuKey -ErrorAction SilentlyContinue
            if ($cur -and $cur.ProxyEnable -ne 0) {
                Set-ItemProperty -LiteralPath $hkcuKey -Name 'ProxyEnable' -Value 0 -Type DWord
                $cleared++
            }
        }
        foreach ($hive in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
            if ($hive.PSChildName -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { continue }
            $ik = 'Registry::HKEY_USERS\' + $hive.PSChildName + '\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
            $ie = Get-ItemProperty -LiteralPath $ik -ErrorAction SilentlyContinue
            if ($ie -and $ie.ProxyEnable -ne 0) {
                Set-ItemProperty -LiteralPath $ik -Name 'ProxyEnable' -Value 0 -Type DWord -ErrorAction SilentlyContinue
                $cleared++
            }
        }
        $winInetDef = @'
using System;
using System.Runtime.InteropServices;
public static class AiGuardWinInet {
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
    public static void NotifyProxyChanged() {
        InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0); // INTERNET_OPTION_SETTINGS_CHANGED
        InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0); // INTERNET_OPTION_REFRESH
    }
}
'@
        if (-not ('AiGuardWinInet' -as [type])) {
            Add-Type -TypeDefinition $winInetDef -ErrorAction SilentlyContinue | Out-Null
        }
        [AiGuardWinInet]::NotifyProxyChanged()
        # Also synchronize v2rayN guiNConfig.json if present
        if (-not $V2rayNRoot) {
            foreach ($cand in @('D:\v2rayN-windows-64-desktop\v2rayN-windows-64', 'D:\v2rayN-windows-64-desktop', 'C:\v2rayN-windows-64-desktop\v2rayN-windows-64', 'D:\v2rayN-windows-64', 'C:\v2rayN-windows-64', 'D:\v2rayN', 'C:\v2rayN', (Join-Path $env:LOCALAPPDATA 'v2rayN'), 'C:\Program Files\v2rayN')) {
                if ($cand -and (Test-Path -LiteralPath (Join-Path $cand 'guiConfigs\guiNConfig.json'))) { $V2rayNRoot = $cand; break }
            }
        }
        if ($V2rayNRoot -and (Test-Path -LiteralPath (Join-Path $V2rayNRoot 'guiConfigs\guiNConfig.json'))) {
            try {
                $guiCfgFile = Join-Path $V2rayNRoot 'guiConfigs\guiNConfig.json'
                $guiCfg = Get-Content -LiteralPath $guiCfgFile -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($guiCfg.SystemProxyItem -and $guiCfg.SystemProxyItem.SysProxyType -ne 0) {
                    $guiCfg.SystemProxyItem.SysProxyType = 0
                    $guiCfg | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $guiCfgFile -Encoding UTF8
                    Write-Ok ('updated v2rayN config: SystemProxyItem.SysProxyType = 0 (Clear)')
                }
            } catch { }
        }
    }
    catch {
        Write-Warn ('WinINET refresh notice: ' + $_.Exception.Message)
    }
    Write-Ok ('system proxy disabled (updated hives=' + $cleared + ')')
    Write-Note 'Notice: If v2rayN is running, please also verify that the bottom proxy dropdown in v2rayN is set to [Clear system proxy] (tray icon turns gray).'
    exit 0
}

# ------------------------------------------------------------------ Load policy
$BackupDir = Join-Path $Root 'backup'
$LogDir = Join-Path $Root 'logs'
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

if (-not $PolicyPath) {
    $PolicyPath = Join-Path $BackupDir 'guard-policy.json'
}

$policyDefaults = [ordered]@{
    Version              = '5.5'
    Preset               = 'Recommended'
    DnsServer            = '223.5.5.5'
    V2rayNRoot           = ''
    AllowCnDirect        = $true
    AllowLan             = $true
    AllowNcsi            = $true
    QuarantineRogueAllow = $true
    LockPhysicalDns      = $true
    DisableSmhnr         = $true
    DisableLlmnrNetbios  = $true
    StrictNrptDoh        = $false
    BlockWebRtcLeak      = $true
    DisablePhysicalIpv6  = $true
    PreferIpv4Prefix     = $true
    ZeroResidentMonitor  = $true
    AutoNodeSync         = $true
    AutoHealStaleProxy   = $true
    DomesticNtp          = $true
    HardenInstallAcl     = $true
    UpdatedAt            = (Get-Date).ToString('o')
}

$applyExitCode = 0
$applyErrors = New-Object System.Collections.Generic.List[string]
$pendingRollbackCancel = $false
$lastGoodPolicyPath = Join-Path $BackupDir 'guard-policy.last-good.json'
$canonicalPolicyPath = Join-Path $BackupDir 'guard-policy.json'
$applyWriteLock = Enter-GuardWriteLock -TimeoutMs 30000
$txResult = $null
try {
$txResult = Invoke-GuardPolicyTransaction -CanonicalPolicyPath $canonicalPolicyPath -PendingPolicyPath $PolicyPath -LastGoodPolicyPath $lastGoodPolicyPath -ApplyAction {
param($txState, $txStageCanonical, $txCommitPolicy)

function Write-CanonicalPolicyAtomic {
    $policy.UpdatedAt = (Get-Date).ToString('o')
    $canJson = ([pscustomobject]$policy) | ConvertTo-Json -Depth 4
    & $txStageCanonical $canJson
}

$isDeployedHost = (Test-Path -LiteralPath (Join-Path $BackupDir 'baseline.json'))
$policyLoaded = Read-GuardPolicyStrict -PolicyPath $PolicyPath -Defaults $policyDefaults -LastGoodPath $lastGoodPolicyPath -IsDeployed:$isDeployedHost
if ($policyLoaded.PolicyHealth -eq 'corrupt-fail-closed') {
    Write-Host ('ERROR: refusing to apply corrupted policy file: ' + $policyLoaded.PolicyWarning) -ForegroundColor Red
    $applyExitCode = 2
}
if ($policyLoaded.PolicyWarning -and $applyExitCode -eq 0) {
    Write-Warn $policyLoaded.PolicyWarning
}
$policy = $policyLoaded

if ($applyExitCode -eq 0) {
    if ($TemporaryIpv6 -eq 'On') {
        $policy.DisablePhysicalIpv6 = $false
        $policy.PreferIpv4Prefix = $true
        Write-Note 'TemporaryIpv6 = On -> DisablePhysicalIpv6=false, PreferIpv4Prefix=true (DisabledComponents=0x20)'
    }
    elseif ($TemporaryIpv6 -eq 'Off') {
        $policy.DisablePhysicalIpv6 = $true
        $policy.PreferIpv4Prefix = $true
        Write-Note 'TemporaryIpv6 = Off -> DisablePhysicalIpv6=true, PreferIpv4Prefix=true'
    }
    # Rule coordination: StrictNrptDoh requires physical DNS locked to 1.1.1.1
    if ($policy.StrictNrptDoh) {
        $policy.LockPhysicalDns = $true
    }

    if ($V2rayNRoot) {
        $policy.V2rayNRoot = $V2rayNRoot
    }
    elseif ($policy.V2rayNRoot -and (Test-Path -LiteralPath $policy.V2rayNRoot)) {
        $V2rayNRoot = $policy.V2rayNRoot
    }
    else {
        if ($env:V2RAYN_ROOT -and (Test-Path -LiteralPath $env:V2RAYN_ROOT)) { $V2rayNRoot = $env:V2RAYN_ROOT }
        else {
            foreach ($cand in @('D:\v2rayN-windows-64-desktop\v2rayN-windows-64', 'D:\v2rayN-windows-64-desktop', 'C:\v2rayN-windows-64-desktop\v2rayN-windows-64', 'C:\v2rayN-windows-64', 'D:\v2rayN-windows-64', 'C:\v2rayN', 'D:\v2rayN', (Join-Path $env:LOCALAPPDATA 'v2rayN'), 'C:\Program Files\v2rayN')) {
                if ($cand -and ((Test-Path -LiteralPath (Join-Path $cand 'v2rayN.exe')) -or (Test-Path -LiteralPath (Join-Path $cand 'binConfigs')))) { $V2rayNRoot = $cand; break }
            }
            if (-not $V2rayNRoot) {
                try {
                    $vp = [System.Diagnostics.Process]::GetProcessesByName('v2rayN')
                    if ($vp.Length -gt 0 -and $vp[0].MainModule.FileName) { $V2rayNRoot = Split-Path -Parent $vp[0].MainModule.FileName }
                }
                catch { }
            }
            if (-not $V2rayNRoot) { $V2rayNRoot = 'C:\v2rayN-windows-64' }
        }
    }
}

$psExe = (Get-Process -Id $PID).Path
if (-not $psExe -or -not (Test-Path -LiteralPath $psExe)) {
    $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
}

if ($applyExitCode -eq 0 -and $SyncNodeOnly) {
    Write-Step 'forcing immediate proxy node & port sync'
    & $psExe -NoProfile -ExecutionPolicy Bypass -File (Get-PolicyScriptPath '10-sync-node-rule.ps1') -Root $Root -V2rayNRoot $V2rayNRoot
    $applyExitCode = $LASTEXITCODE
    if ($applyExitCode -eq 0) {
        $applyExitCode = -1
    }
}

$targetDns = if ($policy.StrictNrptDoh) { '1.1.1.1' } elseif ($policy.DnsServer) { [string]$policy.DnsServer } else { '223.5.5.5' }
$knownTuns = @($TunName, 'xray_tun', 'singbox_tun', 'mihomo_tun', 'Meta', 'Mihomo') | Select-Object -Unique

function Get-BaselineDnsObject {
    $bf = Join-Path $BackupDir 'baseline.json'
    $dnsPath = $null
    if (Test-Path -LiteralPath $bf) {
        try { $dnsPath = (Get-Content -LiteralPath $bf -Raw -Encoding UTF8 | ConvertFrom-Json).Dns } catch { }
    }
    if (-not $dnsPath) {
        $oldest = Get-ChildItem -Path $BackupDir -Filter 'dns-*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -First 1
        if ($oldest) { $dnsPath = $oldest.FullName }
    }
    if ($dnsPath -and (Test-Path -LiteralPath $dnsPath)) {
        try { return (Get-Content -LiteralPath $dnsPath -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { }
    }
    return $null
}

function Get-PhysicalAdaptersAll {
    @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -ne 'Not Present' -and
        ($knownTuns -notcontains $_.Name) -and
        $_.InterfaceDescription -notmatch '(?i)Wintun|sing-tun|Mihomo|Loopback'
    })
}

function Get-IPv4MaskBytesPolicy([int]$PrefixLen) {
    if ($PrefixLen -lt 0) { $PrefixLen = 0 }
    if ($PrefixLen -gt 32) { $PrefixLen = 32 }
    $full = [int][Math]::Floor($PrefixLen / 8)
    $rem = $PrefixLen % 8
    $b = New-Object 'byte[]' 4
    for ($i = 0; $i -lt 4; $i++) {
        if ($i -lt $full) { $b[$i] = [byte]255 }
        elseif ($i -eq $full -and $rem -gt 0) { $b[$i] = [byte]((0xFF -shl (8 - $rem)) -band 0xFF) }
        else { $b[$i] = [byte]0 }
    }
    return ,$b
}

function Get-IPv4NetworkTextPolicy([string]$Ip, [byte[]]$Mask) {
    $ipb = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
    $n = New-Object 'byte[]' 4
    for ($i = 0; $i -lt 4; $i++) { $n[$i] = [byte]($ipb[$i] -band $Mask[$i]) }
    return (([string]$n[0]) + '.' + ([string]$n[1]) + '.' + ([string]$n[2]) + '.' + ([string]$n[3]))
}

function Get-PhysicalEgressCidrsPolicy([string[]]$PhysicalAlias, [string[]]$TunAlias) {
    $out = New-Object System.Collections.Generic.List[string]
    $tunIps = @()
    if ($TunAlias) {
        try {
            $tunIps = @(Get-NetIPAddress -InterfaceAlias $TunAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -and $_.IPAddress -notlike '127.*' } |
                Select-Object -ExpandProperty IPAddress -Unique)
        }
        catch { }
    }
    $addrs = @()
    try {
        $addrs = @(Get-NetIPAddress -InterfaceAlias $PhysicalAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -and $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' })
    }
    catch { }
    foreach ($a in $addrs) {
        $ip = [string]$a.IPAddress
        $plen = 32
        try { $plen = [int]$a.PrefixLength } catch { $plen = 32 }
        if ($plen -le 0 -or $plen -gt 32) { $plen = 32 }
        $mask = Get-IPv4MaskBytesPolicy $plen
        $net = Get-IPv4NetworkTextPolicy $ip $mask
        $overlapsTun = $false
        if ($plen -lt 32) {
            foreach ($ti in $tunIps) {
                if ((Get-IPv4NetworkTextPolicy $ti $mask) -eq $net) { $overlapsTun = $true; break }
            }
        }
        $cidr = if ($plen -ge 32 -or $overlapsTun) { ($ip + '/32') } else { ($net + '/' + [string]$plen) }
        if (-not $out.Contains($cidr)) { $out.Add($cidr) }
    }
    return $out.ToArray()
}

function Invoke-QuickConnectivityCheck([bool]$AllowCn) {
    $badProf = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled -or $_.DefaultOutboundAction -ne 'Block' })
    if ($badProf.Count -gt 0) {
        throw ('firewall profiles not set to Block: ' + (($badProf | ForEach-Object { $_.Name }) -join ','))
    }
    foreach ($rn in @('AI-Guard-Allow-TUN', 'AI-Guard-Allow-Node-TCP')) {
        $r = Get-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $r -or $r.Enabled -ne 'True') { throw ('core rule missing or disabled: ' + $rn) }
    }

    $activeTun = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Up' -and (($knownTuns -contains $_.Name) -or $_.InterfaceDescription -match '(?i)Wintun|sing-tun|Mihomo') } |
        Select-Object -First 1

    if ([int][Net.ServicePointManager]::SecurityProtocol -ne 0) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }

    if ($activeTun) {
        $probeUrl = if ($AllowCn) { 'https://www.baidu.com' } else { 'https://api.ipify.org' }
        $req = [System.Net.HttpWebRequest]::Create($probeUrl)
        $req.Proxy = $null
        $req.Timeout = 10000
        $req.ReadWriteTimeout = 10000
        $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        $resp = $req.GetResponse()
        $resp.Close()
        return ('TUN=' + $activeTun.Name + ', probe ' + $probeUrl + ' OK')
    }
    elseif ($AllowCn) {
        $req = [System.Net.HttpWebRequest]::Create('https://www.baidu.com')
        $req.Proxy = $null
        $req.Timeout = 10000
        $req.ReadWriteTimeout = 10000
        $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        $resp = $req.GetResponse()
        $resp.Close()
        return 'TUN=off, domestic direct probe https://www.baidu.com OK'
    }
    else {
        return 'TUN=off, strict global lock invariants OK'
    }
}

# ------------------------------------------------------------------ Determine Fresh Install vs Incremental Reconfigure
if ($applyExitCode -eq 0) {
$baselineFile = Join-Path $BackupDir 'baseline.json'
$baselineObj = $null
if (Test-Path -LiteralPath $baselineFile) {
    try { $baselineObj = Get-Content -LiteralPath $baselineFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
}
$hasDnsBaseline = [bool]($baselineObj -and $baselineObj.Dns -and (Test-Path -LiteralPath $baselineObj.Dns))
$hasFwBaseline  = [bool]($baselineObj -and $baselineObj.Firewall -and (Test-Path -LiteralPath $baselineObj.Firewall))
$isFreshInstall = (-not $hasDnsBaseline) -or (-not $hasFwBaseline)

Write-Host ''
Write-Host ('=== AI-Net-Guard v5.9.6 Policy Engine (' + $(if ($isFreshInstall) { 'Initial Deployment' } else { 'Incremental Update' }) + ') ===') -ForegroundColor Cyan
Write-Note ('Root=' + $Root + '  V2rayNRoot=' + $V2rayNRoot + '  Preset=' + $policy.Preset)

if (-not $isFreshInstall) {
    Write-CanonicalPolicyAtomic
}

if ($isFreshInstall) {
    # -------------------------------------------------------------- Preflight for Fresh Install
    Write-Step 'running preflight checks before initial deployment'
    $physUp = @(Get-PhysicalAdaptersAll | Where-Object { $_.Status -eq 'Up' })
    if ($physUp.Count -eq 0) {
        Write-Host 'ERROR: No active physical network adapter (Wi-Fi / Ethernet) is connected.' -ForegroundColor Red
        $applyExitCode = 2
    }
    $cfgCheck = Join-Path $V2rayNRoot 'binConfigs\config.json'
    if ($applyExitCode -eq 0 -and -not (Test-Path -LiteralPath $cfgCheck)) {
        Write-Host ('ERROR: v2rayN config not found at "' + $cfgCheck + '". Select your v2rayN directory and start v2rayN once first.') -ForegroundColor Red
        $applyExitCode = 2
    }
    $tunAdapter = if ($applyExitCode -eq 0) {
        Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { ($knownTuns -contains $_.Name) -or $_.InterfaceDescription -match '(?i)Wintun|sing-tun|Mihomo' } |
            Select-Object -First 1
    } else { $null }
    if ($applyExitCode -eq 0 -and -not $tunAdapter) {
        Write-Host 'ERROR: Virtual TUN adapter (xray_tun / singbox_tun) has not been created yet.' -ForegroundColor Red
        Write-Host '       Please enable "Enable Tun" inside v2rayN once first so Windows creates the TUN interface.' -ForegroundColor Yellow
        $applyExitCode = 2
    }
    if ($applyExitCode -eq 0) {
        $TunName = $tunAdapter.Name
        if ($policy.StrictNrptDoh -and $tunAdapter.Status -ne 'Up') {
            Write-Host 'ERROR: Strict NRPT DoH (1.1.1.1) requires v2rayN TUN to be actively UP during deployment.' -ForegroundColor Red
            $applyExitCode = 2
        }
    }
    if ($applyExitCode -eq 0) {
        Write-CanonicalPolicyAtomic
        Write-Ok ('preflight passed (NIC=' + (($physUp | ForEach-Object { $_.Name }) -join ',') + ', TUN=' + $TunName + ':' + $tunAdapter.Status + ')')

        # Step 1: Capture pristine DNS baseline & apply selected DNS/IPv6/NTP switches
        if (-not $hasDnsBaseline) {
            Write-Step 'step 1/4: capturing DNS/IPv6/NTP baseline and applying DNS policy'
            $dnsArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Get-PolicyScriptPath '01-dns-hardening.ps1'),
                '-Root', $Root, '-TunName', $TunName, '-DnsServer', $targetDns, '-Force')
            if (-not $policy.DisablePhysicalIpv6) { $dnsArgs += '-SkipIpv6Disable' }
            if (-not $policy.PreferIpv4Prefix)    { $dnsArgs += '-SkipIpv4Prefer' }
            if (-not $policy.DisableLlmnrNetbios) { $dnsArgs += '-SkipLlmnrNetbios' }
            if (-not $policy.DisableSmhnr)        { $dnsArgs += '-SkipSmhnr' }
            if (-not $policy.DomesticNtp)         { $dnsArgs += '-SkipNtp' }
            if (-not $policy.BlockWebRtcLeak)     { $dnsArgs += '-SkipWebRtcPolicy' }
            if ($policy.StrictNrptDoh)            { $dnsArgs += '-UseNrpt' }
            & $psExe @dnsArgs
            if ($LASTEXITCODE -ne 0) { throw ('01-dns-hardening.ps1 exited with code ' + $LASTEXITCODE) }

            # If user explicitly unchecked LockPhysicalDns (and StrictNrptDoh is off), restore original NIC DNS while keeping baseline intact
            if (-not $policy.LockPhysicalDns -and -not $policy.StrictNrptDoh) {
                $db = Get-BaselineDnsObject
                if ($db -and $db.Dns) {
                    foreach ($d in @($db.Dns)) {
                        try {
                            if ($d.WasStatic -and @($d.Ipv4Servers).Count -gt 0) {
                                Set-DnsClientServerAddress -InterfaceAlias $d.Name -ServerAddresses @($d.Ipv4Servers) -ErrorAction SilentlyContinue
                            }
                            else {
                                Set-DnsClientServerAddress -InterfaceAlias $d.Name -ResetServerAddresses -ErrorAction SilentlyContinue
                            }
                        }
                        catch { }
                    }
                    Write-Note 'restored original adapter DNS (LockPhysicalDns=false)'
                }
                try {
                    $cKeyInit = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
                    $eKeyInit = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                    if (Test-Path -LiteralPath $cKeyInit) {
                        if ($db -and ($db.PSObject.Properties.Name -contains 'ChromeDohMode') -and $null -ne $db.ChromeDohMode) {
                            New-ItemProperty -Path $cKeyInit -Name 'DnsOverHttpsMode' -Value ([string]$db.ChromeDohMode) -PropertyType String -Force | Out-Null
                        } else {
                            Remove-ItemProperty -Path $cKeyInit -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue
                        }
                    }
                    if (Test-Path -LiteralPath $eKeyInit) {
                        if ($db -and ($db.PSObject.Properties.Name -contains 'EdgeDohMode') -and $null -ne $db.EdgeDohMode) {
                            New-ItemProperty -Path $eKeyInit -Name 'DnsOverHttpsMode' -Value ([string]$db.EdgeDohMode) -PropertyType String -Force | Out-Null
                        } else {
                            Remove-ItemProperty -Path $eKeyInit -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue
                        }
                    }
                } catch { }
            }
        }

        # Step 2: Capture pristine Firewall baseline & install AI-Guard rules (with 30-min rollback safety net)
        if (-not $hasFwBaseline) {
            Write-Step 'step 2/4: capturing Firewall baseline and installing kernel WFP guard rules'
            $ksArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Get-PolicyScriptPath '02-killswitch.ps1'),
                '-Root', $Root, '-V2rayNRoot', $V2rayNRoot, '-TunName', $TunName, '-DnsServer', $targetDns,
                '-RollbackMinutes', '30', '-SkipDnsCheck', '-AllowRemainingRules', '-Force')
            if (-not $policy.AllowCnDirect)        { $ksArgs += '-StrictKillSwitchOnly' }
            if (-not $policy.AllowLan)             { $ksArgs += '-SkipLanRule' }
            if (-not $policy.AllowNcsi)            { $ksArgs += '-SkipNcsiRule' }
            if (-not $policy.BlockWebRtcLeak)      { $ksArgs += '-SkipWebRtcBlock' }
            if (-not $policy.DisablePhysicalIpv6)  { $ksArgs += '-SkipIpv6Block' }
            if (-not $policy.QuarantineRogueAllow) { $ksArgs += '-KeepExistingAllowRules' }
            & $psExe @ksArgs
            if ($LASTEXITCODE -ne 0) { throw ('02-killswitch.ps1 exited with code ' + $LASTEXITCODE) }
        }

        # Step 3: Connectivity verification (defer cancelling AI-Guard-Test-Rollback until all finalization steps pass)
        Write-Step 'step 3/4: verifying live connectivity (rollback timer stays armed until all finalization steps succeed)'
        try {
            $probeResult = Invoke-QuickConnectivityCheck -AllowCn ([bool]$policy.AllowCnDirect)
            Write-Ok ('connectivity check passed (' + $probeResult + ')')
            $pendingRollbackCancel = $true
        }
        catch {
            if ($ForceCommit) {
                Write-Warn ('connectivity probe failed (' + $_.Exception.Message + '), but -ForceCommit specified')
                $pendingRollbackCancel = $true
            }
            else {
                Write-Warn ('connectivity probe failed: ' + $_.Exception.Message)
                Write-Warn 'Keeping 30-minute AI-Guard-Test-Rollback safety timer armed! Fix TUN/network or click Rollback.'
                $applyExitCode = 4
            }
        }
    }
}
else {
    # -------------------------------------------------------------- Incremental Update on Existing Deployment
    $dnsBackup = Get-BaselineDnsObject

    # Ensure core firewall rules exist; if missing, repair them via 02-killswitch.ps1 -Force -SkipRollbackTask
    $coreMissing = $false
    foreach ($coreRn in @('AI-Guard-Allow-TUN', 'AI-Guard-Allow-Node-TCP', 'AI-Guard-Allow-DoH-Ali', 'AI-Guard-Allow-DHCP')) {
        if (-not (Get-NetFirewallRule -DisplayName $coreRn -ErrorAction SilentlyContinue)) { $coreMissing = $true; break }
    }
    if ($coreMissing) {
        Write-Step 'recreating missing core firewall rules'
        $tunAdapter = Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { ($knownTuns -contains $_.Name) -or $_.InterfaceDescription -match '(?i)Wintun|sing-tun|Mihomo' } |
            Select-Object -First 1
        if ($tunAdapter) { $TunName = $tunAdapter.Name }
        $ksArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Get-PolicyScriptPath '02-killswitch.ps1'),
            '-Root', $Root, '-V2rayNRoot', $V2rayNRoot, '-TunName', $TunName, '-DnsServer', $targetDns,
            '-SkipRollbackTask', '-SkipDnsCheck', '-AllowRemainingRules', '-Force')
        if (-not $policy.AllowCnDirect)        { $ksArgs += '-StrictKillSwitchOnly' }
        if (-not $policy.AllowLan)             { $ksArgs += '-SkipLanRule' }
        if (-not $policy.AllowNcsi)            { $ksArgs += '-SkipNcsiRule' }
        if (-not $policy.BlockWebRtcLeak)      { $ksArgs += '-SkipWebRtcBlock' }
        if (-not $policy.DisablePhysicalIpv6)  { $ksArgs += '-SkipIpv6Block' }
        if (-not $policy.QuarantineRogueAllow) { $ksArgs += '-KeepExistingAllowRules' }
        & $psExe @ksArgs
    }

    Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultOutboundAction Block -Enabled True

    # Ensure AI-Guard-Allow-TUN(-Alt) only allows TUN IPs/subnets (prevents physical-IP bound sockets bypassing WFP)
    try {
        $physIpList = @(Get-NetIPAddress -InterfaceAlias @(Get-PhysicalAdaptersAll | Select-Object -ExpandProperty Name) -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -and $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
            Select-Object -ExpandProperty IPAddress -Unique)
        $tunAdaptersAll = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { ($knownTuns -contains $_.Name) -or $_.InterfaceDescription -match '(?i)Wintun|sing-tun|Mihomo' })
        $tunIpList = @()
        if ($tunAdaptersAll.Count -gt 0) {
            $tunIpList = @(Get-NetIPAddress -InterfaceIndex @($tunAdaptersAll | Select-Object -ExpandProperty ifIndex) -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -and $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -notlike 'fe80::*' -and ($physIpList -notcontains $_.IPAddress) } |
                ForEach-Object { ($_.IPAddress -split '%')[0] } | Select-Object -Unique)
        }
        $tunScope = @($tunIpList)
        foreach ($cidr in @('172.18.0.0/16', '172.19.0.0/16', '172.20.0.0/16', '198.18.0.0/15', '100.64.0.0/10')) {
            $overlap = $false
            $cp = $cidr -split '/'
            $nb = ([System.Net.IPAddress]::Parse($cp[0])).GetAddressBytes()
            $plen = [int]$cp[1]
            $mask = if ($plen -eq 0) { [uint32]0 } else { [uint32]::MaxValue -shl (32 - $plen) }
            $nhost = ([uint32]$nb[0] -shl 24) -bor ([uint32]$nb[1] -shl 16) -bor ([uint32]$nb[2] -shl 8) -bor [uint32]$nb[3]
            foreach ($pip in $physIpList) {
                $pb = ([System.Net.IPAddress]::Parse($pip)).GetAddressBytes()
                $ph = ([uint32]$pb[0] -shl 24) -bor ([uint32]$pb[1] -shl 16) -bor ([uint32]$pb[2] -shl 8) -bor [uint32]$pb[3]
                if (($ph -band $mask) -eq ($nhost -band $mask)) { $overlap = $true; break }
            }
            if (-not $overlap -and ($tunScope -notcontains $cidr)) { $tunScope += $cidr }
        }
        $tunScope += @('fc00::/7', 'fe80::/10')
        $tunScope = @($tunScope | Select-Object -Unique)
        foreach ($trName in @('AI-Guard-Allow-TUN', 'AI-Guard-Allow-TUN-Alt')) {
            $trObj = Get-NetFirewallRule -Name $trName -ErrorAction SilentlyContinue
            if ($trObj -and $tunScope.Count -gt 0) {
                Set-NetFirewallRule -InputObject $trObj -LocalAddress $tunScope -ErrorAction SilentlyContinue
            }
        }
        $tunNamesActive = @($tunAdaptersAll | Select-Object -ExpandProperty Name -Unique)
        $physAliasForTunBlk = @(Get-PhysicalAdaptersAll | Select-Object -ExpandProperty Name)
        $physCidrsForTunBlk = @(Get-PhysicalEgressCidrsPolicy -PhysicalAlias $physAliasForTunBlk -TunAlias $tunNamesActive)
        if ($physCidrsForTunBlk.Count -eq 0) { $physCidrsForTunBlk = $physIpList }
        if ($tunNamesActive.Count -gt 0 -and $physCidrsForTunBlk.Count -gt 0) {
            $blkPhysTun = Get-NetFirewallRule -Name 'AI-Guard-Block-PhysicalIP-On-TUN' -ErrorAction SilentlyContinue
            if ($blkPhysTun) {
                Set-NetFirewallRule -InputObject $blkPhysTun -InterfaceAlias $tunNamesActive -LocalAddress $physCidrsForTunBlk -Enabled True -ErrorAction SilentlyContinue
            }
            else {
                New-NetFirewallRule -Name 'AI-Guard-Block-PhysicalIP-On-TUN' -DisplayName 'AI-Guard-Block-PhysicalIP-On-TUN' `
                    -Direction Outbound -Action Block -InterfaceAlias $tunNamesActive -LocalAddress $physCidrsForTunBlk -Protocol Any -Profile Any -Enabled True `
                    -Description 'Explicitly block sockets bound to physical NIC subnets from matching Xray TUN soft-permit on TUN interface.' | Out-Null
            }
        }
    }
    catch { }

    # 1. Traffic Routing & Firewall Boundary toggles
    Write-Step 'applying firewall & routing boundary policy'

    # 1a. AllowCnDirect
    if ($policy.AllowCnDirect) {
        @(Get-NetFirewallRule -DisplayName 'AI-Guard-Block-DNS-*' -ErrorAction SilentlyContinue) +
        @(Get-NetFirewallRule -DisplayName 'AI-Guard-Block-DoT' -ErrorAction SilentlyContinue) |
            Where-Object { $_ } | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        $cnRule = Get-NetFirewallRule -Name 'AI-Guard-Allow-CN' -ErrorAction SilentlyContinue
        if ($cnRule -and $cnRule.Enabled -ne 'True') {
            Enable-NetFirewallRule -Name 'AI-Guard-Allow-CN' -ErrorAction SilentlyContinue
        }
        Write-Ok 'AllowCnDirect = ON (mainland-China direct allowlist active)'
    }
    else {
        $cnRule = Get-NetFirewallRule -Name 'AI-Guard-Allow-CN' -ErrorAction SilentlyContinue
        if ($cnRule -and $cnRule.Enabled -eq 'True') {
            Disable-NetFirewallRule -Name 'AI-Guard-Allow-CN' -ErrorAction SilentlyContinue
        }
        Write-Ok 'AllowCnDirect = OFF (strict global fail-closed lock active)'
    }

    # 1b. AllowLan
    $lanRule = Get-NetFirewallRule -DisplayName 'AI-Guard-Allow-LAN' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($policy.AllowLan) {
        if (-not $lanRule) {
            New-NetFirewallRule -Name 'AI-Guard-Allow-LAN' -DisplayName 'AI-Guard-Allow-LAN' `
                -Direction Outbound -Action Allow -RemoteAddress @('LocalSubnet', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16') -Profile Any -Enabled True `
                -Description 'Local subnet and private LAN subnets (RFC1918).' | Out-Null
        }
        elseif ($lanRule.Enabled -ne 'True') {
            Enable-NetFirewallRule -InputObject $lanRule -ErrorAction SilentlyContinue
        }
        Write-Ok 'AllowLan = ON (LocalSubnet access enabled)'
    }
    else {
        if ($lanRule -and $lanRule.Enabled -eq 'True') {
            Disable-NetFirewallRule -InputObject $lanRule -ErrorAction SilentlyContinue
        }
        Write-Ok 'AllowLan = OFF (LocalSubnet isolated)'
    }

    # 1c. AllowNcsi
    $ncsiRule = Get-NetFirewallRule -DisplayName 'AI-Guard-Allow-NCSI' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($policy.AllowNcsi) {
        if (-not $ncsiRule) {
            New-NetFirewallRule -Name 'AI-Guard-Allow-NCSI' -DisplayName 'AI-Guard-Allow-NCSI' `
                -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress '13.107.4.52' -RemotePort @('80') `
                -Profile Any -Enabled True `
                -Description 'Windows NCSI connecttest.txt HTTP-80 probe (prevents false No-Internet globe when TUN is off).' | Out-Null
        }
        elseif ($ncsiRule.Enabled -ne 'True') {
            Enable-NetFirewallRule -InputObject $ncsiRule -ErrorAction SilentlyContinue
        }
        Write-Ok 'AllowNcsi = ON (Windows connectivity indicator probe allowed)'
    }
    else {
        if ($ncsiRule -and $ncsiRule.Enabled -eq 'True') {
            Disable-NetFirewallRule -InputObject $ncsiRule -ErrorAction SilentlyContinue
        }
        Write-Ok 'AllowNcsi = OFF (NCSI probe blocked)'
    }

    # 1d. QuarantineRogueAllow
    $qFile = Join-Path $BackupDir 'auto-disabled-outbound-allow.json'
    if (-not $policy.QuarantineRogueAllow) {
        $restoredCnt = 0
        if (Test-Path -LiteralPath $qFile) {
            try {
                foreach ($qr in @((Read-GuardQuarantineList -Path $qFile).Items)) {
                    if ($qr.Name) {
                        Enable-NetFirewallRule -Name $qr.Name -ErrorAction SilentlyContinue
                        $restoredCnt++
                    }
                }
                Remove-Item -LiteralPath $qFile -Force -ErrorAction SilentlyContinue
            }
            catch { }
        }
        Write-Ok ('QuarantineRogueAllow = OFF (restored ' + $restoredCnt + ' dynamically quarantined rule(s))')
    }
    else {
        Write-Ok 'QuarantineRogueAllow = ON (outbound allow drift protection active)'
    }

    # 2. DNS & Leak-Shield Hardening toggles
    Write-Step 'applying DNS & leak-shield policy'
    if ($policy.StrictNrptDoh) {
        $activeTunNow = Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq 'Up' -and (($knownTuns -contains $_.Name) -or $_.InterfaceDescription -match '(?i)Wintun|sing-tun|Mihomo') } |
            Select-Object -First 1
        if (-not $activeTunNow) {
            Write-Warn 'TUN is currently OFF; Strict NRPT DoH (1.1.1.1) will block DNS resolution until TUN is turned ON.'
        }
        try {
            $existingDoh = Get-DnsClientDohServerAddress -ServerAddress '1.1.1.1' -ErrorAction SilentlyContinue
            if ($existingDoh) {
                Set-DnsClientDohServerAddress -ServerAddress '1.1.1.1' -DohTemplate 'https://cloudflare-dns.com/dns-query' -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction Stop
            }
            else {
                Add-DnsClientDohServerAddress -ServerAddress '1.1.1.1' -DohTemplate 'https://cloudflare-dns.com/dns-query' -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction Stop
            }
        }
        catch { }
        @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -like 'AI-Guard*' }) |
            Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue
        Add-DnsClientNrptRule -Namespace '.' -NameServers '1.1.1.1' -Comment 'AI-Guard-NRPT' | Out-Null
        foreach ($pa in (Get-PhysicalAdaptersAll)) {
            try { Set-DnsClientServerAddress -InterfaceAlias $pa.Name -ServerAddresses '1.1.1.1' -ErrorAction SilentlyContinue } catch { }
        }
        Write-Ok 'StrictNrptDoh = ON (global DoH-only NRPT 1.1.1.1 active)'
    }
    else {
        $oldNrpt = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -like 'AI-Guard*' })
        if ($oldNrpt.Count -gt 0) {
            $oldNrpt | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue
            Write-Note 'removed AI-Guard NRPT rules'
        }
        if ($policy.LockPhysicalDns) {
            foreach ($pa in (Get-PhysicalAdaptersAll)) {
                try { Set-DnsClientServerAddress -InterfaceAlias $pa.Name -ServerAddresses $targetDns -ErrorAction SilentlyContinue } catch { }
            }
            Write-Ok ('LockPhysicalDns = ON (physical adapters locked to ' + $targetDns + ')')
        }
        else {
            foreach ($pa in (Get-PhysicalAdaptersAll)) {
                $rec = if ($dnsBackup -and $dnsBackup.Dns) { @($dnsBackup.Dns | Where-Object { $_.Name -eq $pa.Name }) | Select-Object -First 1 } else { $null }
                try {
                    if ($rec -and $rec.WasStatic -and @($rec.Ipv4Servers).Count -gt 0) {
                        Set-DnsClientServerAddress -InterfaceAlias $pa.Name -ServerAddresses @($rec.Ipv4Servers) -ErrorAction SilentlyContinue
                    }
                    else {
                        Set-DnsClientServerAddress -InterfaceAlias $pa.Name -ResetServerAddresses -ErrorAction SilentlyContinue
                    }
                }
                catch { }
            }
            Write-Ok 'LockPhysicalDns = OFF (restored original DHCP / custom adapter DNS)'
        }
    }

    $cPolKey = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
    $ePolKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    if ($policy.LockPhysicalDns -or $policy.StrictNrptDoh) {
        try {
            if (-not (Test-Path -LiteralPath $cPolKey)) { New-Item -Path $cPolKey -Force | Out-Null }
            New-ItemProperty -Path $cPolKey -Name 'DnsOverHttpsMode' -Value 'off' -PropertyType String -Force | Out-Null
            if (-not (Test-Path -LiteralPath $ePolKey)) { New-Item -Path $ePolKey -Force | Out-Null }
            New-ItemProperty -Path $ePolKey -Name 'DnsOverHttpsMode' -Value 'off' -PropertyType String -Force | Out-Null
            Write-Ok 'BrowserDoh = OFF (Chrome & Edge DnsOverHttpsMode=off; DNS routed via TUN)'
        } catch { }
    }
    else {
        try {
            if (Test-Path -LiteralPath $cPolKey) {
                if ($dnsBackup -and ($dnsBackup.PSObject.Properties.Name -contains 'ChromeDohMode') -and $null -ne $dnsBackup.ChromeDohMode) {
                    New-ItemProperty -Path $cPolKey -Name 'DnsOverHttpsMode' -Value ([string]$dnsBackup.ChromeDohMode) -PropertyType String -Force | Out-Null
                }
                else {
                    Remove-ItemProperty -Path $cPolKey -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue
                }
            }
            if (Test-Path -LiteralPath $ePolKey) {
                if ($dnsBackup -and ($dnsBackup.PSObject.Properties.Name -contains 'EdgeDohMode') -and $null -ne $dnsBackup.EdgeDohMode) {
                    New-ItemProperty -Path $ePolKey -Name 'DnsOverHttpsMode' -Value ([string]$dnsBackup.EdgeDohMode) -PropertyType String -Force | Out-Null
                }
                else {
                    Remove-ItemProperty -Path $ePolKey -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue
                }
            }
        } catch { }
        Write-Ok 'BrowserDoh = RESTORED (Chrome & Edge built-in DoH restored)'
    }

    # 2b. DisableSmhnr & DisableLlmnrNetbios (guard New-Item with Test-Path!)
    $dnsPolKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    $dnsSvcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
    if (-not (Test-Path -LiteralPath $dnsPolKey)) {
        New-Item -Path $dnsPolKey -Force | Out-Null
    }
    if ($policy.DisableSmhnr) {
        New-ItemProperty -Path $dnsPolKey -Name 'DisableSmartNameResolution' -Value 1 -PropertyType DWord -Force | Out-Null
        if (Test-Path -LiteralPath $dnsSvcKey) {
            New-ItemProperty -Path $dnsSvcKey -Name 'DisableSmartNameResolution' -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Ok 'DisableSmhnr = ON (Smart Multi-Homed Name Resolution disabled)'
    }
    else {
        if ($dnsBackup -and ($dnsBackup.PSObject.Properties.Name -contains 'SmartNameResolutionPolicy') -and $null -ne $dnsBackup.SmartNameResolutionPolicy) {
            New-ItemProperty -Path $dnsPolKey -Name 'DisableSmartNameResolution' -Value ([int]$dnsBackup.SmartNameResolutionPolicy) -PropertyType DWord -Force | Out-Null
        }
        else {
            Remove-ItemProperty -Path $dnsPolKey -Name 'DisableSmartNameResolution' -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $dnsSvcKey) {
            if ($dnsBackup -and ($dnsBackup.PSObject.Properties.Name -contains 'SmartNameResolutionService') -and $null -ne $dnsBackup.SmartNameResolutionService) {
                New-ItemProperty -Path $dnsSvcKey -Name 'DisableSmartNameResolution' -Value ([int]$dnsBackup.SmartNameResolutionService) -PropertyType DWord -Force | Out-Null
            }
            else {
                Remove-ItemProperty -Path $dnsSvcKey -Name 'DisableSmartNameResolution' -ErrorAction SilentlyContinue
            }
        }
        Write-Ok 'DisableSmhnr = OFF (restored Windows default SMHNR)'
    }

    if ($policy.DisableLlmnrNetbios) {
        New-ItemProperty -Path $dnsPolKey -Name 'EnableMulticast' -Value 0 -PropertyType DWord -Force | Out-Null
        if (Test-Path -LiteralPath $dnsSvcKey) {
            New-ItemProperty -Path $dnsSvcKey -Name 'EnableMDNS' -Value 0 -PropertyType DWord -Force | Out-Null
        }
        foreach ($pa in (Get-PhysicalAdaptersAll)) {
            if ($pa.InterfaceGuid) {
                $nbk = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_' + $pa.InterfaceGuid
                if (Test-Path -LiteralPath $nbk) {
                    New-ItemProperty -Path $nbk -Name 'NetbiosOptions' -Value 2 -PropertyType DWord -Force | Out-Null
                }
            }
        }
        Write-Ok 'DisableLlmnrNetbios = ON (LLMNR, mDNS & NetBIOS disabled)'
    }
    else {
        if ($dnsBackup -and $null -ne $dnsBackup.Llmnr) {
            New-ItemProperty -Path $dnsPolKey -Name 'EnableMulticast' -Value ([int]$dnsBackup.Llmnr) -PropertyType DWord -Force | Out-Null
        }
        else {
            Remove-ItemProperty -Path $dnsPolKey -Name 'EnableMulticast' -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $dnsSvcKey) {
            if ($dnsBackup -and ($dnsBackup.PSObject.Properties.Name -contains 'MdnsEnabled') -and $null -ne $dnsBackup.MdnsEnabled) {
                New-ItemProperty -Path $dnsSvcKey -Name 'EnableMDNS' -Value ([int]$dnsBackup.MdnsEnabled) -PropertyType DWord -Force | Out-Null
            }
            else {
                Remove-ItemProperty -Path $dnsSvcKey -Name 'EnableMDNS' -ErrorAction SilentlyContinue
            }
        }
        if ($dnsBackup -and $dnsBackup.Netbios) {
            foreach ($nb in @($dnsBackup.Netbios)) {
                $nbk = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\' + $nb.Key
                if (Test-Path -LiteralPath $nbk) {
                    if ($null -eq $nb.NetbiosOptions) { Remove-ItemProperty -Path $nbk -Name 'NetbiosOptions' -ErrorAction SilentlyContinue }
                    else { New-ItemProperty -Path $nbk -Name 'NetbiosOptions' -Value ([int]$nb.NetbiosOptions) -PropertyType DWord -Force | Out-Null }
                }
            }
        }
        else {
            foreach ($pa in (Get-PhysicalAdaptersAll)) {
                if ($pa.InterfaceGuid) {
                    $nbk = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_' + $pa.InterfaceGuid
                    if (Test-Path -LiteralPath $nbk) {
                        New-ItemProperty -Path $nbk -Name 'NetbiosOptions' -Value 0 -PropertyType DWord -Force | Out-Null
                    }
                }
            }
        }
        Write-Ok 'DisableLlmnrNetbios = OFF (restored default multicast & NetBIOS)'
    }

    # 2c. BlockWebRtcLeak (physical NIC STUN/TURN firewall rules + LocalIP subnet rules + 15-webrtc-browser-shield + Chrome/Edge policy)
    $wrtcPorts = @(Get-StunGuardPortStrings)
    $cPolKey = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
    $ePolKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    $shieldScript = Get-PolicyScriptPath '15-webrtc-browser-shield.ps1'
    $ruleWrtcUdp = Get-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-UDP' -ErrorAction SilentlyContinue
    $ruleWrtcTcp = Get-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-TCP' -ErrorAction SilentlyContinue
    $ruleWrtcLocalUdp = Get-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-LocalIP-UDP' -ErrorAction SilentlyContinue
    $ruleWrtcLocalTcp = Get-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-LocalIP-TCP' -ErrorAction SilentlyContinue
    if ($policy.BlockWebRtcLeak) {
        $physAliasList = @(Get-PhysicalAdaptersAll | Select-Object -ExpandProperty Name)
        if ($physAliasList.Count -gt 0) {
            if ($ruleWrtcUdp) {
                Set-NetFirewallRule -InputObject $ruleWrtcUdp -InterfaceAlias $physAliasList -Enabled True -ErrorAction SilentlyContinue
            }
            else {
                New-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-UDP' -DisplayName 'AI-Guard-Block-WebRTC-UDP' `
                    -Direction Outbound -Action Block -Protocol UDP -RemotePort $wrtcPorts `
                    -InterfaceAlias $physAliasList -Profile Any -Enabled True `
                    -Description 'Block WebRTC STUN/TURN outbound UDP on physical NICs (anti-leak for all proxy cores).' | Out-Null
            }
            if ($ruleWrtcTcp) {
                Set-NetFirewallRule -InputObject $ruleWrtcTcp -InterfaceAlias $physAliasList -Enabled True -ErrorAction SilentlyContinue
            }
            else {
                New-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-TCP' -DisplayName 'AI-Guard-Block-WebRTC-TCP' `
                    -Direction Outbound -Action Block -Protocol TCP -RemotePort $wrtcPorts `
                    -InterfaceAlias $physAliasList -Profile Any -Enabled True `
                    -Description 'Block WebRTC STUN/TURN outbound TCP on physical NICs (anti-leak for all proxy cores).' | Out-Null
            }
            $physCidrs = @(Get-PhysicalEgressCidrsPolicy -PhysicalAlias $physAliasList -TunAlias $knownTuns)
            if ($physCidrs.Count -gt 0) {
                if ($ruleWrtcLocalUdp) {
                    Set-NetFirewallRule -InputObject $ruleWrtcLocalUdp -LocalAddress $physCidrs -Enabled True -ErrorAction SilentlyContinue
                }
                else {
                    New-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-LocalIP-UDP' -DisplayName 'AI-Guard-Block-WebRTC-LocalIP-UDP' `
                        -Direction Outbound -Action Block -Protocol UDP -LocalAddress $physCidrs -RemotePort $wrtcPorts `
                        -Profile Any -Enabled True `
                        -Description 'Block WebRTC STUN/TURN UDP bound to physical NIC subnets even when TUN metric 0 captures ALE routing.' | Out-Null
                }
                if ($ruleWrtcLocalTcp) {
                    Set-NetFirewallRule -InputObject $ruleWrtcLocalTcp -LocalAddress $physCidrs -Enabled True -ErrorAction SilentlyContinue
                }
                else {
                    New-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-LocalIP-TCP' -DisplayName 'AI-Guard-Block-WebRTC-LocalIP-TCP' `
                        -Direction Outbound -Action Block -Protocol TCP -LocalAddress $physCidrs -RemotePort $wrtcPorts `
                        -Profile Any -Enabled True `
                        -Description 'Block WebRTC STUN/TURN TCP bound to physical NIC subnets even when TUN metric 0 captures ALE routing.' | Out-Null
                }
            }
        }
        if (Test-Path -LiteralPath $shieldScript) {
            try {
                & $psExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $shieldScript -Apply -Quiet | Out-Null
            } catch { }
        }
        try {
            if (-not (Test-Path -LiteralPath $cPolKey)) { New-Item -Path $cPolKey -Force | Out-Null }
            New-ItemProperty -Path $cPolKey -Name 'WebRtcIPHandlingPolicy' -Value 'disable_non_proxied_udp' -PropertyType String -Force | Out-Null
            if (-not (Test-Path -LiteralPath $ePolKey)) { New-Item -Path $ePolKey -Force | Out-Null }
            New-ItemProperty -Path $ePolKey -Name 'WebRtcIPHandlingPolicy' -Value 'disable_non_proxied_udp' -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $ePolKey -Name 'WebRtcLocalhostIpHandling' -Value 'disable_non_proxied_udp' -PropertyType String -Force | Out-Null
        } catch { }
        Write-Ok 'BlockWebRtcLeak = ON (physical NIC + LocalIP subnet + browser shield + Chrome/Edge policy)'
    }
    else {
        foreach ($wr in @($ruleWrtcUdp, $ruleWrtcTcp, $ruleWrtcLocalUdp, $ruleWrtcLocalTcp)) {
            if ($wr -and $wr.Enabled -eq 'True') {
                Disable-NetFirewallRule -InputObject $wr -ErrorAction SilentlyContinue
            }
        }
        if (Test-Path -LiteralPath $shieldScript) {
            try {
                & $psExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $shieldScript -Remove -Quiet | Out-Null
            } catch { }
        }
        try {
            Get-NetFirewallRule -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^AI-Guard-Block-WebRTC-(?:.+-PhysUDP|.+-CoreSTUN-(?:UDP|TCP))$' -and $_.Enabled -eq 'True' } |
                Disable-NetFirewallRule -ErrorAction SilentlyContinue
        } catch { }
        try {
            if (Test-Path -LiteralPath $cPolKey) {
                if ($dnsBackup -and ($dnsBackup.PSObject.Properties.Name -contains 'ChromeWebRtcPolicy') -and $null -ne $dnsBackup.ChromeWebRtcPolicy) {
                    New-ItemProperty -Path $cPolKey -Name 'WebRtcIPHandlingPolicy' -Value ([string]$dnsBackup.ChromeWebRtcPolicy) -PropertyType String -Force | Out-Null
                }
                else {
                    Remove-ItemProperty -Path $cPolKey -Name 'WebRtcIPHandlingPolicy' -ErrorAction SilentlyContinue
                }
            }
            if (Test-Path -LiteralPath $ePolKey) {
                if ($dnsBackup -and ($dnsBackup.PSObject.Properties.Name -contains 'EdgeWebRtcPolicy') -and $null -ne $dnsBackup.EdgeWebRtcPolicy) {
                    New-ItemProperty -Path $ePolKey -Name 'WebRtcIPHandlingPolicy' -Value ([string]$dnsBackup.EdgeWebRtcPolicy) -PropertyType String -Force | Out-Null
                }
                else {
                    Remove-ItemProperty -Path $ePolKey -Name 'WebRtcIPHandlingPolicy' -ErrorAction SilentlyContinue
                }
                if ($dnsBackup -and ($dnsBackup.PSObject.Properties.Name -contains 'EdgeWebRtcLocalhost') -and $null -ne $dnsBackup.EdgeWebRtcLocalhost) {
                    New-ItemProperty -Path $ePolKey -Name 'WebRtcLocalhostIpHandling' -Value ([string]$dnsBackup.EdgeWebRtcLocalhost) -PropertyType String -Force | Out-Null
                }
                else {
                    Remove-ItemProperty -Path $ePolKey -Name 'WebRtcLocalhostIpHandling' -ErrorAction SilentlyContinue
                }
            }
        } catch { }
        Write-Ok 'BlockWebRtcLeak = OFF (WebRTC STUN block rules disabled & browser policies restored)'
    }

    # 3. IPv6 & Dual-Stack Precedence toggles
    Write-Step 'applying IPv6 & dual-stack precedence policy'
    if ($policy.DisablePhysicalIpv6) {
        foreach ($pa in (Get-PhysicalAdaptersAll)) {
            try {
                $b = Get-NetAdapterBinding -Name $pa.Name -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue
                if ($b -and $b.Enabled) {
                    Disable-NetAdapterBinding -Name $pa.Name -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue
                }
            }
            catch { }
        }
        Get-NetFirewallRule -Name 'AI-Guard-Allow-DHCPv6', 'AI-Guard-Allow-NDP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-Ok 'DisablePhysicalIpv6 = ON (ms_tcpip6 unbound on physical adapters)'
    }
    else {
        $hpFile = Join-Path $BackupDir 'hotplug-ipv6.json'
        $hpNames = @()
        if (Test-Path -LiteralPath $hpFile) {
            try { $hpNames = @(Get-Content -LiteralPath $hpFile -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { }
        }
        foreach ($pa in (Get-PhysicalAdaptersAll)) {
            $rec = if ($dnsBackup -and $dnsBackup.Dns) { @($dnsBackup.Dns | Where-Object { $_.Name -eq $pa.Name }) | Select-Object -First 1 } else { $null }
            $shouldEnable = if ($rec -and $null -ne $rec.Ipv6Binding) { [bool]$rec.Ipv6Binding } else { $true }
            if ($shouldEnable -or ($hpNames -contains $pa.Name)) {
                try { Enable-NetAdapterBinding -Name $pa.Name -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue } catch { }
            }
        }
        $v6BlkRule = Get-NetFirewallRule -Name 'AI-Guard-Block-Foreign-Physical-IPv6' -ErrorAction SilentlyContinue
        if ($v6BlkRule -and $v6BlkRule.Enabled -eq 'True') {
            Disable-NetFirewallRule -InputObject $v6BlkRule -ErrorAction SilentlyContinue
        }

        $dhcp6Rule = Get-NetFirewallRule -Name 'AI-Guard-Allow-DHCPv6' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($dhcp6Rule) {
            try {
                Set-NetFirewallRule -InputObject $dhcp6Rule -Protocol UDP -LocalPort @('546') -RemotePort @('547') -RemoteAddress @('fe80::/10', 'ff02::1:2') -InterfaceAlias 'Any' -Enabled True -ErrorAction Stop
            }
            catch {
                $dhcp6Rule | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                New-NetFirewallRule -Name 'AI-Guard-Allow-DHCPv6' -DisplayName 'AI-Guard-Allow-DHCPv6' `
                    -Direction Outbound -Action Allow -Protocol UDP -LocalPort @('546') -RemotePort @('547') `
                    -RemoteAddress @('fe80::/10', 'ff02::1:2') -Profile Any -Enabled True `
                    -Description 'Link-local DHCPv6 lease renewal when temporary IPv6 is enabled.' | Out-Null
            }
        }
        else {
            New-NetFirewallRule -Name 'AI-Guard-Allow-DHCPv6' -DisplayName 'AI-Guard-Allow-DHCPv6' `
                -Direction Outbound -Action Allow -Protocol UDP -LocalPort @('546') -RemotePort @('547') `
                -RemoteAddress @('fe80::/10', 'ff02::1:2') -Profile Any -Enabled True `
                -Description 'Link-local DHCPv6 lease renewal when temporary IPv6 is enabled.' | Out-Null
        }

        $ndpRule = Get-NetFirewallRule -Name 'AI-Guard-Allow-NDP' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($ndpRule) {
            try {
                Set-NetFirewallRule -InputObject $ndpRule -Protocol ICMPv6 -IcmpType @('133', '134', '135', '136') -RemoteAddress @('fe80::/10', 'ff02::/16') -InterfaceAlias 'Any' -Enabled True -ErrorAction Stop
            }
            catch {
                $ndpRule | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                New-NetFirewallRule -Name 'AI-Guard-Allow-NDP' -DisplayName 'AI-Guard-Allow-NDP' `
                    -Direction Outbound -Action Allow -Protocol ICMPv6 -IcmpType @('133', '134', '135', '136') `
                    -RemoteAddress @('fe80::/10', 'ff02::/16') -Profile Any -Enabled True `
                    -Description 'Link-local IPv6 NDP (RS/RA/NS/NA) when temporary IPv6 is enabled.' | Out-Null
            }
        }
        else {
            New-NetFirewallRule -Name 'AI-Guard-Allow-NDP' -DisplayName 'AI-Guard-Allow-NDP' `
                -Direction Outbound -Action Allow -Protocol ICMPv6 -IcmpType @('133', '134', '135', '136') `
                -RemoteAddress @('fe80::/10', 'ff02::/16') -Profile Any -Enabled True `
                -Description 'Link-local IPv6 NDP (RS/RA/NS/NA) when temporary IPv6 is enabled.' | Out-Null
        }
        Write-Ok 'DisablePhysicalIpv6 = OFF (restored ms_tcpip6 binding on physical adapters)'
        Write-Ok 'temporary IPv6 bootstrap rules active (AI-Guard-Allow-DHCPv6 + AI-Guard-Allow-NDP, link-local only)'
    }

    $tcpip6Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
    if ($policy.PreferIpv4Prefix) {
        if (-not (Test-Path -LiteralPath $tcpip6Key)) { New-Item -Path $tcpip6Key -Force | Out-Null }
        $curDc = (Get-ItemProperty -LiteralPath $tcpip6Key -ErrorAction SilentlyContinue).DisabledComponents
        $newDc = if (-not $policy.DisablePhysicalIpv6) { 0x20 } elseif ($null -ne $curDc) { ([int]$curDc -bor 0x20) } else { 0x20 }
        New-ItemProperty -Path $tcpip6Key -Name 'DisabledComponents' -Value $newDc -PropertyType DWord -Force | Out-Null
        netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 50 4 | Out-Null
        Write-Ok ('PreferIpv4Prefix = ON (::ffff:0:0/96 precedence 50 > ::/0 40, DisabledComponents=0x' + ('{0:x}' -f $newDc) + ')')
    }
    else {
        if (Test-Path -LiteralPath $tcpip6Key) {
            if ($dnsBackup -and ($dnsBackup.PSObject.Properties.Name -contains 'Tcpip6DisabledComponents')) {
                if ($null -eq $dnsBackup.Tcpip6DisabledComponents) {
                    Remove-ItemProperty -Path $tcpip6Key -Name 'DisabledComponents' -ErrorAction SilentlyContinue
                }
                else {
                    New-ItemProperty -Path $tcpip6Key -Name 'DisabledComponents' -Value ([int]$dnsBackup.Tcpip6DisabledComponents) -PropertyType DWord -Force | Out-Null
                }
            }
            else {
                $curDc = (Get-ItemProperty -LiteralPath $tcpip6Key -ErrorAction SilentlyContinue).DisabledComponents
                if ($null -ne $curDc) {
                    $clearedDc = ([int]$curDc -band (-bnot 0x20))
                    if ($clearedDc -eq 0) { Remove-ItemProperty -Path $tcpip6Key -Name 'DisabledComponents' -ErrorAction SilentlyContinue }
                    else { New-ItemProperty -Path $tcpip6Key -Name 'DisabledComponents' -Value $clearedDc -PropertyType DWord -Force | Out-Null }
                }
            }
        }
        $restorePrec = if ($dnsBackup -and $dnsBackup.Ipv4PrefixPolicy -and $dnsBackup.Ipv4PrefixPolicy.Precedence) { [int]$dnsBackup.Ipv4PrefixPolicy.Precedence } else { 35 }
        $restoreLbl  = if ($dnsBackup -and $dnsBackup.Ipv4PrefixPolicy -and $null -ne $dnsBackup.Ipv4PrefixPolicy.Label) { [int]$dnsBackup.Ipv4PrefixPolicy.Label } else { 4 }
        netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 $restorePrec $restoreLbl | Out-Null
        Write-Ok ('PreferIpv4Prefix = OFF (restored ::ffff:0:0/96 precedence=' + $restorePrec + ')')
    }

    # 4. Domestic NTP toggle
    $w32Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
    if ($policy.DomesticNtp) {
        if (Test-Path -LiteralPath $w32Key) {
            $curNtp = [string](Get-ItemProperty -LiteralPath $w32Key -ErrorAction SilentlyContinue).NtpServer
            # Healthy = names a known-working domestic peer and no longer carries the dead www.time.ac.cn.
            if ($curNtp -notmatch '(?i)(aliyun|tencent|ntsc\.ac\.cn|203\.107\.6\.88)' -or $curNtp -match '(?i)www\.time\.ac\.cn') {
                New-ItemProperty -Path $w32Key -Name 'NtpServer' -Value 'ntp.aliyun.com,0x9 ntp.tencent.com,0x9 ntp.ntsc.ac.cn,0x9' -PropertyType String -Force | Out-Null
                $w32svc = Get-Service -Name w32time -ErrorAction SilentlyContinue
                if ($w32svc -and $w32svc.Status -eq 'Running') { w32tm /config /update 2>$null | Out-Null; w32tm /resync /nowait 2>$null | Out-Null }
            }
        }
        Write-Ok 'DomesticNtp = ON (domestic NTP peers configured)'
    }
    else {
        if ((Test-Path -LiteralPath $w32Key) -and $dnsBackup -and $dnsBackup.NtpServer) {
            New-ItemProperty -Path $w32Key -Name 'NtpServer' -Value ([string]$dnsBackup.NtpServer) -PropertyType String -Force | Out-Null
            $w32svc = Get-Service -Name w32time -ErrorAction SilentlyContinue
            if ($w32svc -and $w32svc.Status -eq 'Running') { w32tm /config /update 2>$null | Out-Null }
        }
        Write-Ok 'DomesticNtp = OFF (restored baseline NTP server)'
    }
}

# ------------------------------------------------------------------ Common Finalization (Mode Pass, ACL before Tasks, Tasks, Deferred Commit)
if ($applyExitCode -eq 0) {
    Write-Step 'synchronizing proxy node & multi-core companion firewall rules'
    $syncNodeScript = Get-PolicyScriptPath '10-sync-node-rule.ps1'
    $v2ConfigFile = Join-Path $V2rayNRoot 'binConfigs\config.json'
    if (Test-Path -LiteralPath $syncNodeScript) {
        if (Test-Path -LiteralPath $v2ConfigFile) {
            try {
                Invoke-GuardChild -ScriptPath $syncNodeScript -ChildArgs @('-Root', $Root, '-V2rayNRoot', $V2rayNRoot) -Label '10-sync-node-rule.ps1'
                Write-Ok 'multi-core node rules synchronized (xray, sing-box, v2rayN across active config.json ports)'
            }
            catch {
                $applyErrors.Add($_.Exception.Message)
                Write-Warn ('node rule synchronization failed: ' + $_.Exception.Message)
            }
        }
        else {
            Write-Note ('node rule synchronization skipped (config.json not found at ' + $v2ConfigFile + ')')
        }
    }

    # Clear Protected persistence lock if user explicitly applied a policy enabling AllowCnDirect (#10)
    $protectedLockPath = Join-Path $BackupDir 'protected-lock.flag'
    if ([bool]$policy.AllowCnDirect -and (Test-Path -LiteralPath $protectedLockPath)) {
        Remove-Item -LiteralPath $protectedLockPath -Force -ErrorAction SilentlyContinue
        Write-Ok 'cleared Protected mode lock (AllowCnDirect enabled by applied policy)'
    }

    Write-Step 'synchronizing active guard state'
    try {
        $modeSyncArgs = @('-Root', $Root, '-V2rayNRoot', $V2rayNRoot, '-DnsServer', $targetDns, '-Quiet')
        if ([bool]$policy.AllowCnDirect) { $modeSyncArgs += '-ClearProtectedLock' }
        Invoke-GuardChild -ScriptPath (Get-PolicyScriptPath '07-mode.ps1') -ChildArgs $modeSyncArgs -Label '07-mode.ps1 sync' -AllowedExitCodes @(0, 3)
        if ($LASTEXITCODE -eq 3) {
            $applyErrors.Add('07-mode.ps1 reported missing companion firewall rules (exit=3)')
        }
    }
    catch {
        $applyErrors.Add($_.Exception.Message)
        Write-Warn ('07-mode.ps1 synchronization failed: ' + $_.Exception.Message)
    }

    # ACL & SYSTEM Task lifecycle (#01 / #05):
    #   - Lock ACL BEFORE registering SYSTEM tasks.
    #   - Remove & verify ALL SYSTEM tasks BEFORE allowing ACL unlock!
    $aclHardenedOk = $false
    $enforceAclLock = [bool]$policy.HardenInstallAcl
    if ($policy.ZeroResidentMonitor -and (-not $enforceAclLock)) {
        Write-Warn 'ZeroResidentMonitor=ON requires a locked ACL on the SYSTEM script root; enforcing HardenInstallAcl.'
        $enforceAclLock = $true
    }
    $aclScript = Get-PolicyScriptPath '13-harden-acl.ps1'
    $pendingAclUnlock = $false
    if (Test-Path -LiteralPath $aclScript) {
        if ($enforceAclLock) {
            try {
                Invoke-GuardChild -ScriptPath $aclScript -ChildArgs @('-Root', $Root, '-SkipVerification', '-SkipRegression') -Label '13-harden-acl.ps1' | Out-Null
                $aclHardenedOk = $true
                Write-Ok ('HardenInstallAcl = ON (' + $Root + ' locked to Administrators/SYSTEM write-only)')
            }
            catch {
                $applyErrors.Add($_.Exception.Message)
                Write-Warn ('ACL hardening failed: ' + $_.Exception.Message)
            }
        }
        else {
            $pendingAclUnlock = $true
        }
    }
    else {
        $applyErrors.Add('required script missing: ' + $aclScript)
    }

    if ($policy.ZeroResidentMonitor) {
        if (-not $aclHardenedOk) {
            $applyErrors.Add('refused to register SYSTEM tasks because install ACL hardening did not succeed')
            Write-Warn 'Refused to register SYSTEM auto-repair tasks while install directory ACL lock failed!'
        }
        else {
            $taskArgs = @('-Root', $Root, '-V2rayNRoot', $V2rayNRoot, '-DnsServer', $targetDns, '-InstallTasks', '-Quiet')
            if (-not $policy.AutoNodeSync)         { $taskArgs += '-DisableAutoNodeSync' }
            if (-not $policy.QuarantineRogueAllow) { $taskArgs += '-SkipQuarantineAllowRules' }
            if (-not $policy.AutoHealStaleProxy)   { $taskArgs += '-SkipStaleProxyHeal' }
            try {
                Invoke-GuardChild -ScriptPath (Get-PolicyScriptPath '07-mode.ps1') -ChildArgs $taskArgs -Label '07-mode.ps1 -InstallTasks'
                $evTask = Get-ScheduledTask -TaskName 'AI-Guard-Mode-Event' -ErrorAction SilentlyContinue
                $fbTask = Get-ScheduledTask -TaskName 'AI-Guard-Mode-Fallback' -ErrorAction SilentlyContinue
                if (-not $evTask -or -not $fbTask) {
                    throw ('task verification failed (event=' + [bool]$evTask + ', fallback=' + [bool]$fbTask + ')')
                }
                Write-Ok 'ZeroResidentMonitor = ON (AI-Guard-Mode-Event + Fallback tasks registered, 0 MB idle RAM)'
            }
            catch {
                $applyErrors.Add($_.Exception.Message)
                Write-Warn ('task registration failed (' + $_.Exception.Message + ') - run scripts\17-autorepair-task.ps1 -Install elevated')
            }
        }
    }
    else {
        try {
            Invoke-GuardChild -ScriptPath (Get-PolicyScriptPath '07-mode.ps1') -ChildArgs @('-RemoveTasks', '-Root', $Root, '-Quiet') -Label '07-mode.ps1 -RemoveTasks'
            Write-Ok 'ZeroResidentMonitor = OFF (background tasks unregistered)'
        }
        catch {
            $applyErrors.Add($_.Exception.Message)
            Write-Warn ('failed to unregister background tasks: ' + $_.Exception.Message)
        }
    }

    # ------------------------------------------------------------------ Enforce Official TUN Recommended System Proxy Mode (ProxyEnable = 0)
    Write-Step 'enforcing official recommended system proxy mode (ProxyEnable = 0, pure TUN mode)'
    try {
        $hkcuKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        if (Test-Path -LiteralPath $hkcuKey) {
            $cur = Get-ItemProperty -LiteralPath $hkcuKey -ErrorAction SilentlyContinue
            if ($cur -and $cur.ProxyEnable -ne 0) {
                Set-ItemProperty -LiteralPath $hkcuKey -Name 'ProxyEnable' -Value 0 -Type DWord
            }
        }
        foreach ($hive in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
            if ($hive.PSChildName -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { continue }
            $ik = 'Registry::HKEY_USERS\' + $hive.PSChildName + '\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
            $ie = Get-ItemProperty -LiteralPath $ik -ErrorAction SilentlyContinue
            if ($ie -and $ie.ProxyEnable -ne 0) {
                Set-ItemProperty -LiteralPath $ik -Name 'ProxyEnable' -Value 0 -Type DWord -ErrorAction SilentlyContinue
            }
        }
        $winInetDef = @'
using System;
using System.Runtime.InteropServices;
public static class AiGuardWinInet {
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
    public static void NotifyProxyChanged() {
        InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
    }
}
'@
        if (-not ('AiGuardWinInet' -as [type])) {
            Add-Type -TypeDefinition $winInetDef -ErrorAction SilentlyContinue | Out-Null
        }
        if ('AiGuardWinInet' -as [type]) {
            [AiGuardWinInet]::NotifyProxyChanged()
        }
        if ($V2rayNRoot -and (Test-Path -LiteralPath (Join-Path $V2rayNRoot 'guiConfigs\guiNConfig.json'))) {
            try {
                $guiCfgFile = Join-Path $V2rayNRoot 'guiConfigs\guiNConfig.json'
                $guiCfg = Get-Content -LiteralPath $guiCfgFile -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($guiCfg.SystemProxyItem -and $guiCfg.SystemProxyItem.SysProxyType -ne 0) {
                    $guiCfg.SystemProxyItem.SysProxyType = 0
                    $guiCfg | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $guiCfgFile -Encoding UTF8
                }
            } catch { }
        }
        Write-Ok 'system proxy verified: ProxyEnable = 0 (official TUN recommended mode: pure virtual NIC routing, 0 WinINET conflict)'
    }
    catch {
        Write-Warn ('system proxy verification notice: ' + $_.Exception.Message)
    }

    try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch { }
    ipconfig.exe /flushdns | Out-Null

    if ($pendingRollbackCancel) {
        if ($applyErrors.Count -eq 0) {
            $rbTask = Get-ScheduledTask -TaskName 'AI-Guard-Test-Rollback' -ErrorAction SilentlyContinue
            if ($rbTask) {
                try {
                    Unregister-ScheduledTask -TaskName 'AI-Guard-Test-Rollback' -Confirm:$false -ErrorAction Stop
                    $rbAfter = Get-ScheduledTask -TaskName 'AI-Guard-Test-Rollback' -ErrorAction SilentlyContinue
                    if ($rbAfter) {
                        throw 'AI-Guard-Test-Rollback still registered after Unregister-ScheduledTask'
                    }
                    Write-Ok 'auto-rollback safety timer cancelled (deployment verified & committed)'
                }
                catch {
                    $applyErrors.Add('failed to unregister AI-Guard-Test-Rollback: ' + $_.Exception.Message)
                    Write-Warn ('failed to unregister AI-Guard-Test-Rollback (auto-rollback may still fire!): ' + $_.Exception.Message)
                }
            }
        }
        else {
            Write-Warn 'Keeping 30-minute AI-Guard-Test-Rollback safety timer armed because finalization had errors!'
        }
    }

    if ($pendingAclUnlock) {
        $remainingSysTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like 'AI-Guard*' })
        if ($remainingSysTasks.Count -gt 0) {
            $remNames = ($remainingSysTasks | ForEach-Object { $_.TaskName }) -join ', '
            $applyErrors.Add('refused to unlock install ACL while SYSTEM tasks remain registered: ' + $remNames)
            Write-Warn ('Refused HardenInstallAcl=OFF while SYSTEM tasks still exist: ' + $remNames)
        }
        elseif ($applyErrors.Count -gt 0) {
            Write-Warn 'Skipping HardenInstallAcl=OFF because policy application encountered errors'
        }
        else {
            try {
                Invoke-GuardChild -ScriptPath $aclScript -ChildArgs @('-Root', $Root, '-Undo') -Label '13-harden-acl.ps1 -Undo' | Out-Null
                Write-Ok ('HardenInstallAcl = OFF (all SYSTEM tasks removed; restored inherited permissions on ' + $Root + ')')
            }
            catch {
                $applyErrors.Add($_.Exception.Message)
                Write-Warn ('ACL unlock failed: ' + $_.Exception.Message)
            }
        }
    }

    & $psExe -NoProfile -ExecutionPolicy Bypass -File (Get-PolicyScriptPath '07-mode.ps1') -Status -Root $Root -V2rayNRoot $V2rayNRoot -DnsServer $targetDns
    Write-Host ''
    if ($applyErrors.Count -gt 0) {
        $applyExitCode = 5
        Write-Host ('[FAILED] AI-Net-Guard v5.9.6 policy application finished with ' + $applyErrors.Count + ' error(s):') -ForegroundColor Red
        foreach ($ae in $applyErrors) { Write-Host ('  - ' + $ae) -ForegroundColor Red }
    }
    else {
        # Commit policy (persist last-good and mark PolicyCommitted=$true) ONLY after zero errors
        try {
            & $txCommitPolicy
            Write-Host '[SUCCESS] AI-Net-Guard v5.9.6 configuration applied successfully.' -ForegroundColor Green
        }
        catch {
            $applyExitCode = 5
            Write-Host ('[FAILED] AI-Net-Guard v5.9.6 failed while committing last-good policy: ' + $_.Exception.Message) -ForegroundColor Red
        }
    }
}
}
$txState.ExitCode = $applyExitCode
}
if ($txResult -and $txResult.ErrorMessage) {
    Write-Host ('[FAILED] Unhandled exception during AI-Net-Guard policy application: ' + $txResult.ErrorMessage) -ForegroundColor Red
}
if ($txResult) {
    $applyExitCode = $txResult.ExitCode
    if ($txResult.CanonicalStaged -and (-not $txResult.PolicyCommitted) -and ($applyExitCode -eq 0 -or $applyExitCode -eq -1)) {
        $applyExitCode = 5
    }
}
else {
    $applyExitCode = 5
}
}
finally {
    Exit-GuardWriteLock $applyWriteLock
}
if ($applyExitCode -eq -1) { $applyExitCode = 0 }
exit $applyExitCode
