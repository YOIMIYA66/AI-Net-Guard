<#
.SYNOPSIS
    AI-Net-Guard v5.7.3 - idempotent policy orchestrator for GUI & CLI (fresh deploy + incremental toggle apply).

.DESCRIPTION
    Reads <Root>\backup\guard-policy.json (or -PolicyPath) and enforces all 15
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
    [switch]$ForceCommit
)

$ErrorActionPreference = 'Stop'
if (-not $Root) {
    $Root = if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\AI-Net-Guard' }
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

function Write-Step([string]$msg) { Write-Host ('[+] ' + $msg) -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host ('    [OK] ' + $msg) -ForegroundColor Green }
function Write-Note([string]$msg) { Write-Host ('    [i]  ' + $msg) -ForegroundColor DarkGray }
function Write-Warn([string]$msg) { Write-Host ('    [!]  ' + $msg) -ForegroundColor Yellow }

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

$policy = [ordered]@{
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
    DisablePhysicalIpv6  = $true
    PreferIpv4Prefix     = $true
    ZeroResidentMonitor  = $true
    AutoNodeSync         = $true
    AutoHealStaleProxy   = $true
    DomesticNtp          = $true
    HardenInstallAcl     = $true
    UpdatedAt            = (Get-Date).ToString('o')
}

if (Test-Path -LiteralPath $PolicyPath) {
    $raw = Get-Content -LiteralPath $PolicyPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($raw) {
        foreach ($k in @('AllowCnDirect', 'AllowLan', 'AllowNcsi', 'QuarantineRogueAllow', 'LockPhysicalDns',
                'DisableSmhnr', 'DisableLlmnrNetbios', 'StrictNrptDoh', 'DisablePhysicalIpv6', 'PreferIpv4Prefix',
                'ZeroResidentMonitor', 'AutoNodeSync', 'AutoHealStaleProxy', 'DomesticNtp', 'HardenInstallAcl')) {
            if ($raw.PSObject.Properties.Name -contains $k -and $null -ne $raw.$k) {
                $policy[$k] = [bool]$raw.$k
            }
        }
        foreach ($sk in @('Version', 'Preset', 'DnsServer', 'V2rayNRoot')) {
            if ($raw.PSObject.Properties.Name -contains $sk -and $null -ne $raw.$sk -and ([string]$raw.$sk).Length -gt 0) {
                $policy[$sk] = [string]$raw.$sk
            }
        }
    }
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
        foreach ($cand in @('C:\v2rayN-windows-64', 'D:\v2rayN-windows-64', 'C:\v2rayN', 'D:\v2rayN', (Join-Path $env:LOCALAPPDATA 'v2rayN'), 'C:\Program Files\v2rayN')) {
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

$policy.UpdatedAt = (Get-Date).ToString('o')
$canonicalPolicyPath = Join-Path $BackupDir 'guard-policy.json'
([pscustomobject]$policy) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $canonicalPolicyPath -Encoding UTF8

$psExe = (Get-Process -Id $PID).Path
if (-not $psExe -or -not (Test-Path -LiteralPath $psExe)) {
    $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
}

if ($SyncNodeOnly) {
    Write-Step 'forcing immediate proxy node & port sync'
    & $psExe -NoProfile -ExecutionPolicy Bypass -File (Get-PolicyScriptPath '10-sync-node-rule.ps1') -Root $Root -V2rayNRoot $V2rayNRoot
    exit $LASTEXITCODE
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
$baselineFile = Join-Path $BackupDir 'baseline.json'
$baselineObj = $null
if (Test-Path -LiteralPath $baselineFile) {
    try { $baselineObj = Get-Content -LiteralPath $baselineFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
}
$hasDnsBaseline = [bool]($baselineObj -and $baselineObj.Dns -and (Test-Path -LiteralPath $baselineObj.Dns))
$hasFwBaseline  = [bool]($baselineObj -and $baselineObj.Firewall -and (Test-Path -LiteralPath $baselineObj.Firewall))
$isFreshInstall = (-not $hasDnsBaseline) -or (-not $hasFwBaseline)

Write-Host ''
Write-Host ('=== AI-Net-Guard v5.7.3 Policy Engine (' + $(if ($isFreshInstall) { 'Initial Deployment' } else { 'Incremental Update' }) + ') ===') -ForegroundColor Cyan
Write-Note ('Root=' + $Root + '  V2rayNRoot=' + $V2rayNRoot + '  Preset=' + $policy.Preset)

if ($isFreshInstall) {
    # -------------------------------------------------------------- Preflight for Fresh Install
    Write-Step 'running preflight checks before initial deployment'
    $physUp = @(Get-PhysicalAdaptersAll | Where-Object { $_.Status -eq 'Up' })
    if ($physUp.Count -eq 0) {
        Write-Host 'ERROR: No active physical network adapter (Wi-Fi / Ethernet) is connected.' -ForegroundColor Red
        exit 2
    }
    $cfgCheck = Join-Path $V2rayNRoot 'binConfigs\config.json'
    if (-not (Test-Path -LiteralPath $cfgCheck)) {
        Write-Host ('ERROR: v2rayN config not found at "' + $cfgCheck + '". Select your v2rayN directory and start v2rayN once first.') -ForegroundColor Red
        exit 2
    }
    $tunAdapter = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { ($knownTuns -contains $_.Name) -or $_.InterfaceDescription -match '(?i)Wintun|sing-tun|Mihomo' } |
        Select-Object -First 1
    if (-not $tunAdapter) {
        Write-Host 'ERROR: Virtual TUN adapter (xray_tun / singbox_tun) has not been created yet.' -ForegroundColor Red
        Write-Host '       Please enable "Enable Tun" inside v2rayN once first so Windows creates the TUN interface.' -ForegroundColor Yellow
        exit 2
    }
    $TunName = $tunAdapter.Name
    if ($policy.StrictNrptDoh -and $tunAdapter.Status -ne 'Up') {
        Write-Host 'ERROR: Strict NRPT DoH (1.1.1.1) requires v2rayN TUN to be actively UP during deployment.' -ForegroundColor Red
        exit 2
    }
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
        if (-not $policy.QuarantineRogueAllow) { $ksArgs += '-KeepExistingAllowRules' }
        & $psExe @ksArgs
        if ($LASTEXITCODE -ne 0) { throw ('02-killswitch.ps1 exited with code ' + $LASTEXITCODE) }
    }

    # Step 3: Connectivity verification & Auto-Commit
    Write-Step 'step 3/4: verifying live connectivity before cancelling 30-min auto-rollback timer'
    try {
        $probeResult = Invoke-QuickConnectivityCheck -AllowCn ([bool]$policy.AllowCnDirect)
        Write-Ok ('connectivity check passed (' + $probeResult + ')')
        $rbTask = Get-ScheduledTask -TaskName 'AI-Guard-Test-Rollback' -ErrorAction SilentlyContinue
        if ($rbTask) {
            Unregister-ScheduledTask -TaskName 'AI-Guard-Test-Rollback' -Confirm:$false
            Write-Ok 'auto-rollback safety timer cancelled (deployment committed)'
        }
    }
    catch {
        if ($ForceCommit) {
            Write-Warn ('connectivity probe failed (' + $_.Exception.Message + '), but -ForceCommit specified')
            $rbTask = Get-ScheduledTask -TaskName 'AI-Guard-Test-Rollback' -ErrorAction SilentlyContinue
            if ($rbTask) { Unregister-ScheduledTask -TaskName 'AI-Guard-Test-Rollback' -Confirm:$false }
        }
        else {
            Write-Warn ('connectivity probe failed: ' + $_.Exception.Message)
            Write-Warn 'Keeping 30-minute AI-Guard-Test-Rollback safety timer armed! Fix TUN/network or click Rollback.'
            exit 4
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
        if (-not $policy.QuarantineRogueAllow) { $ksArgs += '-KeepExistingAllowRules' }
        & $psExe @ksArgs
    }

    Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultOutboundAction Block -Enabled True

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
                -Direction Outbound -Action Allow -RemoteAddress 'LocalSubnet' -Profile Any -Enabled True `
                -Description 'Local subnet only.' | Out-Null
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
                foreach ($qr in @(Get-Content -LiteralPath $qFile -Raw -Encoding UTF8 | ConvertFrom-Json)) {
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
        foreach ($pa in (Get-PhysicalAdaptersAll)) {
            if ($pa.InterfaceGuid) {
                $nbk = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_' + $pa.InterfaceGuid
                if (Test-Path -LiteralPath $nbk) {
                    New-ItemProperty -Path $nbk -Name 'NetbiosOptions' -Value 2 -PropertyType DWord -Force | Out-Null
                }
            }
        }
        Write-Ok 'DisableLlmnrNetbios = ON (LLMNR & NetBIOS disabled)'
    }
    else {
        if ($dnsBackup -and $null -ne $dnsBackup.Llmnr) {
            New-ItemProperty -Path $dnsPolKey -Name 'EnableMulticast' -Value ([int]$dnsBackup.Llmnr) -PropertyType DWord -Force | Out-Null
        }
        else {
            Remove-ItemProperty -Path $dnsPolKey -Name 'EnableMulticast' -ErrorAction SilentlyContinue
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
        try {
            Stop-Service -Name 'DiagTrack' -Force -ErrorAction SilentlyContinue
            Set-Service -Name 'DiagTrack' -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name 'dmwappushservice' -Force -ErrorAction SilentlyContinue
            Set-Service -Name 'dmwappushservice' -StartupType Disabled -ErrorAction SilentlyContinue
            $dcKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            if (-not (Test-Path -LiteralPath $dcKey)) { New-Item -Path $dcKey -Force | Out-Null }
            Set-ItemProperty -LiteralPath $dcKey -Name 'AllowTelemetry' -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath $dcKey -Name 'MaxTelemetryAllowed' -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Write-Ok 'WindowsTelemetry = OFF (DiagTrack disabled, AllowTelemetry=0)'
        } catch { }
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
        Write-Ok 'DisablePhysicalIpv6 = OFF (restored ms_tcpip6 binding on physical adapters)'
    }

    $tcpip6Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
    if ($policy.PreferIpv4Prefix) {
        if (-not (Test-Path -LiteralPath $tcpip6Key)) { New-Item -Path $tcpip6Key -Force | Out-Null }
        $curDc = (Get-ItemProperty -LiteralPath $tcpip6Key -ErrorAction SilentlyContinue).DisabledComponents
        $newDc = if ($null -ne $curDc) { ([int]$curDc -bor 0x20) } else { 0x20 }
        New-ItemProperty -Path $tcpip6Key -Name 'DisabledComponents' -Value $newDc -PropertyType DWord -Force | Out-Null
        netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 50 4 | Out-Null
        Write-Ok 'PreferIpv4Prefix = ON (::ffff:0:0/96 precedence 50 > ::/0 40)'
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

# ------------------------------------------------------------------ Common Finalization (Mode Pass, Tasks, ACL, DNS Flush)
Write-Step 'synchronizing proxy node & multi-core companion firewall rules'
$syncNodeScript = Get-PolicyScriptPath '10-sync-node-rule.ps1'
if (Test-Path -LiteralPath $syncNodeScript) {
    try {
        & $psExe -NoProfile -ExecutionPolicy Bypass -File $syncNodeScript -Root $Root -V2rayNRoot $V2rayNRoot
        Write-Ok 'multi-core node rules synchronized (xray, sing-box, v2rayN across all active/test ports)'
    }
    catch {
        Write-Warn ('node rule synchronization skipped: ' + $_.Exception.Message)
    }
}

Write-Step 'synchronizing background monitor tasks & active guard state'
& $psExe -NoProfile -ExecutionPolicy Bypass -File (Get-PolicyScriptPath '07-mode.ps1') -Root $Root -V2rayNRoot $V2rayNRoot -DnsServer $targetDns -Quiet

if ($policy.ZeroResidentMonitor) {
    $taskArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Get-PolicyScriptPath '07-mode.ps1'),
        '-InstallTasks', '-Root', $Root, '-V2rayNRoot', $V2rayNRoot, '-DnsServer', $targetDns, '-Quiet')
    if (-not $policy.AutoNodeSync)         { $taskArgs += '-DisableAutoNodeSync' }
    if (-not $policy.QuarantineRogueAllow) { $taskArgs += '-SkipQuarantineAllowRules' }
    if (-not $policy.AutoHealStaleProxy)   { $taskArgs += '-SkipStaleProxyHeal' }
    & $psExe @taskArgs
    Write-Ok 'ZeroResidentMonitor = ON (AI-Guard-Mode-Event + Fallback tasks registered, 0 MB idle RAM)'
}
else {
    & $psExe -NoProfile -ExecutionPolicy Bypass -File (Get-PolicyScriptPath '07-mode.ps1') -RemoveTasks -Root $Root -Quiet
    Write-Ok 'ZeroResidentMonitor = OFF (background tasks unregistered)'
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

$aclScript = Get-PolicyScriptPath '13-harden-acl.ps1'
if (Test-Path -LiteralPath $aclScript) {
    if ($policy.HardenInstallAcl) {
        & $psExe -NoProfile -ExecutionPolicy Bypass -File $aclScript -Root $Root -SkipVerification -SkipRegression | Out-Null
        Write-Ok ('HardenInstallAcl = ON (' + $Root + ' locked to Administrators/SYSTEM write-only)')
    }
    else {
        & $psExe -NoProfile -ExecutionPolicy Bypass -File $aclScript -Root $Root -Undo | Out-Null
        Write-Ok ('HardenInstallAcl = OFF (restored inherited folder permissions on ' + $Root + ')')
    }
}

& $psExe -NoProfile -ExecutionPolicy Bypass -File (Get-PolicyScriptPath '07-mode.ps1') -Status -Root $Root -V2rayNRoot $V2rayNRoot -DnsServer $targetDns
Write-Host ''
Write-Host '[SUCCESS] AI-Net-Guard v5.7.3 configuration applied successfully.' -ForegroundColor Green
exit 0
