<#
.SYNOPSIS
    AI-Net-Guard v5.9.4 - zero-resident static guard, persistent GUI/CLI policy engine, multi-core auto node sync, drift quarantine, SMHNR hardening, and event-task manager.

.DESCRIPTION
    The guard itself is 100% STATIC in Windows kernel WFP (BFE / tcpip.sys):
    opening/closing the proxy changes nothing on the Windows firewall or NICs,
    so switch latency is 0 ms and protection holds even with ZERO background
    PowerShell processes running.

        default outbound = Block (always)
        AI-Guard-Allow-CN     : mainland-China IPv4 prefixes, always enabled
        AI-Guard-Allow-TUN    : interface xray_tun (+ dynamic -TUN-Alt for singbox_tun/mihomo)
        Node / AliDNS DoH / DHCP / LAN / NCSI : always
        physical DNS          : 223.5.5.5 (AliDNS, LLMNR=off, SMHNR=off)

    v5.4 Zero-Resident, Zero-Drift & Multi-Core architecture:
      * 0 resident powershell.exe processes by default: AI-Guard-Mode-Event wakes
        on Windows NetworkProfile Event ID 10000/10001, Boot, AND Sleep / Modern
        Standby Resume (Power-Troubleshooter 1 / Kernel-Power 107, 507);
        AI-Guard-Mode-Fallback runs a ~90 ms zero-CIM fast check every 60 minutes.
      * Hands-free multi-core automatic node sync (default ON): <0.3 ms timestamp
        check on v2rayN binConfigs\config.json; supports BOTH Xray and sing-box
        (including Hysteria2 port-hopping ranges), auto-binds the active core
        executable (xray.exe / sing-box.exe / mihomo.exe) and dynamic TUN adapter,
        and resolves domain nodes over encrypted https://223.5.5.5/resolve first.
      * Race-free +800 ms late settle: unconditionally re-verifies node sync and
        dead loopback proxy cleanup after Wintun / v2rayN shutdown settles.
      * Windows Smart Multi-Homed Name Resolution (SMHNR) disabled
        (DisableSmartNameResolution=1), stopping parallel DNS spray onto physical
        NICs when TUN is active (auto-migrated via backup\v54-migrated.flag).
      * Zero-cost rogue Outbound Allow drift quarantine (+0 ms inside existing
        registry pass) + cross-session dead loopback proxy auto-heal.
#>

[CmdletBinding()]
param(
    [ValidateSet('Auto', 'Strict', 'Daily', 'Protected')]
    [string]$Mode = 'Auto',
    [switch]$Status,
    [switch]$Upgrade,
    [switch]$InstallTasks,
    [switch]$RemoveTasks,
    [switch]$OnNetworkEvent,
    [switch]$UseResidentWatchdog,
    [switch]$DisableAutoNodeSync,
    [switch]$SkipQuarantineAllowRules,
    [switch]$SkipStaleProxyHeal,
    [switch]$ClearProtectedLock,
    [int]$FallbackMinutes = 60,
    [switch]$Quiet,
    [string]$Root = $(if ($PSScriptRoot) { if ((Split-Path -Leaf $PSScriptRoot) -ieq 'scripts') { Split-Path -Parent $PSScriptRoot } else { $PSScriptRoot } } else { 'C:\AI-Net-Guard' }),
    [string]$V2rayNRoot = '',
    [string]$TunName = 'xray_tun',
    [string]$DnsServer = '223.5.5.5'
)

$ErrorActionPreference = 'Continue'
$script:CliBoundParams = @{}
foreach ($bpKey in $PSBoundParameters.Keys) { $script:CliBoundParams[$bpKey] = $PSBoundParameters[$bpKey] }
$script:CliDefaultDnsServer = $DnsServer
$script:CliDefaultV2rayNRoot = $V2rayNRoot
$policyFile = Join-Path $Root 'backup\guard-policy.json'
$protectedLockFile = Join-Path $Root 'backup\protected-lock.flag'

$libCommon = ''
$commonCandidates = @((Join-Path $Root 'scripts\lib-guard-common.ps1'), (Join-Path $Root 'lib-guard-common.ps1'))
if ($PSScriptRoot) { $commonCandidates = @((Join-Path $PSScriptRoot 'lib-guard-common.ps1')) + $commonCandidates }
foreach ($cand in $commonCandidates) {
    if ($cand -and (Test-Path -LiteralPath $cand)) { $libCommon = $cand; break }
}
if (-not $libCommon) {
    Write-Host '[!] lib-guard-common.ps1 missing - cannot enforce policy/ACL/write-lock invariants' -ForegroundColor Red
    exit 1
}
. $libCommon

function Get-GuardPolicy {
    $pol = [ordered]@{
        Version              = '5.5'
        Preset               = 'Recommended'
        DnsServer            = $DnsServer
        V2rayNRoot           = ''
        AllowCnDirect        = $true
        AllowLan             = $true
        AllowNcsi            = $true
        QuarantineRogueAllow = (-not [bool]$SkipQuarantineAllowRules)
        LockPhysicalDns      = $true
        DisableSmhnr         = $true
        DisableLlmnrNetbios  = $true
        StrictNrptDoh        = $false
        DisablePhysicalIpv6  = $true
        PreferIpv4Prefix     = $true
        ZeroResidentMonitor  = $true
        AutoNodeSync         = (-not [bool]$DisableAutoNodeSync)
        AutoHealStaleProxy   = (-not [bool]$SkipStaleProxyHeal)
        DomesticNtp          = $true
        HardenInstallAcl     = $true
        BlockWebRtcLeak      = $true
    }
    $lastGoodFile = Join-Path $Root 'backup\guard-policy.last-good.json'
    $isDeployedHost = (Test-Path -LiteralPath (Join-Path $Root 'backup\baseline.json'))
    return (Read-GuardPolicyStrict -PolicyPath $policyFile -Defaults $pol -LastGoodPath $lastGoodFile -IsDeployed:$isDeployedHost)
}

function Resolve-EffectiveV2rayNRoot {
    if ($env:V2RAYN_ROOT -and (Test-Path -LiteralPath $env:V2RAYN_ROOT)) { return $env:V2RAYN_ROOT }
    foreach ($cand in @('D:\v2rayN-windows-64-desktop\v2rayN-windows-64', 'D:\v2rayN-windows-64-desktop', 'C:\v2rayN-windows-64-desktop\v2rayN-windows-64', 'C:\v2rayN-windows-64', 'D:\v2rayN-windows-64', 'C:\v2rayN', 'D:\v2rayN', (Join-Path $env:LOCALAPPDATA 'v2rayN'), 'C:\Program Files\v2rayN')) {
        if ($cand -and ((Test-Path -LiteralPath (Join-Path $cand 'v2rayN.exe')) -or (Test-Path -LiteralPath (Join-Path $cand 'binConfigs')))) { return $cand }
    }
    try {
        $vp = [System.Diagnostics.Process]::GetProcessesByName('v2rayN')
        if ($vp.Length -gt 0 -and $vp[0].MainModule.FileName) { return (Split-Path -Parent $vp[0].MainModule.FileName) }
    }
    catch { }
    return 'C:\v2rayN-windows-64'
}

function Apply-GuardPolicyToScriptVars {
    if (-not $script:CliBoundParams.ContainsKey('V2rayNRoot')) {
        if ($script:guardPolicy.V2rayNRoot -and (Test-Path -LiteralPath $script:guardPolicy.V2rayNRoot)) {
            $script:V2rayNRoot = $script:guardPolicy.V2rayNRoot
        }
        elseif ($script:CliDefaultV2rayNRoot -and (Test-Path -LiteralPath $script:CliDefaultV2rayNRoot)) {
            $script:V2rayNRoot = $script:CliDefaultV2rayNRoot
        }
        else {
            $script:V2rayNRoot = Resolve-EffectiveV2rayNRoot
        }
    }
    if (-not $script:CliBoundParams.ContainsKey('DnsServer')) {
        if ($script:guardPolicy.StrictNrptDoh) { $script:DnsServer = '1.1.1.1' }
        elseif ($script:guardPolicy.DnsServer) { $script:DnsServer = $script:guardPolicy.DnsServer }
        else { $script:DnsServer = $script:CliDefaultDnsServer }
    }
    if (-not $script:CliBoundParams.ContainsKey('DisableAutoNodeSync')) {
        $script:DisableAutoNodeSync = if (-not [bool]$script:guardPolicy.AutoNodeSync) { [switch]::Present } else { [switch]$false }
    }
    if (-not $script:CliBoundParams.ContainsKey('SkipQuarantineAllowRules')) {
        $script:SkipQuarantineAllowRules = if (-not [bool]$script:guardPolicy.QuarantineRogueAllow) { [switch]::Present } else { [switch]$false }
    }
    if (-not $script:CliBoundParams.ContainsKey('SkipStaleProxyHeal')) {
        $script:SkipStaleProxyHeal = if (-not [bool]$script:guardPolicy.AutoHealStaleProxy) { [switch]::Present } else { [switch]$false }
    }
}

$script:guardPolicy = Get-GuardPolicy
Apply-GuardPolicyToScriptVars

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($Status) {
        $script:ReadOnlyStatusMode = $true
    }
    else {
        Write-Host 'ERROR: run this script in an elevated PowerShell (Run as Administrator).' -ForegroundColor Red
        Write-Host '       Win+X -> Terminal (Admin), then:' -ForegroundColor Yellow
        Write-Host ('       cd "' + $Root + '" ; .\07-mode.ps1 -Status') -ForegroundColor Yellow
        exit 1
    }
}

function Say($msg) { if (-not $Quiet) { Write-Host $msg } }

$cnList = Join-Path $Root 'cn-ipv4.txt'
$cnSig = Join-Path $Root 'backup\cn-rule.sig'
$cnMeta = Join-Path $Root 'backup\cn-file.meta'
$nodeMeta = Join-Path $Root 'backup\node-sync.meta'
$nodeRoutesMeta = Join-Path $Root 'backup\node-routes.meta'
$v54Flag = Join-Path $Root 'backup\v54-migrated.flag'
$quarantineFile = Join-Path $Root 'backup\auto-disabled-outbound-allow.json'
$allowExceptionsFile = Join-Path $Root 'backup\allowed-outbound-rules.json'
$stateFile = Join-Path $Root 'backup\mode-state.json'
$b1Meta = Join-Path $Root 'backup\b1-guard.meta'
$hotplugFile = Join-Path $Root 'backup\hotplug-ipv6.json'
$logDir = Join-Path $Root 'logs'
$eventLog = Join-Path $logDir 'watchdog.log'
$cnRuleName = 'AI-Guard-Allow-CN'
$requiredRules = @('AI-Guard-Allow-TUN', 'AI-Guard-Allow-Node-TCP', 'AI-Guard-Allow-DoH-Ali', 'AI-Guard-Allow-DHCP')
if ($guardPolicy.AllowLan) { $requiredRules += 'AI-Guard-Allow-LAN' }
$knownTunNames = @($TunName, 'xray_tun', 'singbox_tun', 'mihomo_tun', 'Meta', 'Mihomo') | Select-Object -Unique

# The STUN/TURN port set and the B1 routing-table checks are defined once, in
# lib-stun-guard.ps1, and shared with 02/14/15/18/verify-leak-test. This script both
# creates the firewall STUN block (section 9) and watches the routing-level guard
# (section 9b), so both halves must agree on the port list - that agreement used to rely
# on seven hand-synced literals.
#
# A missing lib is a hard stop, not a fallback to a local literal: a drift check that runs
# against an empty port set reports 'clean' for a rule that blocks nothing, which is the
# silent failure the check exists to prevent.
$libStun = ''
$libCandidates = @((Join-Path $Root 'scripts\lib-stun-guard.ps1'), (Join-Path $Root 'lib-stun-guard.ps1'))
# $PSScriptRoot is empty when this file is dot-sourced from an interactive host, and
# Join-Path throws on an empty -Path. Guard it instead of trusting the caller.
if ($PSScriptRoot) { $libCandidates = @((Join-Path $PSScriptRoot 'lib-stun-guard.ps1')) + $libCandidates }
foreach ($cand in $libCandidates) {
    if ($cand -and (Test-Path -LiteralPath $cand)) { $libStun = $cand; break }
}
if (-not $libStun) {
    Write-Host '[!] lib-stun-guard.ps1 missing - cannot determine the STUN/TURN port set' -ForegroundColor Red
    Write-Host '    expected next to this script or under scripts\ - the install is incomplete.' -ForegroundColor Red
    exit 1
}
. $libStun
$stunPorts = @(Get-StunGuardPortStrings)
$webrtcPorts = @($stunPorts)

# ---------------------------------------------------------------- helpers (zero-CIM fast primitives)
function Write-MonitorLog([string]$msg) {
    try {
        if (-not (Test-Path -LiteralPath $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        if ((Test-Path -LiteralPath $eventLog) -and ((Get-Item -LiteralPath $eventLog).Length -gt 2MB)) {
            Move-Item -LiteralPath $eventLog -Destination ($eventLog + '.1') -Force -ErrorAction SilentlyContinue
        }
        Add-Content -LiteralPath $eventLog -Value ((Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '  ' + $msg) -Encoding UTF8
    }
    catch { }
}

function Test-IsTunInterface([System.Net.NetworkInformation.NetworkInterface]$ni) {
    if (-not $ni) { return $false }
    # Exclude .NET Core / PowerShell 7+ NDIS lightweight filter layers (*-Npcap*, *-Filter-0000, *-QoS*)
    $hasIp = $ni.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv4) -or
             $ni.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv6)
    if (-not $hasIp) { return $false }
    if ($knownTunNames -contains $ni.Name) { return $true }
    if ($ni.Description -match '(?i)Wintun|sing-tun|Mihomo') { return $true }
    return $false
}

function Get-ActiveTunNamesFast {
    $names = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($ni in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($ni.OperationalStatus -ne 'Up') { continue }
            if (Test-IsTunInterface $ni) { $names.Add($ni.Name) }
        }
    }
    catch { }
    return $names.ToArray()
}

function Test-TunUp {
    return ((@(Get-ActiveTunNamesFast)).Count -gt 0)
}

# ------------------------------------------------------------ NetSecurity cache
# Measured on this host: Get-NetFirewallRule costs ~1.23 s whether or not -Name
# narrows it (the module issues a full CIM round-trip and filters client side), and
# each Get-NetFirewall*Filter call costs another ~0.3 s. A single self-check used to
# issue 8-14 of them, which is where most of the 20 s wall clock went.
#
# The index below enumerates the rule table once and serves every later lookup from
# memory. Any write invalidates it: a cached object goes stale the moment
# Set-/New-/Remove-/Disable-/Enable-NetFirewallRule touches the store, and repairing
# from a stale object is how a guard silently re-applies the drift it just fixed.
$script:RuleIndex = $null
$script:RuleFilterCache = @{}

function Reset-RuleCache {
    $script:RuleIndex = $null
    $script:RuleFilterCache = @{}
}

function Get-RuleIndex {
    if ($null -ne $script:RuleIndex) { return $script:RuleIndex }
    $idx = @{}
    try {
        foreach ($r in @(Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
            if (-not $r) { continue }
            $n = [string]$r.Name
            if ($n -and -not $idx.ContainsKey($n)) { $idx[$n] = $r }
            $d = [string]$r.DisplayName
            if ($d -and -not $idx.ContainsKey($d)) { $idx[$d] = $r }
        }
    }
    catch { }
    $script:RuleIndex = $idx
    return $idx
}

function Get-GuardRule([string]$Key) {
    if (-not $Key) { return $null }
    $idx = Get-RuleIndex
    if ($idx.ContainsKey($Key)) { return $idx[$Key] }
    return $null
}

function Get-GuardRuleFilter([string]$Key, [string]$Kind) {
    $ck = $Kind + '|' + $Key
    if ($script:RuleFilterCache.ContainsKey($ck)) { return $script:RuleFilterCache[$ck] }
    $val = $null
    $r = Get-GuardRule $Key
    if ($r) {
        try {
            switch ($Kind) {
                'Interface' { $val = @(($r | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue).InterfaceAlias) }
                'Address' { $val = @(($r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue).LocalAddress) }
                'Application' { $val = ($r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program }
                'Port' { $val = @(($r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue).RemotePort) }
            }
        }
        catch { $val = $null }
    }
    $script:RuleFilterCache[$ck] = $val
    return $val
}

function Test-FirewallRuleHasTun($ruleObject, [string]$tunName) {
    if (-not $ruleObject -or -not $tunName) { return $false }
    try {
        $key = [string]$ruleObject.Name
        if (-not $key) { return $false }
        $all = @(Get-GuardRuleFilter $key 'Interface')
        if ($all.Count -eq 0) { return $false }
        $aliases = @($all | Where-Object { $_ -and $_ -ne '0' -and $_ -ne 'Any' })
        if ($aliases -contains $tunName) { return $true }

        $ad = Get-NetAdapter -Name $tunName -ErrorAction SilentlyContinue
        if ($ad -and $ad.InterfaceGuid) {
            $guidClean = $ad.InterfaceGuid.Trim('{', '}').ToLowerInvariant()
            foreach ($a in $aliases) {
                if ($a.Trim('{', '}').ToLowerInvariant() -eq $guidClean) { return $true }
            }
        }
    }
    catch { }
    return $false
}

function Get-ActivePhysicalNicsFast {
    $list = New-Object System.Collections.Generic.List[System.Net.NetworkInformation.NetworkInterface]
    try {
        foreach ($ni in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($ni.OperationalStatus -ne 'Up') { continue }
            if ((Test-IsTunInterface $ni) -or $ni.Description -match 'Loopback|WAN Miniport' -or $ni.NetworkInterfaceType -eq 'Loopback') { continue }
            # In .NET Core / PowerShell 7+, GetAllNetworkInterfaces() also enumerates NDIS
            # lightweight filter layers (*-Filter-0000, *-Npcap*, *-QoS Packet Scheduler*)
            # and WAN Miniports that have neither IPv4 nor IPv6 protocol bindings.
            $hasV4 = $ni.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv4)
            $hasV6 = $ni.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv6)
            if (-not $hasV4 -and -not $hasV6) { continue }
            $list.Add($ni)
        }
    }
    catch { }
    return $list.ToArray()
}

# ------------------------------------------------------------ IPv4 subnet helpers
# The WebRTC LocalAddress rules used to store the exact DHCP lease (e.g. 192.168.1.165).
# A lease change then leaves the rule pointing at an address this host no longer owns, so it
# silently stops blocking while still looking "enabled" in every status view.  Comparing the
# rule against the *subnet* of each physical NIC survives an in-LAN renumber, and /32 is kept
# whenever the subnet would also cover a TUN address (that would black-hole proxied WebRTC).
function Get-IPv4MaskBytes([int]$PrefixLen) {
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

function Get-IPv4PrefixFromMask([string]$Mask) {
    $bits = 0
    foreach ($x in ([System.Net.IPAddress]::Parse($Mask)).GetAddressBytes()) {
        for ($i = 7; $i -ge 0; $i--) { if ((([int]$x -shr $i) -band 1) -eq 1) { $bits++ } }
    }
    return $bits
}

function Get-IPv4NetworkText([string]$Ip, [byte[]]$Mask) {
    $ipb = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
    $n = New-Object 'byte[]' 4
    for ($i = 0; $i -lt 4; $i++) { $n[$i] = [byte]($ipb[$i] -band $Mask[$i]) }
    return (([string]$n[0]) + '.' + ([string]$n[1]) + '.' + ([string]$n[2]) + '.' + ([string]$n[3]))
}

function ConvertTo-IPv4CidrSet([string[]]$Values) {
    # normalise any mix of '1.2.3.4', '1.2.3.0/24', '1.2.3.0/255.255.255.0' into '1.2.3.0/24'
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($v in $Values) {
        if (-not $v) { continue }
        foreach ($tok in ([string]$v -split ',')) {
            $t = $tok.Trim()
            if (-not $t -or $t -eq 'Any' -or $t -match ':') { continue }
            $parts = $t -split '/'
            $ip = $parts[0].Trim()
            if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { continue }
            $plen = 32
            if ($parts.Count -ge 2) {
                $mx = $parts[1].Trim()
                if ($mx -match '^\d+$') { $plen = [int]$mx } else { $plen = Get-IPv4PrefixFromMask $mx }
            }
            if ($plen -lt 0 -or $plen -gt 32) { $plen = 32 }
            $mask = Get-IPv4MaskBytes $plen
            $cidr = (Get-IPv4NetworkText $ip $mask) + '/' + ([string]$plen)
            if (-not $out.Contains($cidr)) { $out.Add($cidr) }
        }
    }
    return $out.ToArray()   # plain return (no leading comma) so callers can wrap with @()
}

function Get-PhysicalEgressCidrsFast($Nics) {
    $out = New-Object System.Collections.Generic.List[string]
    $tunIps = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($ni in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($ni.OperationalStatus -ne 'Up' -or -not (Test-IsTunInterface $ni)) { continue }
            foreach ($ua in $ni.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $tunIps.Add($ua.Address.IPAddressToString)
                }
            }
        }
    }
    catch { }
    foreach ($ni in $Nics) {
        try {
            foreach ($ua in $ni.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }
                $ip = $ua.Address.IPAddressToString
                if (-not $ip -or $ip -like '127.*' -or $ip -like '169.254.*') { continue }
                $plen = 32
                try { $plen = [int]$ua.PrefixLength } catch { $plen = 32 }
                if ($plen -le 0 -or $plen -gt 32) { $plen = 32 }
                $mask = Get-IPv4MaskBytes $plen
                $net = Get-IPv4NetworkText $ip $mask
                $overlap = $false
                if ($plen -lt 32) {
                    foreach ($ti in $tunIps) {
                        if ((Get-IPv4NetworkText $ti $mask) -eq $net) { $overlap = $true; break }
                    }
                }
                $cidr = if ($plen -ge 32 -or $overlap) { ($ip + '/32') } else { ($net + '/' + ([string]$plen)) }
                if (-not $out.Contains($cidr)) { $out.Add($cidr) }
            }
        }
        catch { }
    }
    return $out.ToArray()   # plain return (no leading comma) so callers can wrap with @()
}

function Get-TunAllowedLocalAddressesFast {
    # Scope AI-Guard-Allow-TUN(-Alt) to TUN IPs and standard TUN subnets (excluding any physical NIC subnet)
    # so sockets explicitly bound to a physical IP cannot match IF=xray_tun at ALE_AUTH_CONNECT_V4.
    $physIps = New-Object System.Collections.Generic.List[string]
    $tunIps = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($ni in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            $isTun = Test-IsTunInterface $ni
            foreach ($ua in $ni.GetIPProperties().UnicastAddresses) {
                $ip = $ua.Address
                if (-not $ip) { continue }
                $s = ($ip.IPAddressToString -split '%')[0]
                if (-not $s -or $s -like '127.*' -or $s -eq '::1' -or $s -like '169.254.*' -or $s -like 'fe80::*') { continue }
                if ($isTun) {
                    if (-not $tunIps.Contains($s)) { $tunIps.Add($s) }
                }
                elseif ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    if (-not $physIps.Contains($s)) { $physIps.Add($s) }
                }
            }
        }
    }
    catch { }

    $out = New-Object System.Collections.Generic.List[string]
    foreach ($ti in $tunIps) {
        if (-not $physIps.Contains($ti) -and -not $out.Contains($ti)) { $out.Add($ti) }
    }
    foreach ($cidr in @('172.18.0.0/16', '172.19.0.0/16', '172.20.0.0/16', '198.18.0.0/15', '100.64.0.0/10')) {
        $overlap = $false
        $cp = $cidr -split '/'
        $nb = ([System.Net.IPAddress]::Parse($cp[0])).GetAddressBytes()
        $plen = [int]$cp[1]
        $mask = if ($plen -eq 0) { [uint32]0 } else { [uint32]::MaxValue -shl (32 - $plen) }
        $nhost = ([uint32]$nb[0] -shl 24) -bor ([uint32]$nb[1] -shl 16) -bor ([uint32]$nb[2] -shl 8) -bor [uint32]$nb[3]
        foreach ($pip in $physIps) {
            $pb = ([System.Net.IPAddress]::Parse($pip)).GetAddressBytes()
            $ph = ([uint32]$pb[0] -shl 24) -bor ([uint32]$pb[1] -shl 16) -bor ([uint32]$pb[2] -shl 8) -bor [uint32]$pb[3]
            if (($ph -band $mask) -eq ($nhost -band $mask)) { $overlap = $true; break }
        }
        if (-not $overlap -and -not $out.Contains($cidr)) { $out.Add($cidr) }
    }
    foreach ($v6cidr in @('fc00::/7', 'fe80::/10')) {
        if (-not $out.Contains($v6cidr)) { $out.Add($v6cidr) }
    }
    return ,$out.ToArray()
}

function Get-RunningCoreProcessesFast {
    $found = New-Object System.Collections.Generic.List[System.Diagnostics.Process]
    foreach ($pn in @('xray', 'sing-box', 'mihomo', 'mihomo-windows-amd64-v1')) {
        try {
            foreach ($pr in [System.Diagnostics.Process]::GetProcessesByName($pn)) {
                $found.Add($pr)
            }
        }
        catch { }
    }
    return ,$found
}

function Resolve-CoreExecutablePath([string]$PreferredCore = 'xray') {
    # 1. If a known core process is currently running under V2rayNRoot\bin, prefer its exact path
    foreach ($pr in (Get-RunningCoreProcessesFast)) {
        try {
            $mp = $pr.MainModule.FileName
            if ($mp -and (Test-Path -LiteralPath $mp)) {
                if ($PreferredCore -eq 'sing-box' -and $pr.ProcessName -eq 'sing-box') { return $mp }
                if ($PreferredCore -eq 'xray' -and $pr.ProcessName -eq 'xray') { return $mp }
                if ($PreferredCore -eq 'mihomo' -and $pr.ProcessName -like 'mihomo*') { return $mp }
            }
        }
        catch { }
    }
    if ($PreferredCore -eq 'sing-box') {
        $sb = Join-Path $V2rayNRoot 'bin\sing_box\sing-box.exe'
        if (Test-Path -LiteralPath $sb) { return $sb }
    }
    elseif ($PreferredCore -eq 'mihomo') {
        foreach ($cand in @('bin\mihomo\mihomo-windows-amd64-v1.exe', 'bin\mihomo\mihomo.exe')) {
            $mh = Join-Path $V2rayNRoot $cand
            if (Test-Path -LiteralPath $mh) { return $mh }
        }
    }
    return (Join-Path $V2rayNRoot 'bin\xray\xray.exe')
}

function Test-FirewallProfilesHealthyFast {
    try {
        foreach ($sub in @('DomainProfile', 'StandardProfile', 'PublicProfile')) {
            $kp = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$sub"
            $gp = Get-ItemProperty -LiteralPath $kp -ErrorAction SilentlyContinue
            if (-not $gp -or $gp.EnableFirewall -ne 1 -or $gp.DefaultOutboundAction -ne 1) { return $false }

            $polKp = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$sub"
            if (Test-Path -LiteralPath $polKp) {
                $pgp = Get-ItemProperty -LiteralPath $polKp -ErrorAction SilentlyContinue
                if ($pgp) {
                    if ($null -ne $pgp.EnableFirewall -and $pgp.EnableFirewall -ne 1) { return $false }
                    if ($null -ne $pgp.DefaultOutboundAction -and $pgp.DefaultOutboundAction -ne 1) { return $false }
                }
            }
        }
        return $true
    }
    catch { return $false }
}

function Test-AiGuardNrptActiveFast {
    foreach ($base in @(
        'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig'
    )) {
        if (-not (Test-Path -LiteralPath $base)) { continue }
        foreach ($sub in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
            $c = (Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue).Comment
            if ($c -and $c -like 'AI-Guard*') { return $true }
        }
    }
    return $false
}

function Get-InstallAclIssues([string]$Path) {
    return (Get-GuardInstallAclIssues -Path $Path)
}

function Get-FirewallRuleAnalysis {
    # Single-pass pure registry scan (~80 ms, zero CIM):
    #   1) checks AI-Guard-* rule existence & Active=TRUE
    #   2) captures raw registry strings for AI-Guard-* rules (for 0-CIM node & core verification)
    #   3) detects any non-AI-Guard active Outbound Allow rules (+0 ms extra I/O)
    $states = @{}
    $rawByRule = @{}
    $rogues = New-Object System.Collections.Generic.List[object]
    $exceptions = @()
    if (Test-Path -LiteralPath $allowExceptionsFile) {
        try { $exceptions = @(Get-Content -LiteralPath $allowExceptionsFile -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { $exceptions = @() }
    }

    try {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
        $props = (Get-ItemProperty -Path $key -ErrorAction Stop).PSObject.Properties
        foreach ($pr in $props) {
            if ($pr.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
            $v = [string]$pr.Value
            $active = ($v -match '(^|\|)Active=TRUE(\||$)')
            $dn = ''
            if ($v -match '(^|\|)Name=([^|]+)') { $dn = $matches[2] }

            if (-not $states.ContainsKey($pr.Name) -or $active) {
                $states[$pr.Name] = $active
            }
            if ($dn -and (-not $states.ContainsKey($dn) -or $active)) {
                $states[$dn] = $active
            }

            $isAiGuard = ($pr.Name -like 'AI-Guard-*') -or ($dn -and ($dn -like 'AI-Guard-*'))
            $isDangerousBlanket = ($active -and ($v -match '(^|\|)Dir=Out(\||$)') -and ($v -match '(^|\|)Action=Allow(\||$)') -and
                                   ($v -notmatch '(^|\|)RA[46]=') -and ($v -notmatch '(^|\|)IF=') -and ($v -notmatch '(^|\|)App='))
            $ruleIdent = if ($dn) { $dn } else { $pr.Name }
            $isAuthorizedAiGuard = $isAiGuard -and (-not $isDangerousBlanket) -and
                ($ruleIdent -match '^AI-Guard-(Allow|Block)-(CN|TUN|TUN-Alt|PhysicalIP-On-TUN|Foreign-Physical|Foreign-Physical-IPv6|Node-TCP|Node-UDP|DoH-Ali|DHCP|LAN|NCSI|Core-.*|WebRTC-.*)$')

            if ($isAuthorizedAiGuard) {
                if (-not $rawByRule.ContainsKey($pr.Name) -or $active) { $rawByRule[$pr.Name] = $v }
                if ($dn -and (-not $rawByRule.ContainsKey($dn) -or $active)) { $rawByRule[$dn] = $v }
            }
            elseif ($active -and ($v -match '(^|\|)Dir=Out(\||$)') -and ($v -match '(^|\|)Action=Allow(\||$)')) {
                $exempt = ($exceptions.Count -gt 0) -and (($exceptions -contains $pr.Name) -or ($dn -and ($exceptions -contains $dn)))
                if (-not $exempt) {
                    $rogues.Add([pscustomobject]@{
                        Key         = $pr.Name
                        DisplayName = $(if ($dn) { $dn } else { $pr.Name })
                    })
                }
            }
        }
    }
    catch { }

    return [pscustomobject]@{
        States              = $states
        RawByRule           = $rawByRule
        RogueOutboundAllows = $rogues
    }
}

function Resolve-DomainIpsSafe([string]$Domain) {
    # 1. Encrypted AliDNS JSON DoH over direct IP 223.5.5.5:443 (Proxy=null):
    #    works even when TUN is OFF (covered by AI-Guard-Allow-CN) and resists UDP-53 spoofing.
    $ips = @()
    try {
        if ([int][Net.ServicePointManager]::SecurityProtocol -ne 0) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
        $uri = 'https://223.5.5.5/resolve?name=' + [uri]::EscapeDataString($Domain) + '&type=A'
        $req = [System.Net.HttpWebRequest]::Create($uri)
        $req.Proxy = $null
        $req.Timeout = 4000
        $req.ReadWriteTimeout = 4000
        $resp = $req.GetResponse()
        try {
            $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $json = $sr.ReadToEnd() | ConvertFrom-Json
            $ips = @($json.Answer | Where-Object { $_.type -eq 1 -and $_.data -match '^\d{1,3}(\.\d{1,3}){3}$' } | ForEach-Object { [string]$_.data })
        }
        finally { $resp.Close() }
    }
    catch { }

    if ($ips.Count -eq 0) {
        try {
            $ips = @(Resolve-DnsName -Name $Domain -Type A -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
        }
        catch { }
    }
    return @($ips | Where-Object { $_ } | Select-Object -Unique)
}

function Parse-ProxyConfigFast($Cfg) {
    if (-not $Cfg -or -not $Cfg.outbounds) { return $null }

    # 1. Xray config format (outbounds[].protocol)
    $xNode = $Cfg.outbounds | Where-Object { $_.protocol -in @('vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'wireguard', 'socks', 'http') } | Select-Object -First 1
    if ($xNode) {
        $addr = [string]$xNode.settings.address
        $pt = [string]$xNode.settings.port
        if (-not $addr -and $xNode.settings.vnext) {
            $addr = [string]$xNode.settings.vnext[0].address
            $pt = [string]$xNode.settings.vnext[0].port
        }
        if (-not $addr -and $xNode.settings.servers) {
            $addr = [string]$xNode.settings.servers[0].address
            $pt = [string]$xNode.settings.servers[0].port
        }
        if (-not $addr -and $xNode.settings.peers) {
            $ep = [string]$xNode.settings.peers[0].endpoint
            if ($ep -match '^(.+):(\d+)$') { $addr = $matches[1].Trim('[', ']'); $pt = $matches[2] }
        }
        if (-not $addr -or -not $pt) { return $null }

        $net = [string]$xNode.streamSettings.network
        $proto = [string]$xNode.protocol
        $alpn = @()
        try { if ($xNode.streamSettings.tlsSettings.alpn) { $alpn += @($xNode.streamSettings.tlsSettings.alpn) } } catch { }
        try { if ($xNode.streamSettings.realitySettings.alpn) { $alpn += @($xNode.streamSettings.realitySettings.alpn) } } catch { }
        $isUdp = ($net -match '(?i)quic|kcp|hysteria|wireguard' -or $proto -match '(?i)hysteria|wireguard' -or ($alpn -contains 'h3'))
        $uPorts = if ($isUdp) { if ($net -match '(?i)kcp') { @('0-65535') } else { @($pt) } } else { @() }
        return [pscustomobject]@{
            CoreType = 'xray'
            Protocol = $proto
            Network  = $net
            Address  = $addr
            TcpPorts = @($pt)
            Udp      = $isUdp
            UdpPorts = $uPorts
        }
    }

    # 2. sing-box config format (outbounds[].type, e.g. Hysteria2 / TUIC / WireGuard / VLESS / AnyTLS)
    $sList = @($Cfg.outbounds | Where-Object { $_.type -in @('hysteria2', 'hysteria', 'tuic', 'vless', 'vmess', 'trojan', 'shadowsocks', 'wireguard', 'anytls', 'socks', 'http') })
    if ($sList.Count -gt 0) {
        $sNode = $sList[0]
        $addrs = @()
        $ports = @()
        $tPorts = @()
        $isUdp = $false
        foreach ($item in $sList) {
            $ia = [string]$item.server
            $ipList = @()
            if ($item.server_port) { $ipList += ([string]$item.server_port) }
            if ($item.server_ports) {
                foreach ($sp in @($item.server_ports)) {
                    # sing-box uses "20000:30000" for Hysteria2 port-hopping ranges; Windows Firewall uses "20000-30000"
                    $norm = ([string]$sp).Replace(':', '-').Trim()
                    if ($norm) { $ipList += $norm }
                }
            }
            if (-not $ia -and $item.peers) {
                $ia = [string]$item.peers[0].server
                if ($item.peers[0].server_port) { $ipList += ([string]$item.peers[0].server_port) }
            }
            if ($ia) { $addrs += $ia }
            $ipList = @($ipList | Where-Object { $_ } | Select-Object -Unique)
            if ($ipList.Count -gt 0) {
                $ports += $ipList
                $pType = [string]$item.type
                $pNet = if ($item.transport -and $item.transport.type) { [string]$item.transport.type } else { $pType }
                $pAlpn = @()
                try { if ($item.tls -and $item.tls.alpn) { $pAlpn += @($item.tls.alpn) } } catch { }
                if (($pType -in @('hysteria2', 'hysteria', 'tuic', 'wireguard')) -or ($pNet -match '(?i)quic') -or ($pAlpn -contains 'h3')) {
                    $isUdp = $true
                }
                if ($pType -in @('hysteria2', 'hysteria', 'tuic', 'wireguard')) { $tPorts += $ipList[0] }
                else { $tPorts += $ipList }
            }
        }
        $addrs = @($addrs | Where-Object { $_ } | Select-Object -Unique)
        $ports = @($ports | Where-Object { $_ } | Select-Object -Unique)
        $tPorts = @($tPorts | Where-Object { $_ } | Select-Object -Unique)
        if ($addrs.Count -eq 0 -or $ports.Count -eq 0) { return $null }

        $proto = [string]$sNode.type
        $net = if ($sNode.transport -and $sNode.transport.type) { [string]$sNode.transport.type } else { $proto }
        $uPorts = if ($isUdp) { $ports } else { @() }
        return [pscustomobject]@{
            CoreType  = 'sing-box'
            Protocol  = $proto
            Network   = $net
            Address   = $addrs[0]
            Addresses = $addrs
            TcpPorts  = $tPorts
            Udp       = $isUdp
            UdpPorts  = $uPorts
        }
    }

    return $null
}

function Test-NodeMetaFastHit([string]$StampPrefix) {
    if (-not (Test-Path -LiteralPath $nodeMeta)) { return $false }
    try {
        return ((Get-Content -LiteralPath $nodeMeta -Raw -Encoding UTF8).Trim().StartsWith($StampPrefix))
    }
    catch { return $false }
}

function Sync-NodeActiveHostRoutes {
    param([string[]]$NodeIps)

    $validIps = @($NodeIps | Where-Object { $_ -and ($_ -match '^\d{1,3}(\.\d{1,3}){3}$') } | Select-Object -Unique)
    if ($validIps.Count -eq 0) { return }

    # Zero-CIM precheck: read active physical IPv4 gateways (.NET) and live /32 routes (route.exe).
    # After a reboot, ActiveStore /32 routes vanish even while config.json & firewall rules are
    # unchanged; after a Wi-Fi/hotspot switch, the next-hop gateway changes. Catch both without
    # loading NetTCPIP CIM on healthy ticks.
    $activePhysGws = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($ni in @(Get-ActivePhysicalNicsFast)) {
        try {
            foreach ($gw in $ni.GetIPProperties().GatewayAddresses) {
                if ($gw.Address -and $gw.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $gs = $gw.Address.IPAddressToString
                    if ($gs -and $gs -ne '0.0.0.0') { [void]$activePhysGws.Add($gs) }
                }
            }
        }
        catch { }
    }
    if ($activePhysGws.Count -eq 0) { return }

    $metaMatched = $false
    if (Test-Path -LiteralPath $nodeRoutesMeta) {
        try {
            $nrMetaRaw = [System.IO.File]::ReadAllText($nodeRoutesMeta, [System.Text.Encoding]::UTF8).Trim()
            $nrMetaIps = @($nrMetaRaw.Split(',') | Where-Object { $_ } | Sort-Object -Unique) -join ','
            $wantSorted = (@($validIps | Sort-Object -Unique)) -join ','
            if ($nrMetaIps -eq $wantSorted) { $metaMatched = $true }
        }
        catch { }
    }

    if ($metaMatched) {
        try {
            $liveHostGw = @{}
            foreach ($rl in @(& route.exe PRINT -4 2>$null)) {
                if ([string]$rl -match '^\s*(\d+\.\d+\.\d+\.\d+)\s+255\.255\.255\.255\s+(\d+\.\d+\.\d+\.\d+)\s+') {
                    $dst = $matches[1]
                    $nh = $matches[2]
                    if (-not $liveHostGw.ContainsKey($dst)) { $liveHostGw[$dst] = New-Object System.Collections.Generic.List[string] }
                    $liveHostGw[$dst].Add($nh)
                }
            }
            $allLiveOk = $true
            foreach ($nip in $validIps) {
                if (-not $liveHostGw.ContainsKey($nip)) { $allLiveOk = $false; break }
                $gwHit = $false
                foreach ($lgw in $liveHostGw[$nip]) {
                    if ($activePhysGws.Contains($lgw)) { $gwHit = $true; break }
                }
                if (-not $gwHit) { $allLiveOk = $false; break }
            }
            if ($allLiveOk) { return }
        }
        catch { }
    }

    # Ensure /32 physical host route for proxy node IPs (ActiveStore only - never PersistentStore)
    try {
        $staleRouteIps = @()
        if (Test-Path -LiteralPath $nodeMeta) {
            $oldMetaRaw = Get-Content -LiteralPath $nodeMeta -Raw -ErrorAction SilentlyContinue
            if ($oldMetaRaw -match '\|([\d\.,]+)\|') {
                $staleRouteIps += @($Matches[1].Split(','))
            }
        }
        if (Test-Path -LiteralPath $nodeRoutesMeta) {
            $oldNrRaw = [System.IO.File]::ReadAllText($nodeRoutesMeta, [System.Text.Encoding]::UTF8).Trim()
            if ($oldNrRaw) {
                $staleRouteIps += @($oldNrRaw.Split(','))
            }
        }
        foreach ($prevIp in @($staleRouteIps | Where-Object { $_ -and ($_ -match '^\d{1,3}(\.\d{1,3}){3}$') } | Select-Object -Unique)) {
            if ($validIps -notcontains $prevIp) {
                Remove-NetRoute -DestinationPrefix ($prevIp + '/32') -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
                Remove-NetRoute -DestinationPrefix ($prevIp + '/32') -PolicyStore PersistentStore -Confirm:$false -ErrorAction SilentlyContinue
            }
        }

        $physRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceAlias -notmatch '(?i)tun|wintun|sing|xray|meta|mihomo|loopback' -and $_.NextHop -ne '0.0.0.0' } |
            Sort-Object { [int]$_.RouteMetric + [int]$_.InterfaceMetric } |
            Select-Object -First 1
        if ($physRoute -and $physRoute.NextHop) {
            $changedRoutes = $false
            foreach ($nodeIp in $validIps) {
                $pDup = @(Get-NetRoute -DestinationPrefix ($nodeIp + '/32') -PolicyStore PersistentStore -ErrorAction SilentlyContinue)
                if ($pDup.Count -gt 0) {
                    $pDup | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
                    $changedRoutes = $true
                }
                $curHostRoute = @(Get-NetRoute -DestinationPrefix ($nodeIp + '/32') -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
                if ($curHostRoute.Count -eq 0) {
                    New-NetRoute -DestinationPrefix ($nodeIp + '/32') -InterfaceAlias $physRoute.InterfaceAlias -NextHop $physRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
                    $changedRoutes = $true
                }
                elseif ($curHostRoute[0].NextHop -ne $physRoute.NextHop -or $curHostRoute[0].InterfaceAlias -ne $physRoute.InterfaceAlias -or $curHostRoute[0].RouteMetric -ne 1) {
                    Remove-NetRoute -DestinationPrefix ($nodeIp + '/32') -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
                    New-NetRoute -DestinationPrefix ($nodeIp + '/32') -InterfaceAlias $physRoute.InterfaceAlias -NextHop $physRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
                    $changedRoutes = $true
                }
            }
            New-Item -ItemType Directory -Path (Split-Path $nodeRoutesMeta) -Force | Out-Null
            [System.IO.File]::WriteAllText($nodeRoutesMeta, ($validIps -join ','), (New-Object System.Text.UTF8Encoding($false)))
            if ($changedRoutes) {
                $script:repairedItems += 'node-route-synced'
                Say ('    synced ActiveStore /32 route -> ' + ($validIps -join ',') + ' via ' + $physRoute.NextHop + ' (' + $physRoute.InterfaceAlias + ')')
            }
        }
    }
    catch { }
}

function Remove-RedundantActiveCoreRules {
    param([pscustomobject]$Analysis, [string]$CoreExe)
    if (-not $Analysis -or -not $CoreExe) { return }
    $activeTag = if ($CoreExe -like '*xray*') { 'Xray' } elseif ($CoreExe -like '*sing*') { 'SingBox' } elseif ($CoreExe -like '*v2rayn*') { 'V2rayN' } else { '' }
    if (-not $activeTag) { return }
    $hasAny = $false
    foreach ($sfx in @('TCP', 'UDP', 'DoH')) {
        $rn = 'AI-Guard-Allow-Core-' + $activeTag + '-' + $sfx
        if ($Analysis.States.ContainsKey($rn)) { $hasAny = $true; break }
    }
    if (-not $hasAny) { return }
    $removedAny = $false
    foreach ($sfx in @('TCP', 'UDP', 'DoH')) {
        $rn = 'AI-Guard-Allow-Core-' + $activeTag + '-' + $sfx
        $dup = Get-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue
        if ($dup) {
            $dup | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            $removedAny = $true
        }
    }
    if ($removedAny) {
        $script:repairedItems += ('core-dup-pruned(' + $activeTag + ')')
        Reset-RuleCache
    }
}

function Sync-NodeRuleFast {
    param([pscustomobject]$Analysis)
    if ($DisableAutoNodeSync) { return }

    $cfgPath = Join-Path $V2rayNRoot 'binConfigs\config.json'
    if (-not (Test-Path -LiteralPath $cfgPath)) { return }
    $cfgItem = Get-Item -LiteralPath $cfgPath -ErrorAction SilentlyContinue
    if (-not $cfgItem) { return }

    $defaultXrayExe = Join-Path $V2rayNRoot 'bin\xray\xray.exe'
    $stampPrefix = ($cfgItem.Length.ToString() + ':' + $cfgItem.LastWriteTimeUtc.Ticks.ToString() + '|')
    $rawTcp = if ($Analysis.RawByRule.ContainsKey('AI-Guard-Allow-Node-TCP')) { [string]$Analysis.RawByRule['AI-Guard-Allow-Node-TCP'] } else { '' }
    $rawUdp = if ($Analysis.RawByRule.ContainsKey('AI-Guard-Allow-Node-UDP')) { [string]$Analysis.RawByRule['AI-Guard-Allow-Node-UDP'] } else { '' }
    $tcpActive = ($Analysis.States.ContainsKey('AI-Guard-Allow-Node-TCP') -and $Analysis.States['AI-Guard-Allow-Node-TCP'])
    $udpExists = $Analysis.States.ContainsKey('AI-Guard-Allow-Node-UDP')
    $udpActive = ($udpExists -and $Analysis.States['AI-Guard-Allow-Node-UDP'])

    # Fast path (<0.3 ms, 0 CIM): config.json unchanged AND live firewall rule still matches cached node + core metadata
    # (Skip fast hit if domain-based node cache is older than 15 minutes so CDN/DDNS IP rotations refresh.)
    if ($tcpActive -and $rawTcp -and (Test-Path -LiteralPath $nodeMeta)) {
        try {
            $metaItem = Get-Item -LiteralPath $nodeMeta -ErrorAction SilentlyContinue
            $cached = (Get-Content -LiteralPath $nodeMeta -Raw -Encoding UTF8).Trim()
            if ($cached.StartsWith($stampPrefix)) {
                $parts = $cached.Split('|')
                $hasDomain = ($parts.Count -ge 6 -and $parts[5] -eq 'domain')
                $domainStale = ($hasDomain -and $metaItem -and (([DateTime]::UtcNow - $metaItem.LastWriteTimeUtc).TotalMinutes -ge 15))
                if (-not $domainStale -and $parts.Count -ge 4) {
                    $wantIps = @($parts[1].Split(',') | Where-Object { $_ })
                    $wantTcp = @($parts[2].Split(',') | Where-Object { $_ })
                    $wantUdp = @($parts[3].Split(',') | Where-Object { $_ })
                    $wantExe = if ($parts.Count -ge 5 -and $parts[4]) { $parts[4] } else { $defaultXrayExe }
                    $ok = ($wantIps.Count -gt 0) -and ($wantTcp.Count -gt 0)
                    if ($ok -and $rawTcp -notmatch ('(?i)(^|\|)App=' + [regex]::Escape($wantExe) + '(\||$)')) {
                        $ok = $false
                    }
                    if ($ok) {
                        foreach ($wip in $wantIps) {
                            if ($rawTcp -notmatch ('(^|\|)RA4=' + [regex]::Escape($wip) + '(\||$)')) { $ok = $false; break }
                        }
                    }
                    if ($ok) {
                        foreach ($wp in $wantTcp) {
                            if ($rawTcp -notmatch ('(^|\|)RPort=' + [regex]::Escape($wp) + '(\||$)')) { $ok = $false; break }
                        }
                    }
                    if ($ok) {
                        if ($wantUdp.Count -gt 0) {
                            if (-not $udpActive -or -not $rawUdp -or ($rawUdp -notmatch ('(?i)(^|\|)App=' + [regex]::Escape($wantExe) + '(\||$)'))) { $ok = $false }
                            if ($ok) {
                                foreach ($wip in $wantIps) {
                                    if ($rawUdp -notmatch ('(^|\|)RA4=' + [regex]::Escape($wip) + '(\||$)')) { $ok = $false; break }
                                }
                            }
                            if ($ok) {
                                foreach ($wup in $wantUdp) {
                                    if ($rawUdp -notmatch ('(^|\|)RPort=' + [regex]::Escape($wup) + '(\||$)')) { $ok = $false; break }
                                }
                            }
                        }
                        elseif ($udpExists) { $ok = $false }
                    }
                    if ($ok) {
                        Sync-NodeActiveHostRoutes -NodeIps $wantIps
                        Remove-RedundantActiveCoreRules -Analysis $Analysis -CoreExe $wantExe
                        return
                    }
                }
            }
        }
        catch { }
    }

    # Parse config.json only when timestamp changed or node-sync.meta missing/drifted
    try {
        $cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $parsed = Parse-ProxyConfigFast -Cfg $cfg
        if (-not $parsed) { return }

        $coreExe = Resolve-CoreExecutablePath -PreferredCore $parsed.CoreType
        $rawAddrs = if ($parsed.PSObject.Properties.Name -contains 'Addresses' -and $parsed.Addresses) { @($parsed.Addresses) } else { @($parsed.Address) }

        $ips = @()
        $usedDomain = $false
        foreach ($raItem in $rawAddrs) {
            if (-not $raItem) { continue }
            if ($raItem -match '^\d{1,3}(\.\d{1,3}){3}$') {
                $ips += @($raItem)
            }
            else {
                $usedDomain = $true
                $ips += @(Resolve-DomainIpsSafe -Domain $raItem)
            }
        }
        if ($ips.Count -eq 0) { return }

        $udp = [bool]$parsed.Udp
        $udpPorts = @($parsed.UdpPorts)
        # Only active config.json outbounds are authorized (ignore transient configTest*.json)
        $ips = @($ips | Where-Object { $_ } | Select-Object -Unique)
        $udpPorts = @($udpPorts | Where-Object { $_ } | Select-Object -Unique)

        # Extract existing IPs, ports & app from raw registry string (0 CIM) to preserve same-IP multi-port setup
        $oldIps = @([regex]::Matches($rawTcp, '(?:^|\|)RA4=([^|]+)') | ForEach-Object { $_.Groups[1].Value })
        $oldPorts = @([regex]::Matches($rawTcp, '(?:^|\|)RPort=([^|]+)') | ForEach-Object { $_.Groups[1].Value })
        $sameApp = ($rawTcp -match ('(?i)(^|\|)App=' + [regex]::Escape($coreExe) + '(\||$)'))

        $tcpPorts = @($parsed.TcpPorts)
        if ($sameApp -and $oldIps.Count -gt 0 -and ((($oldIps | Sort-Object) -join ',') -eq (($ips | Sort-Object) -join ','))) {
            if ($oldPorts.Count -gt 0 -and ($oldPorts -notcontains 'Any')) {
                $tcpPorts = @($oldPorts) + @($tcpPorts)
            }
        }
        $tcpPorts = @($tcpPorts | Where-Object { $_ } | Select-Object -Unique)

        # Also validate AI-Guard-Allow-Node-UDP (e.g. hy2 port-hopping ranges) before taking fast skip
        $oldUdpIps = @([regex]::Matches($rawUdp, '(?:^|\|)RA4=([^|]+)') | ForEach-Object { $_.Groups[1].Value })
        $oldUdpPorts = @([regex]::Matches($rawUdp, '(?:^|\|)RPort=([^|]+)') | ForEach-Object { $_.Groups[1].Value })
        $sameUdpApp = ($rawUdp -match ('(?i)(^|\|)App=' + [regex]::Escape($coreExe) + '(\||$)'))
        $udpExact = if ($udp) {
            $udpActive -and
            $sameUdpApp -and
            ($rawUdp -notmatch '\|IF=') -and
            (((($oldUdpIps | Sort-Object) -join ',') -eq (($ips | Sort-Object) -join ','))) -and
            (((($oldUdpPorts | Sort-Object) -join ',') -eq (($udpPorts | Sort-Object) -join ',')))
        }
        else {
            -not $udpExists
        }

        # Check if raw registry rule already satisfies everything (avoids loading NetSecurity CIM on first meta write)
        $alreadyExact = $tcpActive -and
            $sameApp -and
            ($rawTcp -notmatch '\|IF=') -and
            (((($oldIps | Sort-Object) -join ',') -eq (($ips | Sort-Object) -join ','))) -and
            (((($oldPorts | Sort-Object) -join ',') -eq (($tcpPorts | Sort-Object) -join ','))) -and
            $udpExact

        if (-not $alreadyExact) {
            $tcpRule = Get-NetFirewallRule -DisplayName 'AI-Guard-Allow-Node-TCP' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($tcpRule) {
                Set-NetFirewallRule -InputObject $tcpRule -Program $coreExe -RemoteAddress $ips -RemotePort $tcpPorts -InterfaceAlias 'Any' -Enabled True -ErrorAction Stop
            }
            else {
                New-NetFirewallRule -Name 'AI-Guard-Allow-Node-TCP' -DisplayName 'AI-Guard-Allow-Node-TCP' `
                    -Direction Outbound -Action Allow -Program $coreExe -Protocol TCP `
                    -RemoteAddress $ips -RemotePort $tcpPorts -Profile Any -Enabled True `
                    -Description 'Proxy core -> authorized proxy node (TCP, any physical NIC).' | Out-Null
            }
            $Analysis.States['AI-Guard-Allow-Node-TCP'] = $true

            $udpRule = Get-NetFirewallRule -DisplayName 'AI-Guard-Allow-Node-UDP' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($udp) {
                if ($udpRule) {
                    Set-NetFirewallRule -InputObject $udpRule -Program $coreExe -RemoteAddress $ips -RemotePort $udpPorts -InterfaceAlias 'Any' -Enabled True -ErrorAction Stop
                }
                else {
                    New-NetFirewallRule -Name 'AI-Guard-Allow-Node-UDP' -DisplayName 'AI-Guard-Allow-Node-UDP' `
                        -Direction Outbound -Action Allow -Program $coreExe -Protocol UDP `
                        -RemoteAddress $ips -RemotePort $udpPorts -Profile Any -Enabled True `
                        -Description 'Proxy core -> authorized proxy node (UDP transports, any physical NIC).' | Out-Null
                }
                $Analysis.States['AI-Guard-Allow-Node-UDP'] = $true
            }
            elseif ($udpRule) {
                $udpRule | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                [void]$Analysis.States.Remove('AI-Guard-Allow-Node-UDP')
            }

            # Keep AI-Guard-Allow-DoH-Ali bound to the active core executable if core changed (e.g. xray <-> sing-box)
            $rawDoh = if ($Analysis.RawByRule.ContainsKey('AI-Guard-Allow-DoH-Ali')) { [string]$Analysis.RawByRule['AI-Guard-Allow-DoH-Ali'] } else { '' }
            if ($rawDoh -and ($rawDoh -notmatch ('(?i)(^|\|)App=' + [regex]::Escape($coreExe) + '(\||$)'))) {
                $dohRule = Get-NetFirewallRule -DisplayName 'AI-Guard-Allow-DoH-Ali' -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($dohRule) {
                    Set-NetFirewallRule -InputObject $dohRule -Program $coreExe -Enabled True -ErrorAction SilentlyContinue
                }
            }

            # Sync companion rules (TCP/UDP node + AliDNS DoH) for standby cores, and prune redundant Core-* rules for active core
            foreach ($candRel in @('bin\xray\xray.exe', 'bin\sing_box\sing-box.exe', 'bin\mihomo\mihomo-windows-amd64-v1.exe', 'bin\mihomo\mihomo.exe', 'v2rayN.exe')) {
                $compExe = Join-Path $V2rayNRoot $candRel
                $cName = if ($candRel -like '*xray*') { 'Xray' } elseif ($candRel -like '*sing*') { 'SingBox' } elseif ($candRel -like '*v2rayn*') { 'V2rayN' } else { [System.IO.Path]::GetFileNameWithoutExtension($candRel) }
                if ($compExe -ieq $coreExe) {
                    foreach ($sfx in @('TCP', 'UDP', 'DoH')) {
                        $dup = Get-NetFirewallRule -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-' + $sfx) -ErrorAction SilentlyContinue
                        if ($dup) { $dup | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
                    }
                    continue
                }
                if (Test-Path -LiteralPath $compExe) {
                    $cRuleTcp = Get-NetFirewallRule -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-TCP') -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($cRuleTcp) {
                        Set-NetFirewallRule -InputObject $cRuleTcp -Program $compExe -RemoteAddress $ips -RemotePort $tcpPorts -InterfaceAlias 'Any' -Enabled True -ErrorAction SilentlyContinue
                    }
                    else {
                        New-NetFirewallRule -Name ('AI-Guard-Allow-Core-' + $cName + '-TCP') -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-TCP') `
                            -Direction Outbound -Action Allow -Program $compExe -Protocol TCP `
                            -RemoteAddress $ips -RemotePort $tcpPorts -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
                    }
                    $cRuleUdp = Get-NetFirewallRule -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-UDP') -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($udp) {
                        if ($cRuleUdp) {
                            Set-NetFirewallRule -InputObject $cRuleUdp -Program $compExe -RemoteAddress $ips -RemotePort $udpPorts -InterfaceAlias 'Any' -Enabled True -ErrorAction SilentlyContinue
                        }
                        else {
                            New-NetFirewallRule -Name ('AI-Guard-Allow-Core-' + $cName + '-UDP') -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-UDP') `
                                -Direction Outbound -Action Allow -Program $compExe -Protocol UDP `
                                -RemoteAddress $ips -RemotePort $udpPorts -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
                        }
                    }
                    elseif ($cRuleUdp) {
                        $cRuleUdp | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                    }
                    $cRuleDoh = Get-NetFirewallRule -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-DoH') -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($cRuleDoh) {
                        Set-NetFirewallRule -InputObject $cRuleDoh -Program $compExe -RemoteAddress @('223.5.5.5', '223.6.6.6') -RemotePort @('443') -InterfaceAlias 'Any' -Enabled True -ErrorAction SilentlyContinue
                    }
                    else {
                        New-NetFirewallRule -Name ('AI-Guard-Allow-Core-' + $cName + '-DoH') -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-DoH') `
                            -Direction Outbound -Action Allow -Program $compExe -Protocol TCP `
                            -RemoteAddress @('223.5.5.5', '223.6.6.6') -RemotePort @('443') -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
                    }
                }
            }
            if (-not $udp) {
                Get-NetFirewallRule -DisplayName 'AI-Guard-Allow-Core-*-UDP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            }

            $coreLabel = Split-Path -Leaf $coreExe
            $summary = ($ips -join ',') + ':' + ($tcpPorts -join ',') + $(if ($udp) { '/udp:' + ($udpPorts -join ',') } else { '' }) + ' [' + $coreLabel + ']'
            $script:repairedItems += ('node-synced(' + $summary + ')')
            Say ('    auto-synced node rule -> ' + $summary)
        }

        Sync-NodeActiveHostRoutes -NodeIps $ips
        Remove-RedundantActiveCoreRules -Analysis $Analysis -CoreExe $coreExe

        New-Item -ItemType Directory -Path (Split-Path $nodeMeta) -Force | Out-Null
        $domainTag = if ($usedDomain) { '|domain' } else { '|ip' }
        $metaLine = $stampPrefix + ($ips -join ',') + '|' + ($tcpPorts -join ',') + '|' + ($udpPorts -join ',') + '|' + $coreExe + $domainTag
        Set-Content -LiteralPath $nodeMeta -Value $metaLine -Encoding ASCII
    }
    catch { }
    # node sync creates / removes companion rules, so an index built before this call
    # no longer reflects the store; drop it instead of repairing from a stale object.
    Reset-RuleCache
}

function Test-LocalPortListening([int]$Port, [int]$TimeoutMs = 150) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }
        try { $c.EndConnect($iar); return $true } catch { return $false }
    }
    catch { return $false }
    finally { try { $c.Close() } catch { } }
}

function Test-AnyProxyAppRunning {
    foreach ($pn in @('xray', 'v2rayN', 'sing-box', 'mihomo', 'mihomo-windows-amd64-v1', 'clash')) {
        if ([System.Diagnostics.Process]::GetProcessesByName($pn).Length -gt 0) { return $true }
    }
    return $false
}

function Heal-StaleLoopbackProxyFast {
    if ($SkipStaleProxyHeal) { return }
    try {
        foreach ($hive in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
            if ($hive.PSChildName -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { continue }
            $ik = 'Registry::HKEY_USERS\' + $hive.PSChildName + '\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
            $ie = Get-ItemProperty -LiteralPath $ik -ErrorAction SilentlyContinue
            if (-not $ie -or $ie.ProxyEnable -ne 1) { continue }
            $ps = [string]$ie.ProxyServer
            if ($ps -notmatch '(?:^|[;=])(?:https?://)?(?:127\.0\.0\.1|localhost):(\d+)') { continue }
            $port = [int]$matches[1]

            if (Test-AnyProxyAppRunning) { return }
            Start-Sleep -Milliseconds 250
            if (Test-AnyProxyAppRunning) { return }
            if (Test-LocalPortListening -Port $port -TimeoutMs 150) { return }

            Set-ItemProperty -LiteralPath $ik -Name 'ProxyEnable' -Value 0 -Type DWord -ErrorAction Stop
            $script:repairedItems += ('cleared-dead-proxy(127.0.0.1:' + $port + ')')
            Say ('    cleared stale loopback system proxy (127.0.0.1:' + $port + ', proxy app not running)')
        }
    }
    catch { }
}

function Backfill-DnsBaselineV54 {
    $bf = Join-Path $Root 'backup\baseline.json'
    $dnsJsonPath = $null
    if (Test-Path -LiteralPath $bf) {
        try { $dnsJsonPath = (Get-Content -LiteralPath $bf -Raw -Encoding UTF8 | ConvertFrom-Json).Dns } catch { }
    }
    if (-not $dnsJsonPath) {
        $oldestDns = Get-ChildItem -Path (Join-Path $Root 'backup') -Filter 'dns-*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -First 1
        if ($oldestDns) { $dnsJsonPath = $oldestDns.FullName }
    }
    if (-not $dnsJsonPath -or -not (Test-Path -LiteralPath $dnsJsonPath)) { return }

    try {
        $db = Get-Content -LiteralPath $dnsJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $dbChanged = $false

        $polKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
        if ($db.PSObject.Properties.Name -notcontains 'SmartNameResolutionPolicy') {
            $curPolSmhnr = if (Test-Path -LiteralPath $polKey) { (Get-ItemProperty -LiteralPath $polKey -ErrorAction SilentlyContinue).DisableSmartNameResolution } else { $null }
            $db | Add-Member -NotePropertyName 'SmartNameResolutionPolicy' -NotePropertyValue $curPolSmhnr -Force
            $dbChanged = $true
        }
        if ($db.PSObject.Properties.Name -notcontains 'SmartNameResolutionService') {
            $curSvcSmhnr = if (Test-Path -LiteralPath $svcKey) { (Get-ItemProperty -LiteralPath $svcKey -ErrorAction SilentlyContinue).DisableSmartNameResolution } else { $null }
            $db | Add-Member -NotePropertyName 'SmartNameResolutionService' -NotePropertyValue $curSvcSmhnr -Force
            $dbChanged = $true
        }

        if ($dbChanged) {
            $db | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $dnsJsonPath -Encoding UTF8
        }
    }
    catch { }
}

function Set-SmhnrHardening {
    param(
        [bool]$DisableLlmnr = $true,
        [bool]$DisableSmhnr = $true
    )
    try {
        if (-not $DisableLlmnr -and -not $DisableSmhnr) { return }
        $polKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
        # NOTE: In PowerShell's Registry provider, New-Item -Force on an existing key
        # recreates the key and wipes sibling values (e.g. EnableMulticast); guard with Test-Path.
        if (-not (Test-Path -LiteralPath $polKey)) {
            New-Item -Path $polKey -Force | Out-Null
        }
        if ($DisableLlmnr) {
            New-ItemProperty -Path $polKey -Name 'EnableMulticast' -Value 0 -PropertyType DWord -Force | Out-Null
            if (Test-Path -LiteralPath $svcKey) {
                New-ItemProperty -Path $svcKey -Name 'EnableMDNS' -Value 0 -PropertyType DWord -Force | Out-Null
            }
        }
        if ($DisableSmhnr) {
            New-ItemProperty -Path $polKey -Name 'DisableSmartNameResolution' -Value 1 -PropertyType DWord -Force | Out-Null
            if (Test-Path -LiteralPath $svcKey) {
                New-ItemProperty -Path $svcKey -Name 'DisableSmartNameResolution' -Value 1 -PropertyType DWord -Force | Out-Null
            }
        }
    }
    catch { }
}

function Set-WebRtcPolicy {
    param([bool]$Enable = $true)
    $changed = $false
    try {
        $cPol = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
        $ePol = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        if ($Enable) {
            $curC = (Get-ItemProperty -LiteralPath $cPol -ErrorAction SilentlyContinue).WebRtcIPHandlingPolicy
            if ($curC -ne 'disable_non_proxied_udp') {
                if (-not (Test-Path -LiteralPath $cPol)) { New-Item -Path $cPol -Force | Out-Null }
                New-ItemProperty -Path $cPol -Name 'WebRtcIPHandlingPolicy' -Value 'disable_non_proxied_udp' -PropertyType String -Force | Out-Null
                $changed = $true
            }
            $ep = Get-ItemProperty -LiteralPath $ePol -ErrorAction SilentlyContinue
            if (-not $ep -or $ep.WebRtcIPHandlingPolicy -ne 'disable_non_proxied_udp' -or $ep.WebRtcLocalhostIpHandling -ne 'disable_non_proxied_udp') {
                if (-not (Test-Path -LiteralPath $ePol)) { New-Item -Path $ePol -Force | Out-Null }
                New-ItemProperty -Path $ePol -Name 'WebRtcIPHandlingPolicy' -Value 'disable_non_proxied_udp' -PropertyType String -Force | Out-Null
                New-ItemProperty -Path $ePol -Name 'WebRtcLocalhostIpHandling' -Value 'disable_non_proxied_udp' -PropertyType String -Force | Out-Null
                $changed = $true
            }
        }
        else {
            if (Test-Path -LiteralPath $cPol) {
                $curC = (Get-ItemProperty -LiteralPath $cPol -ErrorAction SilentlyContinue).WebRtcIPHandlingPolicy
                if ($null -ne $curC) {
                    Remove-ItemProperty -Path $cPol -Name 'WebRtcIPHandlingPolicy' -ErrorAction SilentlyContinue
                    $changed = $true
                }
            }
            if (Test-Path -LiteralPath $ePol) {
                $ep = Get-ItemProperty -LiteralPath $ePol -ErrorAction SilentlyContinue
                if ($ep -and ($null -ne $ep.WebRtcIPHandlingPolicy -or $null -ne $ep.WebRtcLocalhostIpHandling)) {
                    Remove-ItemProperty -Path $ePol -Name 'WebRtcIPHandlingPolicy' -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $ePol -Name 'WebRtcLocalhostIpHandling' -ErrorAction SilentlyContinue
                    $changed = $true
                }
            }
        }
    }
    catch { }
    return $changed
}

function Set-BrowserDohPolicy {
    param([bool]$DisableBuiltInDoh = $true)
    $changed = $false
    try {
        $cPol = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
        $ePol = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        if ($DisableBuiltInDoh) {
            $curC = (Get-ItemProperty -LiteralPath $cPol -ErrorAction SilentlyContinue).DnsOverHttpsMode
            if ($curC -ne 'off') {
                if (-not (Test-Path -LiteralPath $cPol)) { New-Item -Path $cPol -Force | Out-Null }
                New-ItemProperty -Path $cPol -Name 'DnsOverHttpsMode' -Value 'off' -PropertyType String -Force | Out-Null
                $changed = $true
            }
            $curE = (Get-ItemProperty -LiteralPath $ePol -ErrorAction SilentlyContinue).DnsOverHttpsMode
            if ($curE -ne 'off') {
                if (-not (Test-Path -LiteralPath $ePol)) { New-Item -Path $ePol -Force | Out-Null }
                New-ItemProperty -Path $ePol -Name 'DnsOverHttpsMode' -Value 'off' -PropertyType String -Force | Out-Null
                $changed = $true
            }
        }
        else {
            if (Test-Path -LiteralPath $cPol) {
                $curC = (Get-ItemProperty -LiteralPath $cPol -ErrorAction SilentlyContinue).DnsOverHttpsMode
                if ($null -ne $curC) {
                    Remove-ItemProperty -Path $cPol -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue
                    $changed = $true
                }
            }
            if (Test-Path -LiteralPath $ePol) {
                $curE = (Get-ItemProperty -LiteralPath $ePol -ErrorAction SilentlyContinue).DnsOverHttpsMode
                if ($null -ne $curE) {
                    Remove-ItemProperty -Path $ePol -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue
                    $changed = $true
                }
            }
        }
    }
    catch { }
    return $changed
}

function Get-CnPrefixes {
    if (-not (Test-Path -LiteralPath $cnList)) { return ,@() }
    $rawLines = [System.IO.File]::ReadAllLines($cnList)
    $validated = @(Get-ValidatedCnPrefixes -Lines $rawLines -MinCount 1000)
    return ,$validated
}

function Get-ListSignature {
    param([string[]]$Prefixes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes(($Prefixes -join "`n"))
        return ($Prefixes.Count.ToString() + ':' + [System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', ''))
    }
    finally {
        $sha.Dispose()
    }
}

function Get-WatchdogProcesses {
    @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -and $_.CommandLine -match 'watchdog\.ps1' })
}

function Read-PrevState {
    if (-not (Test-Path -LiteralPath $stateFile)) { return $null }
    try { return (Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json) }
    catch { return $null }
}

function Write-State {
    param([string]$Label, [bool]$CnEnabled, [string]$Sig, [bool]$TunState, [string[]]$Missing = @(), $B1 = $null)
    New-Item -ItemType Directory -Path (Split-Path $stateFile) -Force | Out-Null
    $b1Obj = $null
    if ($null -ne $B1) {
        $b1Obj = [pscustomobject]@{
            State  = [string]$B1.State
            Detail = [string]$B1.Detail
            Ports  = [int]$B1.Ports
            Shadow = [int]$B1.Shadow
            Caveat = [int]$B1.Caveat
        }
    }
    [pscustomobject]@{
        Version      = '5.5'
        Mode         = $Label
        CnEnabled    = $CnEnabled
        Signature    = $Sig
        MissingRules = $Missing
        TunUp        = $TunState
        B1Guard      = $b1Obj
        Updated      = (Get-Date).ToString('o')
    } | ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding UTF8
}

function Stop-WatchdogTasksAndProcesses {
    $existingTasks = @(Get-ScheduledTask -TaskName 'AI-Guard-Mode-*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty TaskName)
    foreach ($tn in (@('AI-Guard-Mode-Event', 'AI-Guard-Mode-Watcher', 'AI-Guard-Mode-Fallback', 'AI-Guard-Mode-Watchdog') + $existingTasks | Select-Object -Unique)) {
        $t = Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
        if ($t) {
            Stop-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
            Say ('[+] removed scheduled task: ' + $tn)
        }
    }
    foreach ($proc in (Get-WatchdogProcesses)) {
        try {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
            Say ('[+] terminated resident watchdog process pid=' + $proc.ProcessId)
        }
        catch { }
    }
}

function Register-ZeroResidentEventTask([string]$ModeScriptPath, [string]$ExtraFlags = '') {
    # Dual-channel EventTrigger (0 MB idle RAM, 0% idle CPU):
    #   Query 0: Microsoft-Windows-NetworkProfile/Operational (EventID 10000/10001 on TUN or NIC connect/disconnect)
    #   Query 1: System (Power-Troubleshooter 1 / Kernel-Power 107, 507 on S3 Sleep / Hibernate / Modern Standby resume)
    $escapedArgs = [System.Security.SecurityElement]::Escape(
        '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $ModeScriptPath +
        '" -OnNetworkEvent -Quiet -Root "' + $Root + '" -V2rayNRoot "' + $V2rayNRoot +
        '" -TunName "' + $TunName + '" -DnsServer "' + $DnsServer + '"' + $ExtraFlags
    )
    $subQuery = [System.Security.SecurityElement]::Escape(
        "<QueryList>" +
        "<Query Id='0' Path='Microsoft-Windows-NetworkProfile/Operational'>" +
        "<Select Path='Microsoft-Windows-NetworkProfile/Operational'>*[System[Provider[@Name='Microsoft-Windows-NetworkProfile'] and (EventID=10000 or EventID=10001)]]</Select>" +
        "</Query>" +
        "<Query Id='1' Path='System'>" +
        "<Select Path='System'>*[System[(Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and EventID=1) or (Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=107 or EventID=507))]]</Select>" +
        "</Query>" +
        "</QueryList>"
    )
    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>AI-Net-Guard v5.9.4 zero-resident network &amp; sleep-resume event handler (wakes on TUN/NIC connect/disconnect, boot, and standby resume; 0 MB idle RAM).</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>$subQuery</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT2M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>$escapedArgs</Arguments>
    </Exec>
  </Actions>
</Task>
"@
    Register-ScheduledTask -TaskName 'AI-Guard-Mode-Event' -Xml $taskXml -Force | Out-Null
}

function Install-WatchdogTasks {
    # Security boundary (#01): verify install ACL before registering any SYSTEM task directly.
    $aclIssues = @(Get-GuardInstallAclIssues -Path $Root)
    if ($aclIssues.Count -gt 0) {
        throw ('Refusing to register SYSTEM watchdog tasks on untrusted install ACL: ' + ($aclIssues -join '; ') + '. Run 13-harden-acl.ps1 first.')
    }

    $modePath = if (Test-Path (Join-Path (Join-Path $Root 'scripts') '07-mode.ps1')) { Join-Path (Join-Path $Root 'scripts') '07-mode.ps1' } else { Join-Path $Root '07-mode.ps1' }
    if (-not (Test-Path -LiteralPath $modePath)) { throw ('missing: ' + $modePath) }

    Stop-WatchdogTasksAndProcesses

    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $extraFlags = ''
    if ($DisableAutoNodeSync) { $extraFlags += ' -DisableAutoNodeSync' }
    if ($SkipQuarantineAllowRules) { $extraFlags += ' -SkipQuarantineAllowRules' }
    if ($SkipStaleProxyHeal) { $extraFlags += ' -SkipStaleProxyHeal' }

    if ($UseResidentWatchdog) {
        $watchdogPath = if (Test-Path (Join-Path (Join-Path $Root 'scripts') 'watchdog.ps1')) { Join-Path (Join-Path $Root 'scripts') 'watchdog.ps1' } else { Join-Path $Root 'watchdog.ps1' }
        if (-not (Test-Path -LiteralPath $watchdogPath)) { throw ('missing: ' + $watchdogPath) }
        $wAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $watchdogPath + '" -Root "' + $Root + '" -TunName "' + $TunName + '"')
        $wTrigger = New-ScheduledTaskTrigger -AtStartup
        $wSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName 'AI-Guard-Mode-Watcher' -Action $wAction -Trigger $wTrigger `
            -Principal $principal -Settings $wSettings -Force | Out-Null
        Start-ScheduledTask -TaskName 'AI-Guard-Mode-Watcher' -ErrorAction SilentlyContinue
        Say '[+] registered and started resident task: AI-Guard-Mode-Watcher'
    }
    else {
        Register-ZeroResidentEventTask -ModeScriptPath $modePath -ExtraFlags $extraFlags
        Write-MonitorLog 'v5.4 event-triggered monitor installed (NetworkProfile + Sleep/Standby Resume + Boot, 0 MB idle RAM)'
        Say '[+] registered zero-resident event task: AI-Guard-Mode-Event (NetworkProfile 10000/10001 + SleepResume + Boot)'
    }

    # Low-frequency periodic self-heal fallback (default every 60 min; ~90 ms zero-CIM fast check)
    $fbMin = [math]::Max(5, $FallbackMinutes)
    $fAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $modePath + '" -Mode Auto -Quiet -Root "' + $Root + '" -V2rayNRoot "' + $V2rayNRoot + '" -TunName "' + $TunName + '" -DnsServer "' + $DnsServer + '"' + $extraFlags)
    $fTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
        -RepetitionInterval (New-TimeSpan -Minutes $fbMin)
    $fSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -MultipleInstances IgnoreNew -Priority 7
    Register-ScheduledTask -TaskName 'AI-Guard-Mode-Fallback' -Action $fAction -Trigger $fTrigger `
        -Principal $principal -Settings $fSettings -Force | Out-Null
    Say ('[+] registered low-frequency fallback task: AI-Guard-Mode-Fallback (every ' + $fbMin + ' min, zero-CIM fast check)')
}

function Get-B1GuardState {
    # Read-only. Answers one question: is the STUN/TURN block still inside the routing
    # table the core actually loaded?
    #
    # Why a watch for something 18-route-stun-guard.ps1 already writes: 18 runs on demand,
    # and nothing after it re-checks the result. A routing-set switch in the v2rayN UI, a
    # v2rayN update, or a hand edit of the routing table can remove the two guard rules,
    # and every symptom stays hidden: the physical-NIC WFP rules block the same egress, so
    # every probe is still silent, while the core's own re-send - the packet the firewall
    # never sees - sails straight out. 15's header and 18's header both document that the
    # WFP layer cannot close that path; the routing table is the only layer that can. It
    # deserves the same 'detect drift every cycle' treatment the firewall rules get.
    #
    # This function NEVER repairs. -Apply has to rewrite guiNDB.db and refuses to run
    # while v2rayN is up, so repairing from a scheduled task would either be reverted by
    # v2rayN on exit or corrupt the database. Detection plus a loud warning is the whole
    # job; the remediation command is printed with the warning.
    #
    # Placement note: -Status invokes Show-Status before the static-state section, so this
    # function must live above Show-Status, not next to its other caller in Ensure-Guard.
    param([string]$ConfigPath)

    $res = [pscustomobject]@{
        State = 'unknown'; Detail = ''; Ports = 0; PairIndex = -1
        RuleCount = 0; Shadow = 0; Caveat = 0; Config = $ConfigPath
    }
    if (-not $ConfigPath -or -not (Test-Path -LiteralPath $ConfigPath)) {
        $res.State = 'no-config'
        $res.Detail = 'core config has not been written yet'
        return $res
    }
    if (-not (Get-Command Get-StunGuardAnalysis -ErrorAction SilentlyContinue)) {
        $res.State = 'lib-missing'
        $res.Detail = 'lib-stun-guard.ps1 is not loaded'
        return $res
    }

    $ports = @(Get-StunGuardPorts)
    $res.Ports = $ports.Count

    # The analysis costs one ConvertFrom-Json over binConfigs\config.json. Cheap on the
    # hourly fallback, but this task also fires on every network-profile event, and
    # re-parsing an unchanged config buys nothing - so the verdict is cached against
    # (mtime ticks, length) of BOTH files it depends on: the core config and the lib
    # that defines the port set and the verdict logic. Caching on the config alone means
    # an upgraded lib keeps returning the old 'present' verdict off an unchanged config,
    # which is exactly the silent staleness this watch exists to prevent. The fast path
    # is two Get-Item calls plus one small read.
    #
    # Cache line: cfgTicks|cfgLen|libTicks|libLen|state|index|ruleCount|shadow|caveat|detail
    # Old-format lines simply do not match the new 10-field schema and are recomputed.
    $stamp = ''
    $it = Get-Item -LiteralPath $ConfigPath -ErrorAction SilentlyContinue
    $li = if ($libStun) { Get-Item -LiteralPath $libStun -ErrorAction SilentlyContinue } else { $null }
    if ($null -ne $it -and $null -ne $li) {
        $stamp = $it.LastWriteTimeUtc.Ticks.ToString() + '|' + $it.Length.ToString() + '|' +
                 $li.LastWriteTimeUtc.Ticks.ToString() + '|' + $li.Length.ToString()
    }
    if ($stamp -and (Test-Path -LiteralPath $b1Meta)) {
        try {
            # Same UTF-8 codec as the write below. Get-Content -Encoding ASCII would
            # mangle a localised Detail back into '?' on every cache hit.
            $c = [System.IO.File]::ReadAllText($b1Meta, [System.Text.Encoding]::UTF8).Trim()
            if ($c -and $c.StartsWith($stamp + '|')) {
                $p = $c.Split('|', 10)
                if ($p.Count -ge 10) {
                    $res.State = $p[4]
                    $res.PairIndex = [int]$p[5]
                    $res.RuleCount = [int]$p[6]
                    $res.Shadow = [int]$p[7]
                    $res.Caveat = [int]$p[8]
                    $res.Detail = $p[9]
                    return $res
                }
            }
        }
        catch { }
    }

    try {
        $a = Get-StunGuardAnalysis -ConfigPath $ConfigPath -Expected $ports
    }
    catch {
        $res.State = 'error'
        $res.Detail = $_.Exception.Message
        return $res
    }
    $res.State = [string]$a.State
    $res.PairIndex = [int]$a.Index
    $res.RuleCount = if ($a.PSObject.Properties.Name -contains 'RuleCount') { [int]$a.RuleCount } else { 2 }
    $res.Shadow = [int]$a.Shadow
    $res.Caveat = [int]$a.Caveat
    switch ($res.State) {
        'present' {
            if ($res.Shadow -gt 0) {
                $res.Detail = 'rule(s) ahead of the guard pair can swallow STUN traffic: ' + (@($a.ShadowRules) -join '; ')
            }
            elseif ($res.Caveat -gt 0) {
                $res.Detail = 'origin-scoped rule(s) ahead of the pair may bypass it: ' + (@($a.CaveatRules) -join '; ')
            }
        }
        'absent' { $res.Detail = 'no block rule carries the complete STUN/TURN port set' }
        default {
            if ($a.Detail) { $res.Detail = [string]$a.Detail }
        }
    }
    # Normalize '|' before caching AND returning so cold computation and cache hit produce the
    # exact same Detail string (prevents duplicate B1 caveat log lines in watchdog.log).
    $res.Detail = (($res.Detail -replace '[\|\r\n]', ' ') -replace '\s{2,}', ' ').Trim()
    if ($res.Detail.Length -gt 400) { $res.Detail = $res.Detail.Substring(0, 400) }

    if ($stamp) {
        try {
            $line = ($stamp + '|' + $res.State + '|' + $res.PairIndex.ToString() + '|' + $res.RuleCount.ToString() + '|' + $res.Shadow.ToString() + '|' + $res.Caveat.ToString() + '|' + $res.Detail)
            New-Item -ItemType Directory -Path (Split-Path $b1Meta) -Force -ErrorAction SilentlyContinue | Out-Null
            # The install root is locked read-only for Users, so a non-elevated -Status
            # must fail this write SILENTLY into the enclosing catch, not print a red
            # permission error in the middle of a read-only report. WriteAllText throws
            # on failure, which the catch already swallows.
            # UTF-8 WITHOUT BOM, the same API lib-foreign-block.ps1 uses for its meta:
            # -Encoding ASCII flattened localised exception text / rule remarks to '?',
            # and Set-Content -Encoding UTF8 on PS 5.1 emits a BOM that would make the
            # StartsWith(stamp) fast path above miss forever and disable the cache.
            [System.IO.File]::WriteAllText($b1Meta, $line, (New-Object System.Text.UTF8Encoding($false)))
        }
        catch { }
    }
    return $res
}

function Show-Status {
    $activeTuns = @(Get-ActiveTunNamesFast)
    $tunUp = ($activeTuns.Count -gt 0)
    $coreProcs = Get-RunningCoreProcessesFast
    $analysis = Get-FirewallRuleAnalysis
    $ruleStates = $analysis.States

    $tunLabel = if ($tunUp) { 'Up (' + ($activeTuns -join ',') + ')' } else { 'absent (' + $TunName + ')' }
    $coreLabel = if ($coreProcs.Count -gt 0) {
        (($coreProcs | ForEach-Object { $_.ProcessName + ':' + $_.Id }) -join ', ')
    }
    else { 'stopped' }

    Write-Host ''
    Write-Host '=== AI-Net-Guard v5.9.4 Status (read-only) ===' -ForegroundColor Cyan
    Write-Host ('TUN : ' + $tunLabel + '   core : ' + $coreLabel)
    if (Test-Path -LiteralPath $protectedLockFile) {
        Write-Host '  Protected lock    : ACTIVE (backup\protected-lock.flag - Auto tasks keep CN direct disabled)' -ForegroundColor Yellow
    }
    if (Test-Path -LiteralPath $policyFile) {
        $polCol = if ($guardPolicy.PolicyHealth -in @('ok', 'default')) { 'Cyan' } else { 'Yellow' }
        Write-Host ('  policy preset     : ' + $guardPolicy.Preset + ' (guard-policy.json active)') -ForegroundColor $polCol
    }
    if ($guardPolicy.PolicyWarning) {
        $pwCol = if ($guardPolicy.PolicyHealth -eq 'corrupt-fail-closed') { 'Red' } else { 'Yellow' }
        Write-Host ('  POLICY WARNING    : ' + $guardPolicy.PolicyWarning) -ForegroundColor $pwCol
    }

    foreach ($pr in (Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        $ok = ($pr.Enabled -and $pr.DefaultOutboundAction -eq 'Block')
        Write-Host ('  profile {0,-8} : Enabled={1} DefaultOutbound={2}' -f $pr.Name, $pr.Enabled, $pr.DefaultOutboundAction) `
            -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
    }

    if (-not $guardPolicy.AllowCnDirect) {
        $cnActive = ($ruleStates.ContainsKey($cnRuleName) -and $ruleStates[$cnRuleName])
        Write-Host ('  rule {0,-24} : active={1} (disabled by policy - strict global lock)' -f $cnRuleName, $cnActive) `
            -ForegroundColor $(if (-not $cnActive) { 'Cyan' } else { 'Yellow' })
    }
    elseif ($ruleStates.ContainsKey($cnRuleName)) {
        $cnActive = $ruleStates[$cnRuleName]
        $sigInfo = ''
        if (Test-Path -LiteralPath $cnSig) {
            $rawSig = (Get-Content -LiteralPath $cnSig -Raw -Encoding UTF8 -ErrorAction SilentlyContinue).Trim()
            if ($rawSig -match '^(\d+):') { $sigInfo = ' (prefixes=' + $matches[1] + ')' }
        }
        Write-Host ('  rule {0,-24} : active={1}{2}' -f $cnRuleName, $cnActive, $sigInfo) `
            -ForegroundColor $(if ($cnActive) { 'Green' } else { 'Yellow' })
    }
    else {
        Write-Host ('  rule {0,-24} : ABSENT' -f $cnRuleName) -ForegroundColor Red
    }

    $displayRules = @('AI-Guard-Allow-TUN', 'AI-Guard-Allow-Node-TCP', 'AI-Guard-Allow-DoH-Ali', 'AI-Guard-Allow-DHCP', 'AI-Guard-Allow-LAN')
    if ($ruleStates.ContainsKey('AI-Guard-Allow-Node-UDP')) { $displayRules += 'AI-Guard-Allow-Node-UDP' }
    if ($ruleStates.ContainsKey('AI-Guard-Allow-TUN-Alt')) { $displayRules += 'AI-Guard-Allow-TUN-Alt' }
    $displayRules += 'AI-Guard-Allow-NCSI'
    $displayRules += 'AI-Guard-Block-Foreign-Physical'
    $displayRules += 'AI-Guard-Block-Foreign-Physical-IPv6'

    foreach ($rn in $displayRules) {
        $optDisabled = ($rn -eq 'AI-Guard-Allow-LAN' -and -not $guardPolicy.AllowLan) -or
                       ($rn -eq 'AI-Guard-Allow-NCSI' -and -not $guardPolicy.AllowNcsi) -or
                       ($rn -eq 'AI-Guard-Block-Foreign-Physical-IPv6' -and -not $guardPolicy.DisablePhysicalIpv6)
        if ($ruleStates.ContainsKey($rn)) {
            $act = $ruleStates[$rn]
            $extra = ''
            if ($rn -in @('AI-Guard-Allow-Node-TCP', 'AI-Guard-Allow-Node-UDP') -and $analysis.RawByRule.ContainsKey($rn)) {
                $rv = $analysis.RawByRule[$rn]
                $rips = @([regex]::Matches($rv, '(?:^|\|)RA4=([^|]+)') | ForEach-Object { $_.Groups[1].Value }) -join ','
                $rpts = @([regex]::Matches($rv, '(?:^|\|)RPort=([^|]+)') | ForEach-Object { $_.Groups[1].Value }) -join ','
                $rapp = ''
                if ($rv -match '(?:^|\|)App=([^|]+)') { $rapp = ', core=' + (Split-Path -Leaf $matches[1]) }
                $syncTxt = if ($DisableAutoNodeSync) { ', auto-sync=off' } else { ', auto-sync=on' }
                if ($rips) { $extra = ' (' + $rips + ':' + $rpts + $rapp + $syncTxt + ')' }
            }
            elseif ($optDisabled -and -not $act) {
                $extra = ' (disabled by policy)'
            }
            $col = if ($act) { 'Green' } elseif ($optDisabled) { 'DarkGray' } else { 'Red' }
            Write-Host ('  rule {0,-24} : active={1}{2}' -f $rn, $act, $extra) -ForegroundColor $col
        }
        elseif ($rn -eq 'AI-Guard-Allow-NCSI' -or $optDisabled) {
            Write-Host ('  rule {0,-24} : not installed (disabled by policy)' -f $rn) -ForegroundColor DarkGray
        }
        else {
            Write-Host ('  rule {0,-24} : MISSING' -f $rn) -ForegroundColor Red
        }
    }

    # B1 routing-table guard (18-route-stun-guard.ps1). Read-only line: the fix requires
    # v2rayN to be closed, so it is reported, not repaired, everywhere it is checked.
    $b1 = if ($script:B1State) { $script:B1State } else { Get-B1GuardState (Join-Path $V2rayNRoot 'binConfigs\config.json') }
    $b1Col = 'Red'; $b1Txt = ''
    switch ($b1.State) {
        'present' {
            $b1Col = 'Green'
            $ruleLocTxt = if ($b1.RuleCount -eq 1) { 'routing rule #' + $b1.PairIndex } else { 'routing rules #' + $b1.PairIndex + ' and #' + ($b1.PairIndex + 1) }
            $b1Txt = 'loaded (' + $b1.Ports + ' ports, udp+tcp, ' + $ruleLocTxt + ')'
            if ($b1.Shadow -gt 0) {
                $b1Col = 'Yellow'
                $b1Txt += ' - SHADOWED by a preceding rule'
            }
            elseif ($b1.Caveat -gt 0) {
                $b1Col = 'Yellow'
                $b1Txt += ' - caveat: origin-scoped rule ahead may bypass it'
            }
        }
        'no-config' { $b1Col = 'DarkGray'; $b1Txt = 'unknown (core config not written yet - start v2rayN once)' }
        'lib-missing' { $b1Txt = 'cannot check (lib-stun-guard.ps1 missing)' }
        default {
            $b1Txt = $b1.State + ' - ' + $b1.Detail
        }
    }
    Write-Host ('  B1 route guard    : ' + $b1Txt) -ForegroundColor $b1Col
    if ($b1.State -notin @('present', 'no-config')) {
        Write-Host '                      fix: close v2rayN, then run scripts\18-route-stun-guard.ps1 -Apply' -ForegroundColor DarkGray
    }

    $rogueCnt = $analysis.RogueOutboundAllows.Count
    if ($rogueCnt -eq 0) {
        Write-Host '  rogue out-allow   : 0 (clean - no unapproved outbound allow rules)' -ForegroundColor Green
    }
    elseif (-not $guardPolicy.QuarantineRogueAllow) {
        Write-Host ('  rogue out-allow   : ' + $rogueCnt + ' active (quarantine disabled by user policy)') -ForegroundColor Yellow
    }
    else {
        $rNames = ($analysis.RogueOutboundAllows | Select-Object -First 5 | ForEach-Object { $_.DisplayName }) -join ', '
        Write-Host ('  rogue out-allow   : ' + $rogueCnt + ' active (' + $rNames + ') - run .\07-mode.ps1 to auto-quarantine') -ForegroundColor Red
    }

    $aclIssues = @(Get-InstallAclIssues -Path $Root)
    if ($aclIssues.Count -eq 0) {
        Write-Host '  install ACL       : locked (owner=Administrators, Users=read-only)' -ForegroundColor Green
    }
    elseif (-not $guardPolicy.HardenInstallAcl) {
        Write-Host ('  install ACL       : unlocked by user policy (' + $aclIssues.Count + ' writable ACEs)') -ForegroundColor Yellow
    }
    else {
        Write-Host ('  install ACL       : WRITABLE by non-admin (' + $aclIssues.Count + ' issue(s), e.g. ' + $aclIssues[0] + ') - run .\13-harden-acl.ps1') -ForegroundColor Red
    }

    foreach ($ni in @(Get-ActivePhysicalNicsFast)) {
        $v4Dns = @($ni.GetIPProperties().DnsAddresses |
            Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
            ForEach-Object { $_.IPAddressToString }) -join ','
        $v6On = $ni.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv6)
        Write-Host ('  NIC  {0,-12} : DNS={1}  IPv6Active={2}' -f $ni.Name, $v4Dns, $v6On)
    }

    $dnsPol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
    $dnsSvc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -ErrorAction SilentlyContinue
    $llmnrOff = ($dnsPol -and $dnsPol.EnableMulticast -eq 0)
    $mdnsOff = ($dnsSvc -and $dnsSvc.EnableMDNS -eq 0)
    $smhnrOff = ($dnsPol -and $dnsPol.DisableSmartNameResolution -eq 1)
    Write-Host ('  DNS leak-shield   : LLMNR={0}  mDNS={1}  SMHNR={2}' -f $(if ($llmnrOff) { 'off' } else { 'ON' }), $(if ($mdnsOff) { 'off' } else { 'ON' }), $(if ($smhnrOff) { 'off' } else { 'pending (auto-applies on next event or .\07-mode.ps1)' }))
    $wrtcUdp = Get-GuardRule 'AI-Guard-Block-WebRTC-UDP'
    $wrtcTcp = Get-GuardRule 'AI-Guard-Block-WebRTC-TCP'
    $cProps = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome' -ErrorAction SilentlyContinue
    $eProps = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -ErrorAction SilentlyContinue
    $cPol = if ($cProps) { $cProps.WebRtcIPHandlingPolicy } else { $null }
    $ePol = if ($eProps) { $eProps.WebRtcIPHandlingPolicy } else { $null }
    $cDoh = if ($cProps) { $cProps.DnsOverHttpsMode } else { $null }
    $eDoh = if ($eProps) { $eProps.DnsOverHttpsMode } else { $null }
    $wrtcFwOk = ($wrtcUdp -and $wrtcUdp.Enabled -eq 'True' -and $wrtcTcp -and $wrtcTcp.Enabled -eq 'True')
    $wrtcPolOk = ($cPol -eq 'disable_non_proxied_udp' -and $ePol -eq 'disable_non_proxied_udp')
    $dohOffOk = ($cDoh -eq 'off' -and $eDoh -eq 'off')
    $wrtcStatus = if ($wrtcFwOk -and $wrtcPolOk) { 'ACTIVE (FW+browser policy)' } elseif ($wrtcFwOk) { 'FW only (browser policy missing)' } elseif ($wrtcPolOk) { 'browser policy only (FW rules missing)' } else { 'MISSING - run 02-killswitch.ps1' }
    $wrtcColor = if ($wrtcFwOk -and $wrtcPolOk) { 'Green' } elseif ($wrtcFwOk -or $wrtcPolOk) { 'Yellow' } else { 'Red' }
    Write-Host ('  WebRTC leak-shield: {0}  BrowserDoH={1}' -f $wrtcStatus, $(if ($dohOffOk) { 'off' } else { 'default' })) -ForegroundColor $wrtcColor

    $v4pol = Get-NetPrefixPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Prefix -eq '::ffff:0:0/96' } | Select-Object -First 1
    $v6pol = Get-NetPrefixPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Prefix -eq '::/0' } | Select-Object -First 1
    if ($v4pol -and $v6pol) {
        $preferV4 = ($v4pol.Precedence -gt $v6pol.Precedence)
        Write-Host ('  IPv4 precedence   : ::ffff:0:0/96={0} vs ::/0={1} (preferIPv4={2})' -f $v4pol.Precedence, $v6pol.Precedence, $preferV4)
    }

    $modeTasks = @(Get-ScheduledTask -TaskName 'AI-Guard-Mode-*' -ErrorAction SilentlyContinue)
    if ($modeTasks.Count -eq 0) {
        if ($script:ReadOnlyStatusMode) {
            Write-Host '  monitor tasks     : inconclusive (non-elevated session cannot enumerate SYSTEM tasks; verify elevated or via 17-autorepair-task.ps1)' -ForegroundColor Yellow
            $prevSt = Read-PrevState
            if ($prevSt -and $prevSt.Updated) {
                Write-Host ('                      (last mode-state.json update: ' + $prevSt.Updated + ')') -ForegroundColor DarkGray
            }
        }
        else {
            Write-Host '  monitor tasks     : none registered (run .\07-mode.ps1 -InstallTasks)' -ForegroundColor Yellow
        }
    }
    else {
        foreach ($t in $modeTasks) {
            Write-Host ('  task {0,-24} : {1}' -f $t.TaskName, $t.State)
        }
    }

    $wd = Get-WatchdogProcesses
    if ($wd.Count -gt 0) {
        Write-Host ('  resident process  : running (pid=' + (($wd | ForEach-Object { $_.ProcessId }) -join ',') + ') - run .\07-mode.ps1 -InstallTasks to switch to 0-MB event mode') -ForegroundColor Yellow
    }
    else {
        Write-Host '  resident process  : none (0 MB background RAM - event-triggered mode)' -ForegroundColor Green
    }

    $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($ie -and $ie.ProxyEnable -eq 1) {
        if ($coreProcs.Count -eq 0) {
            Write-Host ('  WARNING: HKCU system proxy is ON (' + $ie.ProxyServer + ') while proxy core is stopped! Run .\07-mode.ps1 to auto-clear dead proxy.') -ForegroundColor Red
        }
        else {
            Write-Host ('  NOTE: HKCU system proxy is ON (' + $ie.ProxyServer + '). Turn off system proxy in v2rayN if you want TUN toggle alone to control all proxy access.') -ForegroundColor Yellow
        }
    }
}

function Invoke-UpgradeV54 {
    Say '[+] upgrading live installation in-place to AI-Net-Guard v5.9.4 (zero-resident + multi-core + SMHNR-off + sleep-resume)...'

    # 1. Backfill new rollback fields into existing DNS baseline JSON without altering original values
    $bf = Join-Path $Root 'backup\baseline.json'
    $dnsJsonPath = $null
    if (Test-Path -LiteralPath $bf) {
        try { $dnsJsonPath = (Get-Content -LiteralPath $bf -Raw -Encoding UTF8 | ConvertFrom-Json).Dns } catch { }
    }
    if (-not $dnsJsonPath) {
        $oldestDns = Get-ChildItem -Path (Join-Path $Root 'backup') -Filter 'dns-*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -First 1
        if ($oldestDns) { $dnsJsonPath = $oldestDns.FullName }
    }

    $tcpip6Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
    $curDisabled = $null
    if (Test-Path -LiteralPath $tcpip6Key) {
        $curDisabled = (Get-ItemProperty -LiteralPath $tcpip6Key -ErrorAction SilentlyContinue).DisabledComponents
    }
    $curPol = Get-NetPrefixPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Prefix -eq '::ffff:0:0/96' } | Select-Object -First 1
    $w32Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
    $curNtp = if (Test-Path -LiteralPath $w32Key) { (Get-ItemProperty -LiteralPath $w32Key -ErrorAction SilentlyContinue).NtpServer } else { $null }

    if ($dnsJsonPath -and (Test-Path -LiteralPath $dnsJsonPath)) {
        try {
            $db = Get-Content -LiteralPath $dnsJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $dbChanged = $false
            if ($db.PSObject.Properties.Name -notcontains 'Tcpip6DisabledComponents') {
                $db | Add-Member -NotePropertyName 'Tcpip6DisabledComponents' -NotePropertyValue $curDisabled -Force
                $dbChanged = $true
            }
            if ($db.PSObject.Properties.Name -notcontains 'Ipv4PrefixPolicy' -and $curPol) {
                $db | Add-Member -NotePropertyName 'Ipv4PrefixPolicy' -NotePropertyValue ([pscustomobject]@{ Precedence = [int]$curPol.Precedence; Label = [int]$curPol.Label }) -Force
                $dbChanged = $true
            }
            if ($db.PSObject.Properties.Name -notcontains 'NtpServer') {
                $db | Add-Member -NotePropertyName 'NtpServer' -NotePropertyValue $curNtp -Force
                $dbChanged = $true
            }
            if ($dbChanged) {
                $db | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $dnsJsonPath -Encoding UTF8
                Say ('    backfilled rollback metadata into ' + (Split-Path -Leaf $dnsJsonPath))
            }
        }
        catch { }
    }

    Backfill-DnsBaselineV54
    Set-SmhnrHardening
    Say '    Smart Multi-Homed Name Resolution disabled (DisableSmartNameResolution=1)'

    # 2. Persist IPv4-over-IPv6 preference (DisabledComponents |= 0x20 + live prefix policy)
    try {
        $newVal = if ($null -ne $curDisabled) { ([int]$curDisabled -bor 0x20) } else { 0x20 }
        if (-not (Test-Path -LiteralPath $tcpip6Key)) {
            New-Item -Path $tcpip6Key -Force | Out-Null
        }
        New-ItemProperty -Path $tcpip6Key -Name 'DisabledComponents' -Value $newVal -PropertyType DWord -Force | Out-Null
        netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 50 4 | Out-Null
        Say '    IPv4 precedence persisted (DisabledComponents|=0x20, ::ffff:0:0/96=50)'
    }
    catch { }

    # 3. Ensure domestic-capable NTP for VLESS+REALITY clock stability
    try {
        # Healthy = names a known-working domestic peer and no longer carries the dead www.time.ac.cn.
        if (([string]$curNtp) -notmatch '(?i)(aliyun|tencent|ntsc\.ac\.cn|203\.107\.6\.88)' -or ([string]$curNtp) -match '(?i)www\.time\.ac\.cn') {
            $newNtp = 'ntp.aliyun.com,0x9 ntp.tencent.com,0x9 ntp.ntsc.ac.cn,0x9'
            New-ItemProperty -Path $w32Key -Name 'NtpServer' -Value $newNtp -PropertyType String -Force | Out-Null
            $w32svc = Get-Service -Name w32time -ErrorAction SilentlyContinue
            if ($w32svc -and $w32svc.Status -eq 'Running') { w32tm /config /update 2>$null | Out-Null; w32tm /resync /nowait 2>$null | Out-Null }
            Say ('    NTP updated to domestic peers: ' + $newNtp)
        }
        else {
            Say ('    NTP already domestic-capable: ' + $curNtp)
        }
    }
    catch { }

    # 4. Relax static InterfaceAlias locks on companion rules so hot-plugged USB NICs work automatically
    foreach ($rn in @('AI-Guard-Allow-Node-TCP', 'AI-Guard-Allow-Node-UDP', 'AI-Guard-Allow-DoH-Ali', 'AI-Guard-Allow-DHCP', 'AI-Guard-Allow-LAN')) {
        $rules = @(Get-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue)
        foreach ($r in $rules) {
            try {
                $ifAlias = @(($r | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue).InterfaceAlias)
                if ($ifAlias.Count -gt 0 -and ($ifAlias -notcontains 'Any')) {
                    Set-NetFirewallRule -InputObject $r -InterfaceAlias 'Any' -ErrorAction Stop
                    Say ('    unlocked InterfaceAlias -> Any on ' + $rn + ' (hot-plug ready)')
                }
            }
            catch { }
        }
    }

    # 5. Add AI-Guard-Allow-NCSI (HTTP 80 to 13.107.4.52) if missing
    $ncsi = Get-NetFirewallRule -DisplayName 'AI-Guard-Allow-NCSI' -ErrorAction SilentlyContinue
    if (-not $ncsi) {
        New-NetFirewallRule -Name 'AI-Guard-Allow-NCSI' -DisplayName 'AI-Guard-Allow-NCSI' `
            -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress '13.107.4.52' -RemotePort @('80') `
            -Profile Any -Enabled True `
            -Description 'Windows NCSI connecttest.txt HTTP-80 probe (prevents false No-Internet globe when TUN is off).' | Out-Null
        Say '    installed AI-Guard-Allow-NCSI (13.107.4.52:80)'
    }

    New-Item -ItemType Directory -Path (Split-Path $v54Flag) -Force | Out-Null
    Set-Content -LiteralPath $v54Flag -Value (Get-Date).ToString('o') -Encoding ASCII
}

# ---------------------------------------------------------------- task / status dispatch
if ($Status) {
    Show-Status
    exit 0
}

$scriptExitCode = 0
$handledEarly = $false
$modeWriteLock = Enter-GuardWriteLock -TimeoutMs 30000
try {
    # Security boundary (#03): re-read policy inside the cross-process write lock so every
    # mutating decision observes the latest committed guard-policy.json.
    $script:guardPolicy = Get-GuardPolicy
    Apply-GuardPolicyToScriptVars
    $requiredRules = @('AI-Guard-Allow-TUN', 'AI-Guard-Allow-Node-TCP', 'AI-Guard-Allow-DoH-Ali', 'AI-Guard-Allow-DHCP')
    if ($guardPolicy.AllowLan) { $requiredRules += 'AI-Guard-Allow-LAN' }

    if ($ClearProtectedLock -and (Test-Path -LiteralPath $protectedLockFile)) {
        Remove-Item -LiteralPath $protectedLockFile -Force -ErrorAction SilentlyContinue
        Write-MonitorLog 'cleared Protected mode lock (backup\protected-lock.flag removed)'
        Say '[+] cleared Protected mode lock'
    }

    if ($RemoveTasks) {
        try { Stop-WatchdogTasksAndProcesses }
        catch { Write-Host ('[!] task removal error: ' + $_.Exception.Message) -ForegroundColor Red }
        $leftTasks = @(Get-ScheduledTask -TaskName 'AI-Guard-Mode-*' -ErrorAction SilentlyContinue)
        if ($leftTasks.Count -gt 0) {
            Write-Host ('[!] still registered: ' + (($leftTasks | ForEach-Object { $_.TaskName }) -join ', ')) -ForegroundColor Red
            Write-Host '    this normally means the shell is not elevated (tasks are owned by SYSTEM).' -ForegroundColor Yellow
            $scriptExitCode = 3
        }
        $handledEarly = $true
    }
    elseif ($InstallTasks) {
        # Registration errors are non-terminating under ErrorActionPreference=Continue,
        # so success must be proven by reading the tasks back, not by the absence of an
        # exception. A non-zero exit here is what 14-apply-policy.ps1 and
        # 17-autorepair-task.ps1 report as a failure.
        try { Install-WatchdogTasks }
        catch {
            Write-Host ('[!] task registration failed: ' + $_.Exception.Message) -ForegroundColor Red
            $scriptExitCode = 3
            $handledEarly = $true
        }
        if (-not $handledEarly) {
            $evOk = Get-ScheduledTask -TaskName 'AI-Guard-Mode-Event' -ErrorAction SilentlyContinue
            $wdOk = Get-ScheduledTask -TaskName 'AI-Guard-Mode-Watcher' -ErrorAction SilentlyContinue
            $fbOk = Get-ScheduledTask -TaskName 'AI-Guard-Mode-Fallback' -ErrorAction SilentlyContinue
            if (-not $fbOk -or (-not $evOk -and -not $wdOk)) {
                Write-Host ('[!] task registration incomplete (event=' + [bool]$evOk + ', watcher=' + [bool]$wdOk + ', fallback=' + [bool]$fbOk + ')') -ForegroundColor Red
                Write-Host '    this normally means the shell is not elevated (tasks run as SYSTEM).' -ForegroundColor Yellow
                $scriptExitCode = 3
            }
            $handledEarly = $true
        }
    }

    if (-not $handledEarly) {
        if ($Upgrade) {
            Invoke-UpgradeV54
        }

        if ($OnNetworkEvent) {
            # Brief settle so Wintun interface bring-up finishes reaching OperationalStatus=Up
            Start-Sleep -Milliseconds 350
        }

        # ---------------------------------------------------------------- geo refresh (fast timestamp check)
        $geoFile = Join-Path $V2rayNRoot 'bin\geoip-only-cn-private.dat'
        if (-not (Test-Path -LiteralPath $geoFile)) { $geoFile = Join-Path $V2rayNRoot 'bin\geoip.dat' }
        $refresher = if (Test-Path (Join-Path (Join-Path $Root 'scripts') '11-geo-cn.ps1')) { Join-Path (Join-Path $Root 'scripts') '11-geo-cn.ps1' } else { Join-Path $Root '11-geo-cn.ps1' }
        if ((Test-Path -LiteralPath $refresher) -and
            ((-not (Test-Path -LiteralPath $cnList)) -or ((Test-Path -LiteralPath $geoFile) -and ((Get-Item -LiteralPath $geoFile).LastWriteTimeUtc -gt (Get-Item -LiteralPath $cnList).LastWriteTimeUtc)))) {
            try { & $refresher -Root $Root -V2rayNRoot $V2rayNRoot -GeoFile $geoFile -OutFile $cnList -Quiet }
            catch { Say ('    CN list refresh failed (keeping old list): ' + $_.Exception.Message) }
        }
    }

# ---------------------------------------------------------------- static state (zero-CIM fast path when healthy)
function Test-ShieldDriftFast($Analysis, $PhysNics) {
    # Decides whether 15-webrtc-browser-shield.ps1 has anything to repair, using only the
    # registry snapshot already collected in $Analysis.RawByRule plus file / process
    # existence.  Spawning that script costs a second PowerShell start-up and a second full
    # rule enumeration; on a healthy host it used to run on every single self-check.
    #
    # Anything that cannot be positively verified counts as drift.  A wrong "clean" would
    # skip a repair and leave a leak path open, which is exactly the silent failure this
    # guard exists to prevent; a wrong "drift" only costs one extra repair run.
    # $stunPorts is the script-scope copy from lib-stun-guard.ps1 (single definition).

    if ($null -eq $Analysis -or $null -eq $Analysis.RawByRule) { return $true }
    $raw = $Analysis.RawByRule

    # Mirror 15's own definition of "physical NIC" exactly. A looser set here would demand
    # coverage of an adapter that 15 never adds and turn every check into a false drift.
    # NetworkInterface.Id already carries its braces: '{A2AF782E-...}'.  Normalise to one
    # braced form here so the registry pattern below can compare it verbatim (adding a
    # second pair of braces made every comparison fail and forced a repair run each time).
    $nicIds = @($PhysNics | Where-Object {
            $_ -and
            ($_.Description -notmatch '(?i)Wintun|sing-tun|Mihomo|TAP-Windows|Loopback') -and
            ($_.Name -notmatch '(?i)loopback') -and
            ($knownTunNames -notcontains $_.Name)
        } | ForEach-Object { '{' + ([string]$_.Id).Trim('{', '}') + '}' })
    if ($nicIds.Count -eq 0) { return $true }

    # every installed browser must own a program-scoped UDP block
    $browsers = @{}
    foreach ($cand in @(
            @{ Tag = 'Chrome'; Exe = (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe') },
            @{ Tag = 'Chrome'; Exe = (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe') },
            @{ Tag = 'Edge'; Exe = (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe') },
            @{ Tag = 'Edge'; Exe = (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe') }
        )) {
        if ($cand.Exe -and (Test-Path -LiteralPath $cand.Exe)) { $browsers[$cand.Tag] = $true }
    }
    if ($browsers.Count -eq 0) { return $true }

    foreach ($tag in @($browsers.Keys)) {
        $n = 'AI-Guard-Block-WebRTC-' + $tag + '-PhysUDP'
        if (-not $raw.ContainsKey($n)) { return $true }
        $s = [string]$raw[$n]
        if ($s -notmatch '(^|\|)Active=TRUE(\||$)') { return $true }
        if ($s -notmatch '(^|\|)Action=Block(\||$)') { return $true }
        if ($s -notmatch '(^|\|)Dir=Out(\||$)') { return $true }
        foreach ($gid in $nicIds) {
            if ($s -notmatch ('(?i)(^|\|)IF=' + [regex]::Escape($gid) + '(\||$)')) { return $true }
        }
    }

    # tunnel core tags: live process first, otherwise the path the guard's own Allow rules
    # already recorded (the core is stopped while v2rayN is closed, and the rules must
    # still match it when it comes back)
    $coreTags = @()
    foreach ($pn in @('xray', 'sing-box', 'mihomo', 'mihomo-windows-amd64-v1')) {
        if (@(Get-Process -Name $pn -ErrorAction SilentlyContinue).Count -gt 0) {
            if ($coreTags -notcontains $pn) { $coreTags += $pn }
        }
    }
    if ($coreTags.Count -eq 0) {
        foreach ($k in @('AI-Guard-Allow-Node-TCP', 'AI-Guard-Allow-Core-Xray-TCP', 'AI-Guard-Allow-Core-SingBox-TCP',
                'AI-Guard-Allow-Core-mihomo-TCP', 'AI-Guard-Allow-Core-mihomo-windows-amd64-v1-TCP')) {
            if (-not $raw.ContainsKey($k)) { continue }
            $s = [string]$raw[$k]
            if ($s -match '(?i)(^|\|)App=([^|]*?(?:xray|sing-box|mihomo)[^|]*?\.exe)') {
                $t = [System.IO.Path]::GetFileNameWithoutExtension($Matches[2])
                if ($t -and ($coreTags -notcontains $t)) { $coreTags += $t }
            }
        }
    }
    if ($coreTags.Count -eq 0) { return $true }

    foreach ($t in $coreTags) {
        foreach ($proto in @('UDP', 'TCP')) {
            $n = 'AI-Guard-Block-WebRTC-' + $t + '-CoreSTUN-' + $proto
            if (-not $raw.ContainsKey($n)) { return $true }
            $s = [string]$raw[$n]
            if ($s -notmatch '(^|\|)Active=TRUE(\||$)') { return $true }
            if ($s -notmatch '(^|\|)Action=Block(\||$)') { return $true }
            if ($s -notmatch '(^|\|)Dir=Out(\||$)') { return $true }
            foreach ($gid in $nicIds) {
                if ($s -notmatch ('(?i)(^|\|)IF=' + [regex]::Escape($gid) + '(\||$)')) { return $true }
            }
            foreach ($sp in $stunPorts) {
                if ($s -notmatch ('(^|\|)RPort=' + $sp + '(\||$)')) { return $true }
            }
        }
    }

    # a CoreSTUN rule for a core that no longer exists has to be swept away
    foreach ($k in @($raw.Keys)) {
        if ($k -notmatch '^AI-Guard-Block-WebRTC-(.+)-CoreSTUN-(?:UDP|TCP)$') { continue }
        if ($coreTags -notcontains $Matches[1]) { return $true }
    }

    return $false
}

function Ensure-Guard {
    $script:missingRules = @()
    $script:repairedItems = @()
    $script:B1State = $null

    # 0. One-time zero-touch v5.4 hot-migration (<0.2 ms Test-Path after first run)
    if (-not (Test-Path -LiteralPath $v54Flag)) {
        try {
            Backfill-DnsBaselineV54
            Set-SmhnrHardening -DisableLlmnr ([bool]$guardPolicy.DisableLlmnrNetbios) -DisableSmhnr ([bool]$guardPolicy.DisableSmhnr)
            $evTask = Get-ScheduledTask -TaskName 'AI-Guard-Mode-Event' -ErrorAction SilentlyContinue
            if ($evTask) {
                $modePath = if (Test-Path (Join-Path (Join-Path $Root 'scripts') '07-mode.ps1')) { Join-Path (Join-Path $Root 'scripts') '07-mode.ps1' } else { Join-Path $Root '07-mode.ps1' }
                $ef = ''
                if ($DisableAutoNodeSync) { $ef += ' -DisableAutoNodeSync' }
                if ($SkipQuarantineAllowRules) { $ef += ' -SkipQuarantineAllowRules' }
                if ($SkipStaleProxyHeal) { $ef += ' -SkipStaleProxyHeal' }
                Register-ZeroResidentEventTask -ModeScriptPath $modePath -ExtraFlags $ef
            }
            New-Item -ItemType Directory -Path (Split-Path $v54Flag) -Force | Out-Null
            Set-Content -LiteralPath $v54Flag -Value (Get-Date).ToString('o') -Encoding ASCII
            $script:repairedItems += 'v54-hot-migrated(SMHNR+sleep-trigger)'
            Say '    applied v5.4 hot-migration (SMHNR disabled + sleep-resume trigger enabled)'
        }
        catch { }
    }

    # 1. default deny (<1 ms registry check; loads NetSecurity CIM only if drifted)
    if (-not (Test-FirewallProfilesHealthyFast)) {
        $prof = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.DefaultOutboundAction -ne 'Block' -or -not $_.Enabled })
        if ($prof.Count -gt 0) {
            Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultOutboundAction Block -Enabled True
            $script:repairedItems += 'profiles->Block'
            Say '    repaired: default outbound -> Block'
        }
    }

    # 2. legacy rules of the old design, once (<0.5 ms Test-Path after first run)
    $flag = Join-Path $Root 'backup\legacy-rules-cleaned-v51.flag'
    if (-not (Test-Path -LiteralPath $flag)) {
        $legacy = @(Get-NetFirewallRule -DisplayName 'AI-Guard-Block-DNS-*' -ErrorAction SilentlyContinue) +
                  @(Get-NetFirewallRule -DisplayName 'AI-Guard-Block-DoT' -ErrorAction SilentlyContinue) +
                  @(Get-NetFirewallRule -DisplayName 'AI-Guard-Block-AI-Direct' -ErrorAction SilentlyContinue)
        if ($legacy.Count -gt 0) { $legacy | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path (Split-Path $flag) -Force | Out-Null
        Set-Content -LiteralPath $flag -Value (Get-Date).ToString('o') -Encoding ASCII
        Remove-Item -LiteralPath (Join-Path $Root 'backup\legacy-rules-cleaned.flag') -Force -ErrorAction SilentlyContinue
    }

    # 3. single-pass registry rule audit (~80 ms, zero CIM)
    $analysis = Get-FirewallRuleAnalysis
    $ruleStates = $analysis.States
    $cnExists = $ruleStates.ContainsKey($cnRuleName)
    $cnActive = ($cnExists -and $ruleStates[$cnRuleName])

    # 3b. auto-quarantine rogue non-AI-Guard Outbound Allow rules added by third-party installers
    # Also self-heal any legacy PS 5.1 nested { value, Count } quarantine JSON on disk.
    if (-not $SkipQuarantineAllowRules -and (($analysis.RogueOutboundAllows.Count -gt 0) -or (Test-Path -LiteralPath $quarantineFile))) {
        $qRead = Read-GuardQuarantineList -Path $quarantineFile
        $qList = New-Object System.Collections.Generic.List[object]
        $existingKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($qItem in @($qRead.Items)) {
            if ($qItem -and $qItem.Name -and $existingKeys.Add([string]$qItem.Name)) {
                $qList.Add($qItem)
            }
        }
        $qChanged = [bool]$qRead.NeedsRewrite
        $qDisabled = 0
        foreach ($rog in $analysis.RogueOutboundAllows) {
            if ($existingKeys.Add([string]$rog.Key)) {
                $qList.Add([pscustomobject]@{
                    Name          = $rog.Key
                    DisplayName   = $rog.DisplayName
                    QuarantinedAt = (Get-Date).ToString('o')
                })
                $qChanged = $true
            }
            try {
                Disable-NetFirewallRule -Name $rog.Key -ErrorAction Stop
                $qDisabled++
                Say ('    quarantined unapproved outbound allow rule: ' + $rog.DisplayName)
            }
            catch { }
        }
        if ($qChanged) {
            Write-GuardQuarantineList -Path $quarantineFile -Items ([object[]]$qList.ToArray())
        }
        if ($qDisabled -gt 0) {
            $script:repairedItems += ('quarantined-outbound-allow(' + $qDisabled + ')')
        }
    }

    # 3c. hands-free multi-core automatic node sync (<0.3 ms 0-CIM fast path when config.json is unchanged)
    Sync-NodeRuleFast -Analysis $analysis

    # 3d. multi-core dynamic TUN interface rule (e.g. singbox_tun / mihomo_tun / xray_tun)
    # Also enforce TUN-only LocalAddress scope AND explicit AI-Guard-Block-PhysicalIP-On-TUN
    # (overrides Xray TUN's "permit through the TUN" WFP soft-permit when a socket binds a physical NIC subnet).
    # Prune dead/orphaned interface GUIDs whenever live TUN adapters are present.
    $rawMainTun = if ($analysis.RawByRule.ContainsKey('AI-Guard-Allow-TUN')) { [string]$analysis.RawByRule['AI-Guard-Allow-TUN'] } else { '' }
    $rawAltTun = if ($analysis.RawByRule.ContainsKey('AI-Guard-Allow-TUN-Alt')) { [string]$analysis.RawByRule['AI-Guard-Allow-TUN-Alt'] } else { '' }
    $rawBlkPhysTun = if ($analysis.RawByRule.ContainsKey('AI-Guard-Block-PhysicalIP-On-TUN')) { [string]$analysis.RawByRule['AI-Guard-Block-PhysicalIP-On-TUN'] } else { '' }
    $blkPhysTunActive = ($ruleStates.ContainsKey('AI-Guard-Block-PhysicalIP-On-TUN') -and $ruleStates['AI-Guard-Block-PhysicalIP-On-TUN'])
    $activeTunObjs = New-Object System.Collections.Generic.List[object]
    $physIpsForTunBlock = New-Object System.Collections.Generic.List[string]
    $physNicsForTunBlock = New-Object System.Collections.Generic.List[object]
    $allLiveNicIds = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    try {
        foreach ($ni in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($ni.Id) { [void]$allLiveNicIds.Add('{' + ([string]$ni.Id).Trim('{', '}') + '}') }
            if ($ni.OperationalStatus -eq 'Up') {
                if (Test-IsTunInterface $ni) {
                    $activeTunObjs.Add($ni)
                }
                elseif ($ni.Description -notmatch 'Loopback|WAN Miniport' -and $ni.NetworkInterfaceType -ne 'Loopback') {
                    $physNicsForTunBlock.Add($ni)
                    foreach ($ua in $ni.GetIPProperties().UnicastAddresses) {
                        if ($ua.Address -and $ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                            $ipS = $ua.Address.IPAddressToString
                            if ($ipS -and $ipS -notlike '127.*' -and $ipS -notlike '169.254.*' -and -not $physIpsForTunBlock.Contains($ipS)) {
                                $physIpsForTunBlock.Add($ipS)
                            }
                        }
                    }
                }
            }
        }
    } catch { }

    $physCidrsForTunBlock = @(Get-PhysicalEgressCidrsFast $physNicsForTunBlock)
    if ($physCidrsForTunBlock.Count -eq 0) { $physCidrsForTunBlock = @($physIpsForTunBlock.ToArray()) }

    $needMainScope = ($rawMainTun -and ($rawMainTun -notmatch '(^|\|)LA4='))
    $needAltScope = ($rawAltTun -and ($rawAltTun -notmatch '(^|\|)LA4='))
    $needTunAdd = $false
    $needTunPrune = $false
    $needBlkPhysTun = ($activeTunObjs.Count -gt 0 -and $physCidrsForTunBlock.Count -gt 0 -and (-not $blkPhysTunActive -or -not $rawBlkPhysTun))
    foreach ($tObj in $activeTunObjs) {
        $ifPat = '(?i)(^|\|)IF=' + [regex]::Escape($tObj.Id) + '(\||$)'
        if (($rawMainTun -notmatch $ifPat) -and ($rawAltTun -notmatch $ifPat)) {
            $needTunAdd = $true
        }
        if (-not $needBlkPhysTun -and $physCidrsForTunBlock.Count -gt 0 -and ($rawBlkPhysTun -notmatch $ifPat)) {
            $needBlkPhysTun = $true
        }
    }
    if ($activeTunObjs.Count -gt 0) {
        foreach ($rawRuleTxt in @($rawMainTun, $rawAltTun, $rawBlkPhysTun)) {
            if (-not $rawRuleTxt) { continue }
            foreach ($m in [regex]::Matches($rawRuleTxt, '(?i)(?:^|\|)IF=(\{[^|]+\})')) {
                if (-not $allLiveNicIds.Contains($m.Groups[1].Value)) { $needTunPrune = $true; break }
            }
            if ($needTunPrune) { break }
        }
    }
    if (-not $needBlkPhysTun -and $activeTunObjs.Count -gt 0 -and $physCidrsForTunBlock.Count -gt 0) {
        $curBlkLa = @([regex]::Matches($rawBlkPhysTun, '(?:^|\|)LA4=([^|]+)') | ForEach-Object { $_.Groups[1].Value })
        $curBlkNorm = (@(ConvertTo-IPv4CidrSet $curBlkLa) | Sort-Object -Unique) -join ';'
        $expBlkNorm = (@(ConvertTo-IPv4CidrSet $physCidrsForTunBlock) | Sort-Object -Unique) -join ';'
        if ($curBlkNorm -ne $expBlkNorm) { $needBlkPhysTun = $true }
    }

    if ($needMainScope -or $needAltScope -or $needTunAdd -or $needTunPrune -or $needBlkPhysTun) {
        $tunLocalAddrs = Get-TunAllowedLocalAddressesFast
        $mainTunRule = Get-GuardRule 'AI-Guard-Allow-TUN'
        $altRule = Get-GuardRule 'AI-Guard-Allow-TUN-Alt'
        [string[]]$activeTunNamesNow = @(Get-ActiveTunNamesFast | Where-Object { $_ })

        # Prune dead GUIDs from AI-Guard-Allow-TUN / AI-Guard-Allow-TUN-Alt when live TUNs exist
        if ($needTunPrune -and $activeTunNamesNow.Count -gt 0) {
            $mainLiveNames = @($activeTunObjs | Where-Object { $rawMainTun -match ('(?i)(^|\|)IF=' + [regex]::Escape($_.Id) + '(\||$)') } | Select-Object -ExpandProperty Name -Unique)
            $mainHasDead = $false
            foreach ($m in [regex]::Matches($rawMainTun, '(?i)(?:^|\|)IF=(\{[^|]+\})')) {
                if (-not $allLiveNicIds.Contains($m.Groups[1].Value)) { $mainHasDead = $true; break }
            }
            if ($mainTunRule -and (($mainLiveNames.Count -eq 0) -or $mainHasDead)) {
                [string[]]$targetMainIfs = if ($mainLiveNames.Count -gt 0) { @($mainLiveNames) } else { @($activeTunNamesNow) }
                try {
                    Set-NetFirewallRule -InputObject $mainTunRule -InterfaceAlias $targetMainIfs -LocalAddress $tunLocalAddrs -Enabled True -ErrorAction Stop
                    Reset-RuleCache
                    $mainTunRule = Get-GuardRule 'AI-Guard-Allow-TUN'
                    $script:repairedItems += 'TUN-pruned'
                    Say ('    pruned dead GUIDs on AI-Guard-Allow-TUN -> ' + ($targetMainIfs -join ','))
                } catch { }
            }
            if ($altRule) {
                $altExtraTuns = @($activeTunObjs | Where-Object {
                    -not (Test-FirewallRuleHasTun $mainTunRule $_.Name)
                } | Select-Object -ExpandProperty Name -Unique)
                if ($altExtraTuns.Count -gt 0) {
                    try {
                        Set-NetFirewallRule -InputObject $altRule -InterfaceAlias $altExtraTuns -LocalAddress $tunLocalAddrs -Enabled True -ErrorAction Stop
                        Reset-RuleCache
                        $altRule = Get-GuardRule 'AI-Guard-Allow-TUN-Alt'
                        $script:repairedItems += 'TUN-Alt-pruned'
                    } catch { }
                }
                else {
                    try {
                        $altRule | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                        Reset-RuleCache
                        $altRule = $null
                        $script:repairedItems += 'TUN-Alt-pruned'
                        Say '    removed redundant AI-Guard-Allow-TUN-Alt (dead GUIDs cleaned)'
                    } catch { }
                }
            }
        }

        if ($needMainScope -and $mainTunRule -and $tunLocalAddrs.Count -gt 0) {
            try {
                Set-NetFirewallRule -InputObject $mainTunRule -LocalAddress $tunLocalAddrs -ErrorAction Stop
                Reset-RuleCache
                $script:repairedItems += 'TUN-LocalScope'
                Say '    tightened AI-Guard-Allow-TUN LocalAddress scope (anti physical-IP bypass)'
            } catch { }
        }
        if ($needAltScope -and $altRule -and $tunLocalAddrs.Count -gt 0) {
            try {
                Set-NetFirewallRule -InputObject $altRule -LocalAddress $tunLocalAddrs -ErrorAction Stop
                Reset-RuleCache
                $script:repairedItems += 'TUN-Alt-LocalScope'
                Say '    tightened AI-Guard-Allow-TUN-Alt LocalAddress scope (anti physical-IP bypass)'
            } catch { }
        }

        foreach ($activeTun in $activeTunNamesNow) {
            if (Test-FirewallRuleHasTun $mainTunRule $activeTun) { continue }
            if (Test-FirewallRuleHasTun $altRule $activeTun) { continue }
            try {
                if (-not $mainTunRule) {
                    New-NetFirewallRule -Name 'AI-Guard-Allow-TUN' -DisplayName 'AI-Guard-Allow-TUN' `
                        -Direction Outbound -Action Allow -InterfaceAlias $activeTun -LocalAddress $tunLocalAddrs -Profile Any -Enabled True `
                        -Description ('Allow outbound traffic routed into TUN (' + $activeTun + ').') | Out-Null
                    Reset-RuleCache
                    $mainTunRule = Get-GuardRule 'AI-Guard-Allow-TUN'
                    $script:repairedItems += ('TUN(' + $activeTun + ')')
                    Say ('    created AI-Guard-Allow-TUN for ' + $activeTun)
                    continue
                }
                if ($altRule) {
                    $curAliases = @(Get-GuardRuleFilter ([string]$altRule.Name) 'Interface' | Where-Object { $_ -and $_ -ne 'Any' -and $_ -ne '0' })
                    $mergedAliases = @($curAliases + @($activeTun) | Select-Object -Unique)
                    Set-NetFirewallRule -InputObject $altRule -InterfaceAlias $mergedAliases -LocalAddress $tunLocalAddrs -Enabled True -ErrorAction Stop
                    Reset-RuleCache
                    $script:repairedItems += ('TUN-Alt(' + $activeTun + ')')
                    Say ('    authorized alternate TUN interface: ' + $activeTun)
                }
                else {
                    New-NetFirewallRule -Name 'AI-Guard-Allow-TUN-Alt' -DisplayName 'AI-Guard-Allow-TUN-Alt' `
                        -Direction Outbound -Action Allow -InterfaceAlias $activeTun -LocalAddress $tunLocalAddrs -Profile Any -Enabled True `
                        -Description ('Allow outbound traffic routed into alternate TUN (' + $activeTun + ').') | Out-Null
                    Reset-RuleCache
                    $altRule = Get-GuardRule 'AI-Guard-Allow-TUN-Alt'
                    $script:repairedItems += ('TUN-Alt(' + $activeTun + ')')
                    Say ('    created AI-Guard-Allow-TUN-Alt for ' + $activeTun)
                }
            }
            catch { }
        }

        if (($needBlkPhysTun -or $needTunPrune) -and $activeTunNamesNow.Count -gt 0 -and $physCidrsForTunBlock.Count -gt 0) {
            try {
                $blkRule = Get-GuardRule 'AI-Guard-Block-PhysicalIP-On-TUN'
                if ($blkRule) {
                    Set-NetFirewallRule -InputObject $blkRule -InterfaceAlias $activeTunNamesNow -LocalAddress $physCidrsForTunBlock -Enabled True -ErrorAction Stop
                    Reset-RuleCache
                    $script:repairedItems += 'Block-PhysicalIP-On-TUN-updated'
                }
                else {
                    New-NetFirewallRule -Name 'AI-Guard-Block-PhysicalIP-On-TUN' -DisplayName 'AI-Guard-Block-PhysicalIP-On-TUN' `
                        -Direction Outbound -Action Block -InterfaceAlias $activeTunNamesNow -LocalAddress $physCidrsForTunBlock -Protocol Any -Profile Any -Enabled True `
                        -Description 'Explicitly block sockets bound to physical NIC subnets from matching Xray TUN soft-permit on TUN interface.' | Out-Null
                    $script:repairedItems += 'Block-PhysicalIP-On-TUN-created'
                }
                Say ('    enforced AI-Guard-Block-PhysicalIP-On-TUN (LA=' + ($physCidrsForTunBlock -join ',') + ' on ' + ($activeTunNamesNow -join ',') + ')')
            } catch { }
        }
    }

    # 4. CN allow rule (file-stamp cache avoids parsing 6,516 lines when unchanged)
    $sig = ''
    if (-not $guardPolicy.AllowCnDirect) {
        if ($cnActive) {
            Disable-NetFirewallRule -Name $cnRuleName -ErrorAction SilentlyContinue
            $script:repairedItems += 'CN-disabled(policy)'
            Say '    enforced policy: CN allow rule disabled (strict global lock)'
        }
        $sig = 'POLICY-NO-CN'
    }
    else {
        if (-not (Test-Path -LiteralPath $cnList)) { return $null }
        $cnItem = Get-Item -LiteralPath $cnList -ErrorAction SilentlyContinue
        if (-not $cnItem -or $cnItem.Length -lt 10000) {
            $prefixes = Get-CnPrefixes
            if ($prefixes.Count -eq 0) { return $null }
        }

        $oldSig = ''
        if (Test-Path -LiteralPath $cnSig) { try { $oldSig = (Get-Content -LiteralPath $cnSig -Raw -Encoding UTF8).Trim() } catch { } }

        $stampPrefix = ($cnItem.Length.ToString() + ':' + $cnItem.LastWriteTimeUtc.Ticks.ToString() + ':')
        $cachedMeta = ''
        if (Test-Path -LiteralPath $cnMeta) { try { $cachedMeta = (Get-Content -LiteralPath $cnMeta -Raw -Encoding UTF8).Trim() } catch { } }

        $prefixes = $null
        if ($cnExists -and $oldSig -and $cachedMeta.StartsWith($stampPrefix)) {
            $cachedSig = $cachedMeta.Substring($stampPrefix.Length)
            if ($cachedSig -eq $oldSig) {
                $sig = $oldSig
            }
        }

        if (-not $sig) {
            $prefixes = Get-CnPrefixes
            if ($prefixes.Count -eq 0) { return $null }
            $sig = Get-ListSignature -Prefixes $prefixes
            New-Item -ItemType Directory -Path (Split-Path $cnMeta) -Force | Out-Null
            Set-Content -LiteralPath $cnMeta -Value ($stampPrefix + $sig) -Encoding ASCII
        }

        $needRebuild = ($oldSig -ne $sig) -or (-not $cnExists)
        if ($needRebuild) {
            if (-not $prefixes) {
                $prefixes = Get-CnPrefixes
                if ($prefixes.Count -eq 0) { return $null }
            }
            $cn = Get-GuardRule $cnRuleName
            if ($cn) { $cn | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
            New-NetFirewallRule -Name $cnRuleName -DisplayName $cnRuleName -Direction Outbound -Action Allow `
                -Protocol Any -RemoteAddress $prefixes -Profile Any -Enabled True `
                -Description 'Allow direct egress to mainland-China IPv4 prefixes.' | Out-Null
            Reset-RuleCache
            New-Item -ItemType Directory -Path (Split-Path $cnSig) -Force | Out-Null
            Set-Content -LiteralPath $cnSig -Value $sig -Encoding ASCII
            Set-Content -LiteralPath $cnMeta -Value ($stampPrefix + $sig) -Encoding ASCII
            $script:repairedItems += ('CN-rebuilt(' + $prefixes.Count + ')')
            Say ('    CN allow rule rebuilt: ' + $prefixes.Count + ' prefixes')
        }
        elseif (-not $cnActive) {
            Enable-NetFirewallRule -Name $cnRuleName -ErrorAction SilentlyContinue
            $script:repairedItems += 'CN-enabled'
            Say '    repaired: CN allow rule re-enabled'
        }
    }

    # 5. required companion rules (check existence AND Active=TRUE; auto-enable if disabled)
    foreach ($n in $requiredRules) {
        if (-not $ruleStates.ContainsKey($n)) {
            if ($n -eq 'AI-Guard-Allow-DoH-Ali') {
                try {
                    New-NetFirewallRule -Name 'AI-Guard-Allow-DoH-Ali' -DisplayName 'AI-Guard-Allow-DoH-Ali' `
                        -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress @('223.5.5.5', '223.6.6.6') -RemotePort @('443') -Profile Any -Enabled True `
                        -Description 'Domestic AliDNS DoH (all proxy cores & system).' | Out-Null
                    $script:repairedItems += 'DoH-Ali-created'
                    Say '    repaired: created missing AI-Guard-Allow-DoH-Ali'
                    continue
                } catch { }
            }
            if ($n -eq 'AI-Guard-Allow-DHCP') {
                try {
                    New-NetFirewallRule -Name 'AI-Guard-Allow-DHCP' -DisplayName 'AI-Guard-Allow-DHCP' `
                        -Direction Outbound -Action Allow -Protocol UDP -LocalPort @('68') -RemotePort @('67') -RemoteAddress @('LocalSubnet', '255.255.255.255') -Profile Any -Enabled True `
                        -Description 'DHCP client lease renewal (all adapters).' | Out-Null
                    $script:repairedItems += 'DHCP-created'
                    Say '    repaired: created missing AI-Guard-Allow-DHCP'
                    continue
                } catch { }
            }
            $script:missingRules += $n
            Say ('    WARNING: missing rule ' + $n + ' (run 02-killswitch.ps1 -Force to recreate)')
        }
        elseif (-not $ruleStates[$n]) {
            Enable-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue
            Enable-NetFirewallRule -Name $n -ErrorAction SilentlyContinue
            $script:repairedItems += ($n + '-enabled')
            Say ('    repaired: re-enabled rule ' + $n)
        }
    }
    if (-not $guardPolicy.AllowLan -and $ruleStates.ContainsKey('AI-Guard-Allow-LAN') -and $ruleStates['AI-Guard-Allow-LAN']) {
        Disable-NetFirewallRule -DisplayName 'AI-Guard-Allow-LAN' -ErrorAction SilentlyContinue
        Disable-NetFirewallRule -Name 'AI-Guard-Allow-LAN' -ErrorAction SilentlyContinue
        $script:repairedItems += 'AI-Guard-Allow-LAN-disabled(policy)'
    }
    if ($guardPolicy.AllowNcsi) {
        if ($ruleStates.ContainsKey('AI-Guard-Allow-NCSI') -and (-not $ruleStates['AI-Guard-Allow-NCSI'])) {
            Enable-NetFirewallRule -DisplayName 'AI-Guard-Allow-NCSI' -ErrorAction SilentlyContinue
            Enable-NetFirewallRule -Name 'AI-Guard-Allow-NCSI' -ErrorAction SilentlyContinue
            $script:repairedItems += 'AI-Guard-Allow-NCSI-enabled'
        }
    }
    elseif ($ruleStates.ContainsKey('AI-Guard-Allow-NCSI') -and $ruleStates['AI-Guard-Allow-NCSI']) {
        Disable-NetFirewallRule -DisplayName 'AI-Guard-Allow-NCSI' -ErrorAction SilentlyContinue
        Disable-NetFirewallRule -Name 'AI-Guard-Allow-NCSI' -ErrorAction SilentlyContinue
        $script:repairedItems += 'AI-Guard-Allow-NCSI-disabled(policy)'
    }

    # 6. pure .NET DNS & IPv6 fast check (<2 ms; loads DnsClient/NetAdapter CIM ONLY if drifted)
    $nrptActive = Test-AiGuardNrptActiveFast
    $dnsChanged = $false

    foreach ($ni in @(Get-ActivePhysicalNicsFast)) {
        if ($guardPolicy.LockPhysicalDns -and -not $nrptActive -and $ni.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv4)) {
            $v4Dns = @($ni.GetIPProperties().DnsAddresses |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                ForEach-Object { $_.IPAddressToString })
            if (($v4Dns -join ',') -ne $DnsServer) {
                try {
                    Set-DnsClientServerAddress -InterfaceAlias $ni.Name -ServerAddresses $DnsServer -ErrorAction Stop
                    $dnsChanged = $true
                    $script:repairedItems += ('DNS:' + $ni.Name)
                    Say ('    repaired DNS on ' + $ni.Name + ' -> ' + $DnsServer)
                }
                catch { }
            }
        }

        if ($guardPolicy.DisablePhysicalIpv6 -and $ni.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv6)) {
            try {
                $b = Get-NetAdapterBinding -Name $ni.Name -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue
                if ($b -and $b.Enabled) {
                    $tracked = @()
                    if (Test-Path -LiteralPath $hotplugFile) {
                        try { $tracked = @(Get-Content -LiteralPath $hotplugFile -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { $tracked = @() }
                    }
                    if ($tracked -notcontains $ni.Name) {
                        $tracked += $ni.Name
                        New-Item -ItemType Directory -Path (Split-Path $hotplugFile) -Force | Out-Null
                        $tracked | ConvertTo-Json | Set-Content -LiteralPath $hotplugFile -Encoding UTF8
                    }
                    Disable-NetAdapterBinding -Name $ni.Name -ComponentID 'ms_tcpip6' -ErrorAction Stop
                    $script:repairedItems += ('IPv6-off:' + $ni.Name)
                    Say ('    hardened hot-plugged NIC ' + $ni.Name + ': ms_tcpip6 disabled')
                }
            }
            catch { }
        }
    }

    if ($dnsChanged) {
        ipconfig.exe /flushdns | Out-Null
    }

    # 7. IPv4 over IPv6 prefix policy & SMHNR (<0.5 ms registry fast check)
    try {
        if ($guardPolicy.PreferIpv4Prefix) {
            $dc = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -ErrorAction SilentlyContinue).DisabledComponents
            if ($null -eq $dc -or (([int]$dc -band 0x20) -eq 0)) {
                $v4pol = Get-NetPrefixPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Prefix -eq '::ffff:0:0/96' } | Select-Object -First 1
                $v6pol = Get-NetPrefixPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Prefix -eq '::/0' } | Select-Object -First 1
                if ($v4pol -and $v6pol -and $v4pol.Precedence -le $v6pol.Precedence) {
                    netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 50 4 | Out-Null
                    $script:repairedItems += 'IPv4-precedence'
                    Say '    repaired: IPv4 prefix precedence set above IPv6 (50 > 40)'
                }
            }
        }
        if ($guardPolicy.DisableLlmnrNetbios -or $guardPolicy.DisableSmhnr) {
            $dnsPol = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
            $dnsSvc = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -ErrorAction SilentlyContinue
            $needLlmnr = ($guardPolicy.DisableLlmnrNetbios -and ((-not $dnsPol -or $dnsPol.EnableMulticast -ne 0) -or (-not $dnsSvc -or $dnsSvc.EnableMDNS -ne 0)))
            $needSmhnr = ($guardPolicy.DisableSmhnr -and (-not $dnsPol -or $dnsPol.DisableSmartNameResolution -ne 1))
            if ($needLlmnr -or $needSmhnr) {
                Set-SmhnrHardening -DisableLlmnr ([bool]$guardPolicy.DisableLlmnrNetbios) -DisableSmhnr ([bool]$guardPolicy.DisableSmhnr)
                $script:repairedItems += 'LLMNR+mDNS+SMHNR-hardened'
                Say '    repaired: DNS leak-shield policy hardened (LLMNR/mDNS/SMHNR)'
            }
        }
        if ($guardPolicy.LockPhysicalDns -or $guardPolicy.StrictNrptDoh) {
            if (Set-BrowserDohPolicy -DisableBuiltInDoh $true) {
                $script:repairedItems += 'BrowserDoH-off'
                Say '    repaired: Chromium DnsOverHttpsMode = off'
            }
        }
    }
    catch { }

    # 8. cross-session dead loopback proxy auto-heal (<1 ms registry check when idle/healthy)
    Heal-StaleLoopbackProxyFast

    # 9. WebRTC STUN/TURN leak shield (dual-layer: WFP firewall + Chromium enterprise policy)
    try {
        $wrtcEnabled = if ($guardPolicy.PSObject.Properties.Name -contains 'BlockWebRtcLeak') { [bool]$guardPolicy.BlockWebRtcLeak } else { $true }
        # $webrtcPorts is the script-scope copy from lib-stun-guard.ps1 (single definition).
        $udpActive = $ruleStates.ContainsKey('AI-Guard-Block-WebRTC-UDP') -and $ruleStates['AI-Guard-Block-WebRTC-UDP']
        $tcpActive = $ruleStates.ContainsKey('AI-Guard-Block-WebRTC-TCP') -and $ruleStates['AI-Guard-Block-WebRTC-TCP']
        $localUdpActive = $ruleStates.ContainsKey('AI-Guard-Block-WebRTC-LocalIP-UDP') -and $ruleStates['AI-Guard-Block-WebRTC-LocalIP-UDP']
        $localTcpActive = $ruleStates.ContainsKey('AI-Guard-Block-WebRTC-LocalIP-TCP') -and $ruleStates['AI-Guard-Block-WebRTC-LocalIP-TCP']

        if ($wrtcEnabled) {
            $physFast = @(Get-ActivePhysicalNicsFast)
            # expected LocalAddress scope = the subnet of every live physical NIC (not the bare lease)
            $physFastCidrs = @(Get-PhysicalEgressCidrsFast $physFast)

            $rawUdp = if ($analysis.RawByRule.ContainsKey('AI-Guard-Block-WebRTC-UDP')) { [string]$analysis.RawByRule['AI-Guard-Block-WebRTC-UDP'] } else { '' }
            $rawTcp = if ($analysis.RawByRule.ContainsKey('AI-Guard-Block-WebRTC-TCP')) { [string]$analysis.RawByRule['AI-Guard-Block-WebRTC-TCP'] } else { '' }
            $rawLocalUdp = if ($analysis.RawByRule.ContainsKey('AI-Guard-Block-WebRTC-LocalIP-UDP')) { [string]$analysis.RawByRule['AI-Guard-Block-WebRTC-LocalIP-UDP'] } else { '' }
            $rawLocalTcp = if ($analysis.RawByRule.ContainsKey('AI-Guard-Block-WebRTC-LocalIP-TCP')) { [string]$analysis.RawByRule['AI-Guard-Block-WebRTC-LocalIP-TCP'] } else { '' }

            $needsFwSync = (-not $udpActive) -or (-not $tcpActive) -or (-not $rawUdp) -or (-not $rawTcp)
            if (-not $needsFwSync) {
                foreach ($pni in $physFast) {
                    $ifPat = '(?i)(^|\|)IF=' + [regex]::Escape($pni.Id) + '(\||$)'
                    if (($rawUdp -notmatch $ifPat) -or ($rawTcp -notmatch $ifPat)) {
                        $needsFwSync = $true
                        break
                    }
                }
            }
            if (-not $needsFwSync -and $physFastCidrs.Count -gt 0) {
                if ((-not $localUdpActive) -or (-not $localTcpActive) -or (-not $rawLocalUdp) -or (-not $rawLocalTcp)) {
                    $needsFwSync = $true
                }
                else {
                    # Set equality on purpose: a lease the router no longer hands out must count
                    # as drift too, otherwise the rule keeps an address this host does not own and
                    # silently blocks nothing while still showing Enabled=True.
                    $expLa = (@($physFastCidrs) | Sort-Object -Unique) -join ';'
                    foreach ($rawLa in @($rawLocalUdp, $rawLocalTcp)) {
                        $la4 = @([regex]::Matches([string]$rawLa, '(?:^|\|)LA4=([^|]+)') | ForEach-Object { $_.Groups[1].Value })
                        $curLa = (@(ConvertTo-IPv4CidrSet $la4) | Sort-Object -Unique) -join ';'
                        if ($curLa -ne $expLa) { $needsFwSync = $true; break }
                    }
                }
            }

            if ($needsFwSync) {
                $activeTunsNow = @(Get-ActiveTunNamesFast)
                $physNames = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
                    $_.Status -ne 'Not Present' -and
                    $_.InterfaceDescription -notmatch '(?i)Wintun|sing-tun|Mihomo|Loopback' -and
                    $_.Name -notmatch '(?i)loopback' -and
                    ($knownTunNames -notcontains $_.Name) -and
                    ($activeTunsNow -notcontains $_.Name)
                } | Select-Object -ExpandProperty Name)
                if ($physNames.Count -eq 0 -and $physFast.Count -gt 0) {
                    $physNames = @($physFast | Select-Object -ExpandProperty Name)
                }

                if ($physNames.Count -gt 0) {
                    $ruleUdp = Get-GuardRule 'AI-Guard-Block-WebRTC-UDP'
                    if (-not $ruleUdp) {
                        New-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-UDP' -DisplayName 'AI-Guard-Block-WebRTC-UDP' `
                            -Direction Outbound -Action Block -Protocol UDP -RemotePort $webrtcPorts `
                            -InterfaceAlias $physNames -Profile Any -Enabled True `
                            -Description 'Block WebRTC STUN/TURN UDP on physical NICs (anti-leak for all proxy cores).' | Out-Null
                        Reset-RuleCache
                        $script:repairedItems += 'WebRTC-UDP-created'
                        Say '    created AI-Guard-Block-WebRTC-UDP (physical NICs)'
                    }
                    else {
                        $curIf = @(Get-GuardRuleFilter 'AI-Guard-Block-WebRTC-UDP' 'Interface' | Where-Object { $_ -and $_ -ne 'Any' -and $_ -ne '0' })
                        $missing = @($physNames | Where-Object { $curIf -notcontains $_ })
                        if ($missing.Count -gt 0 -or $ruleUdp.Enabled -ne 'True') {
                            $merged = @($curIf + $missing | Where-Object { $_ -and ($knownTunNames -notcontains $_) -and ($activeTunsNow -notcontains $_) } | Select-Object -Unique)
                            Set-NetFirewallRule -InputObject $ruleUdp -InterfaceAlias $merged -Enabled True -ErrorAction SilentlyContinue
                            Reset-RuleCache
                            $script:repairedItems += 'WebRTC-UDP-updated'
                            Say ('    updated AI-Guard-Block-WebRTC-UDP (physical NICs: ' + ($merged -join ',') + ')')
                        }
                    }

                    $ruleTcp = Get-GuardRule 'AI-Guard-Block-WebRTC-TCP'
                    if (-not $ruleTcp) {
                        New-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-TCP' -DisplayName 'AI-Guard-Block-WebRTC-TCP' `
                            -Direction Outbound -Action Block -Protocol TCP -RemotePort $webrtcPorts `
                            -InterfaceAlias $physNames -Profile Any -Enabled True `
                            -Description 'Block WebRTC STUN/TURN TCP on physical NICs (anti-leak for all proxy cores).' | Out-Null
                        Reset-RuleCache
                        $script:repairedItems += 'WebRTC-TCP-created'
                        Say '    created AI-Guard-Block-WebRTC-TCP (physical NICs)'
                    }
                    else {
                        $curIf = @(Get-GuardRuleFilter 'AI-Guard-Block-WebRTC-TCP' 'Interface' | Where-Object { $_ -and $_ -ne 'Any' -and $_ -ne '0' })
                        $missing = @($physNames | Where-Object { $curIf -notcontains $_ })
                        if ($missing.Count -gt 0 -or $ruleTcp.Enabled -ne 'True') {
                            $merged = @($curIf + $missing | Where-Object { $_ -and ($knownTunNames -notcontains $_) -and ($activeTunsNow -notcontains $_) } | Select-Object -Unique)
                            Set-NetFirewallRule -InputObject $ruleTcp -InterfaceAlias $merged -Enabled True -ErrorAction SilentlyContinue
                            Reset-RuleCache
                            $script:repairedItems += 'WebRTC-TCP-updated'
                            Say ('    updated AI-Guard-Block-WebRTC-TCP (physical NICs: ' + ($merged -join ',') + ')')
                        }
                    }
                }

                if ($physFastCidrs.Count -gt 0) {
                    $ruleLocalUdp = Get-GuardRule 'AI-Guard-Block-WebRTC-LocalIP-UDP'
                    if (-not $ruleLocalUdp) {
                        New-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-LocalIP-UDP' -DisplayName 'AI-Guard-Block-WebRTC-LocalIP-UDP' `
                            -Direction Outbound -Action Block -Protocol UDP -LocalAddress $physFastCidrs -RemotePort $webrtcPorts `
                            -Profile Any -Enabled True `
                            -Description 'Block WebRTC STUN/TURN UDP bound to physical NIC subnets even when TUN metric 0 captures ALE routing.' | Out-Null
                        Reset-RuleCache
                        $script:repairedItems += 'WebRTC-LocalIP-UDP-created'
                        Say ('    created AI-Guard-Block-WebRTC-LocalIP-UDP (' + ($physFastCidrs -join ',') + ')')
                    }
                    else {
                        $curLa = @(ConvertTo-IPv4CidrSet @(Get-GuardRuleFilter 'AI-Guard-Block-WebRTC-LocalIP-UDP' 'Address' | Where-Object { $_ -and $_ -ne 'Any' }))
                        if (((($curLa | Sort-Object -Unique) -join ';') -ne ((@($physFastCidrs) | Sort-Object -Unique) -join ';')) -or $ruleLocalUdp.Enabled -ne 'True') {
                            Set-NetFirewallRule -InputObject $ruleLocalUdp -LocalAddress $physFastCidrs -Enabled True -ErrorAction SilentlyContinue
                            Reset-RuleCache
                            $script:repairedItems += 'WebRTC-LocalIP-UDP-updated'
                            Say ('    updated AI-Guard-Block-WebRTC-LocalIP-UDP (' + ($physFastCidrs -join ',') + ')')
                        }
                    }

                    $ruleLocalTcp = Get-GuardRule 'AI-Guard-Block-WebRTC-LocalIP-TCP'
                    if (-not $ruleLocalTcp) {
                        New-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-LocalIP-TCP' -DisplayName 'AI-Guard-Block-WebRTC-LocalIP-TCP' `
                            -Direction Outbound -Action Block -Protocol TCP -LocalAddress $physFastCidrs -RemotePort $webrtcPorts `
                            -Profile Any -Enabled True `
                            -Description 'Block WebRTC STUN/TURN TCP bound to physical NIC subnets even when TUN metric 0 captures ALE routing.' | Out-Null
                        Reset-RuleCache
                        $script:repairedItems += 'WebRTC-LocalIP-TCP-created'
                        Say ('    created AI-Guard-Block-WebRTC-LocalIP-TCP (' + ($physFastCidrs -join ',') + ')')
                    }
                    else {
                        $curLa = @(ConvertTo-IPv4CidrSet @(Get-GuardRuleFilter 'AI-Guard-Block-WebRTC-LocalIP-TCP' 'Address' | Where-Object { $_ -and $_ -ne 'Any' }))
                        if (((($curLa | Sort-Object -Unique) -join ';') -ne ((@($physFastCidrs) | Sort-Object -Unique) -join ';')) -or $ruleLocalTcp.Enabled -ne 'True') {
                            Set-NetFirewallRule -InputObject $ruleLocalTcp -LocalAddress $physFastCidrs -Enabled True -ErrorAction SilentlyContinue
                            Reset-RuleCache
                            $script:repairedItems += 'WebRTC-LocalIP-TCP-updated'
                            Say ('    updated AI-Guard-Block-WebRTC-LocalIP-TCP (' + ($physFastCidrs -join ',') + ')')
                        }
                    }
                }
            }

            if (Set-WebRtcPolicy -Enable $true) {
                $script:repairedItems += 'WebRTC-policy'
                Say '    repaired: Chromium WebRtcIPHandlingPolicy = disable_non_proxied_udp'
            }

            # Port-independent browser shield: BLOCK all UDP from chrome.exe/msedge.exe on the
            # physical NICs, so TURN-over-443 and any custom STUN port cannot reach a domestic
            # relay through AI-Guard-Allow-CN.  Idempotent; also repairs stale interface/IP drift
            # on the stock AI-Guard-Block-WebRTC-* rules (DHCP lease change).
            #
            # Gate first: the child costs a PowerShell start-up plus a second full rule
            # enumeration, so it only runs when the registry snapshot shows real drift.
            $shieldScript = Join-Path $PSScriptRoot '15-webrtc-browser-shield.ps1'
            if (-not (Test-Path -LiteralPath $shieldScript)) { $shieldScript = Join-Path $Root 'scripts\15-webrtc-browser-shield.ps1' }
            if ((Test-Path -LiteralPath $shieldScript) -and (Test-ShieldDriftFast $analysis $physFast)) {
                try {
                    # child process: the shield ends with 'exit', which would abort this
                    # script if invoked in-process via & (exit kills the calling runspace).
                    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $shieldScript -Apply -Quiet | Out-Null
                }
                catch { }
            }
        }
        else {
            if ($udpActive) {
                Disable-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-UDP' -ErrorAction SilentlyContinue
                $script:repairedItems += 'WebRTC-UDP-disabled(policy)'
                Say '    enforced policy: WebRTC UDP block disabled (BlockWebRtcLeak=false)'
            }
            if ($tcpActive) {
                Disable-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-TCP' -ErrorAction SilentlyContinue
                $script:repairedItems += 'WebRTC-TCP-disabled(policy)'
                Say '    enforced policy: WebRTC TCP block disabled (BlockWebRtcLeak=false)'
            }
            if ($localUdpActive) {
                Disable-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-LocalIP-UDP' -ErrorAction SilentlyContinue
                $script:repairedItems += 'WebRTC-LocalIP-UDP-disabled(policy)'
            }
            if ($localTcpActive) {
                Disable-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-LocalIP-TCP' -ErrorAction SilentlyContinue
                $script:repairedItems += 'WebRTC-LocalIP-TCP-disabled(policy)'
            }
            foreach ($rk in @($ruleStates.Keys)) {
                if ($ruleStates[$rk] -and ($rk -match '^AI-Guard-Block-WebRTC-(?:.+-PhysUDP|.+-CoreSTUN-(?:UDP|TCP))$')) {
                    Disable-NetFirewallRule -Name $rk -ErrorAction SilentlyContinue
                    $script:repairedItems += ($rk + '-disabled(policy)')
                }
            }
            if (Set-WebRtcPolicy -Enable $false) {
                $script:repairedItems += 'WebRTC-policy-removed(policy)'
                Say '    enforced policy: Chromium WebRtcIPHandlingPolicy removed (BlockWebRtcLeak=false)'
            }
        }
    }
    catch { }

    # 9b. B1 routing-table guard (scripts\18-route-stun-guard.ps1): DETECT, never repair.
    #
    # The section above auto-repairs 15-webrtc-browser-shield.ps1, but 15's own header
    # admits the firewall layer cannot stop this leak once a TUN is up: the browser hands
    # the packet to the tunnel, the core re-sends it from the physical NIC, and the WFP
    # block filters are never evaluated. The layer that actually drops the traffic is the
    # core's routing table, maintained by 18 - and until now NOTHING watched it. A
    # routing-set switch in the v2rayN UI, a v2rayN update, or a hand edit could remove
    # the two guard rules, and every probe would stay silent (the physical-NIC WFP rules
    # block the same egress) while the core's own re-send leaks the real address. The
    # self-heal chain repaired the layer that cannot win and ignored the layer that can;
    # this check fixes that asymmetry.
    #
    # No auto-repair by design: -Apply has to rewrite guiNDB.db and refuses to run while
    # v2rayN is up, so repairing from here would be reverted by v2rayN on exit at best and
    # would corrupt the database at worst. Detection + a loud warning + the exact
    # remediation command is the whole job. The exit code is NOT raised on this alone:
    # running a routing set without the guard is a legitimate user choice, and a task that
    # fails every hour teaches people to ignore failures.
    try {
        $script:B1State = Get-B1GuardState (Join-Path $V2rayNRoot 'binConfigs\config.json')
        switch ($script:B1State.State) {
            'present' {
                if ($script:B1State.Shadow -gt 0) {
                    Write-MonitorLog ('WARNING: B1 STUN route guard is loaded but SHADOWED - ' + $script:B1State.Detail)
                }
                elseif ($script:B1State.Caveat -gt 0) {
                    $prevB1 = if ($prevState -and ($prevState.PSObject.Properties.Name -contains 'B1Guard')) { $prevState.B1Guard } else { $null }
                    $b1Changed = (-not $prevB1) -or
                        ([string]$prevB1.State -ne [string]$script:B1State.State) -or
                        ([int]$prevB1.Caveat -ne [int]$script:B1State.Caveat) -or
                        ([string]$prevB1.Detail -ne [string]$script:B1State.Detail)
                    if ($b1Changed) {
                        Write-MonitorLog ('B1 STUN route guard: loaded, caveat=' + $script:B1State.Caveat + ' (' + $script:B1State.Detail + ')')
                    }
                }
            }
            'no-config' { }
            default {
                Write-MonitorLog ('WARNING: B1 STUN route guard is ' + $script:B1State.State + ' in the core routing table - ' + $script:B1State.Detail)
                Write-MonitorLog '         STUN/TURN can leave through the core unobserved. Fix: close v2rayN, then run scripts\18-route-stun-guard.ps1 -Apply'
            }
        }
    }
    catch {
        # Never swallow this silently: an unchecked B1 is precisely the failure mode this
        # section was added to catch. B1State stays null, so the state file records
        # B1Guard=null and a reader can tell the check did not complete.
        Write-MonitorLog ('WARNING: B1 route guard check threw - ' + $_.Exception.Message)
    }

    # 10. Explicit physical-NIC foreign IPv4 block (vetoes third-party WFP soft-permit callouts)
    try {
        $libForeign = if ($PSScriptRoot -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'lib-foreign-block.ps1'))) {
            Join-Path $PSScriptRoot 'lib-foreign-block.ps1'
        }
        else {
            Join-Path $Root 'scripts\lib-foreign-block.ps1'
        }
        if (Test-Path -LiteralPath $libForeign) {
            $fpActive = $ruleStates.ContainsKey('AI-Guard-Block-Foreign-Physical') -and $ruleStates['AI-Guard-Block-Foreign-Physical']
            $fpV6Active = $ruleStates.ContainsKey('AI-Guard-Block-Foreign-Physical-IPv6') -and $ruleStates['AI-Guard-Block-Foreign-Physical-IPv6']
            $wantV6Block = [bool]$guardPolicy.DisablePhysicalIpv6
            $physFastFp = @(Get-ActivePhysicalNicsFast)
            $physNamesFastFp = @($physFastFp | Select-Object -ExpandProperty Name | Sort-Object -Unique)

            $nodeIpsMeta = @()
            if (Test-Path -LiteralPath $nodeMeta) {
                try {
                    $nmRaw = (Get-Content -LiteralPath $nodeMeta -Raw -Encoding ASCII -ErrorAction SilentlyContinue).Trim()
                    $nmParts = $nmRaw.Split('|')
                    if ($nmParts.Count -ge 2 -and $nmParts[1]) {
                        $nodeIpsMeta = @($nmParts[1].Split(',') | Where-Object { $_ -and ($_ -match '^\d{1,3}(\.\d{1,3}){3}$') } | Sort-Object -Unique)
                    }
                } catch { }
            }

            $cnStampFp = 'nocn'
            if ($guardPolicy.AllowCnDirect -and (Test-Path -LiteralPath $cnList)) {
                $cnItemFp = Get-Item -LiteralPath $cnList -ErrorAction SilentlyContinue
                if ($cnItemFp) { $cnStampFp = ($cnItemFp.Length.ToString() + ':' + $cnItemFp.LastWriteTimeUtc.Ticks.ToString()) }
            }

            $fpMetaFile = Join-Path $Root 'backup\foreign-block.meta'
            $fpNeedsSync = (-not $fpActive) -or ($wantV6Block -and -not $fpV6Active) -or ((-not $wantV6Block) -and $fpV6Active)
            if (-not $fpNeedsSync -and (Test-Path -LiteralPath $fpMetaFile)) {
                try {
                    # UTF-8 must match how Sync-ForeignPhysicalBlockRule writes it: the
                    # signature carries localised adapter aliases, and reading them back as
                    # ASCII turned each one into '?' so this gate never matched and the
                    # whole foreign-block rule got rebuilt on every single run.
                    $fpMetaRaw = [System.IO.File]::ReadAllText($fpMetaFile, [System.Text.Encoding]::UTF8).Trim()
                    $fpParts = $fpMetaRaw.Split('|')
                    if ($fpParts.Count -ge 7) {
                        $metaCn = [int]$fpParts[0]
                        $metaLan = [int]$fpParts[1]
                        $metaNcsi = [int]$fpParts[2]
                        $metaPhys = @($fpParts[3].Split(',') | Where-Object { $_ })
                        $metaNodes = @($fpParts[4].Split(',') | Where-Object { $_ })
                        $metaStamp = $fpParts[5]
                        $metaV6 = [int]$fpParts[6]
                        if ($metaCn -ne [int][bool]$guardPolicy.AllowCnDirect -or
                            $metaLan -ne [int][bool]$guardPolicy.AllowLan -or
                            $metaNcsi -ne [int][bool]$guardPolicy.AllowNcsi -or
                            $metaV6 -ne [int]$wantV6Block -or
                            $metaStamp -ne $cnStampFp -or
                            (($metaNodes -join ',') -ne ($nodeIpsMeta -join ','))) {
                            $fpNeedsSync = $true
                        }
                        if (-not $fpNeedsSync) {
                            foreach ($pn in $physNamesFastFp) {
                                if ($metaPhys -notcontains $pn) { $fpNeedsSync = $true; break }
                            }
                        }
                    }
                    else { $fpNeedsSync = $true }
                } catch { $fpNeedsSync = $true }
            }
            elseif (-not (Test-Path -LiteralPath $fpMetaFile)) {
                $fpNeedsSync = $true
            }

            if ($fpNeedsSync) {
                $activeTunsFp = @(Get-ActiveTunNamesFast)
                $allPhysFp = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
                    $_.Status -ne 'Not Present' -and
                    $_.InterfaceDescription -notmatch '(?i)Wintun|sing-tun|Mihomo|Loopback' -and
                    $_.Name -notmatch '(?i)loopback' -and
                    ($knownTunNames -notcontains $_.Name) -and
                    ($activeTunsFp -notcontains $_.Name)
                } | Select-Object -ExpandProperty Name)
                if ($allPhysFp.Count -eq 0) { $allPhysFp = $physNamesFastFp }
                if ($allPhysFp.Count -gt 0) {
                    . $libForeign
                    if (Sync-ForeignPhysicalBlockRule -Root $Root -PhysicalAliases $allPhysFp -NodeIps $nodeIpsMeta `
                        -AllowCnDirect ([bool]$guardPolicy.AllowCnDirect) -AllowLan ([bool]$guardPolicy.AllowLan) `
                        -AllowNcsi ([bool]$guardPolicy.AllowNcsi) -BlockPhysicalIpv6 $wantV6Block) {
                        $script:repairedItems += 'Foreign-Physical-synced'
                        Say '    enforced AI-Guard-Block-Foreign-Physical (vetoes WFP soft-permit callouts)'
                    }
                }
            }
        }
    }
    catch { }

    return $sig
}

# ---------------------------------------------------------------- mode dispatch
if (-not $handledEarly) {
    if ($guardPolicy.PolicyWarning) {
        Write-MonitorLog ('WARNING: ' + $guardPolicy.PolicyWarning)
    }

    $prevState = Read-PrevState
    $prevTun = if ($prevState -and $null -ne $prevState.TunUp) { [bool]$prevState.TunUp } else { $null }
    $tunUp = Test-TunUp

    if ($Mode -eq 'Protected') {
        $lockDir = Split-Path -Parent $protectedLockFile
        if ($lockDir -and -not (Test-Path -LiteralPath $lockDir)) {
            New-Item -ItemType Directory -Path $lockDir -Force | Out-Null
        }
        [System.IO.File]::WriteAllText($protectedLockFile, (Get-Date).ToString('o'), (New-Object System.Text.UTF8Encoding($false)))
        Say '[+] PROTECTED: default deny, CN allow disabled (fail closed, persisted with full self-healing)'
        Write-MonitorLog 'mode -> Protected (protected-lock.flag written; forcing AllowCnDirect=false while running full Ensure-Guard)'
    }

    # Protected persistence (#01): override AllowCnDirect=false instead of skipping Ensure-Guard
    $protectedLockActive = (Test-Path -LiteralPath $protectedLockFile)
    if ($protectedLockActive) {
        $script:guardPolicy.AllowCnDirect = $false
        if ($Mode -ne 'Protected') {
            Say '[+] PROTECTED (locked): backup\protected-lock.flag active - forcing AllowCnDirect=false with full self-healing'
            Write-MonitorLog 'Protected lock active (backup\protected-lock.flag); forcing AllowCnDirect=false while running full Ensure-Guard'
        }
    }

    if ($OnNetworkEvent) {
            if ($null -eq $prevTun -or $tunUp -ne $prevTun) {
                if ($tunUp) {
                    if ($prevTun -eq $false) {
                        ipconfig.exe /flushdns | Out-Null
                        Write-MonitorLog 'proxy path UP (TUN present) - flushed stale/poisoned DNS cache'
                    }
                    else {
                        Write-MonitorLog 'proxy path UP (TUN present)'
                    }
                }
                else {
                    Write-MonitorLog 'proxy path OFF (TUN gone) - domestic direct allowed, foreign blocked'
                }
            }
        }

        $sig = Ensure-Guard
        if (-not $sig) {
            Say '[+] PROTECTED: CN prefix list missing/invalid (fail closed)'
            Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultOutboundAction Block -Enabled True
            Disable-NetFirewallRule -Name $cnRuleName -ErrorAction SilentlyContinue
            Write-State -Label 'Protected' -CnEnabled $false -Sig '' -TunState $tunUp -B1 $script:B1State
            Write-MonitorLog 'verify: CN list invalid -> Protected (fail closed)'
            $scriptExitCode = 2
        }
        else {
            if ($OnNetworkEvent) {
                # Race-free +800 ms late settle:
                #   1) catches late Wintun bring-up when Event 10001/10000 arrived mid-transition
                #   2) unconditionally checks if config.json changed late during fast node-switch (<0.3 ms)
                #   3) unconditionally checks if v2rayN finished exiting ~500 ms after TUN teardown (<0.5 ms)
                Start-Sleep -Milliseconds 800
                $tunLate = Test-TunUp
                $tunFlipped = ($tunLate -ne $tunUp)
                if ($tunFlipped) {
                    $tunUp = $tunLate
                    if ($tunUp) {
                        ipconfig.exe /flushdns | Out-Null
                        Write-MonitorLog 'proxy path UP (late settle) - flushed stale/poisoned DNS cache'
                    }
                    else {
                        Write-MonitorLog 'proxy path OFF (late settle) - domestic direct allowed, foreign blocked'
                    }
                }

                if (-not $DisableAutoNodeSync) {
                    $cfgLatePath = Join-Path $V2rayNRoot 'binConfigs\config.json'
                    $cfgLateItem = Get-Item -LiteralPath $cfgLatePath -ErrorAction SilentlyContinue
                    if ($cfgLateItem) {
                        $lateStamp = ($cfgLateItem.Length.ToString() + ':' + $cfgLateItem.LastWriteTimeUtc.Ticks.ToString() + '|')
                        if ($tunFlipped -or -not (Test-NodeMetaFastHit -StampPrefix $lateStamp)) {
                            $lateAnalysis = Get-FirewallRuleAnalysis
                            Sync-NodeRuleFast -Analysis $lateAnalysis
                        }
                    }
                }

                if ($tunFlipped) {
                    $tunLocalAddrsLate = Get-TunAllowedLocalAddressesFast
                    $mainTunRuleLate = Get-GuardRule 'AI-Guard-Allow-TUN'
                    $altRuleLate = Get-GuardRule 'AI-Guard-Allow-TUN-Alt'
                    foreach ($activeTun in @(Get-ActiveTunNamesFast)) {
                        if (Test-FirewallRuleHasTun $mainTunRuleLate $activeTun) { continue }
                        if (Test-FirewallRuleHasTun $altRuleLate $activeTun) { continue }
                        try {
                            if ($altRuleLate) {
                                $curAliasesLate = @(Get-GuardRuleFilter ([string]$altRuleLate.Name) 'Interface' | Where-Object { $_ -and $_ -ne 'Any' -and $_ -ne '0' })
                                $mergedAliasesLate = @($curAliasesLate + @($activeTun) | Select-Object -Unique)
                                Set-NetFirewallRule -InputObject $altRuleLate -InterfaceAlias $mergedAliasesLate -LocalAddress $tunLocalAddrsLate -Enabled True -ErrorAction Stop
                                Reset-RuleCache
                                $script:repairedItems += ('TUN-Alt(' + $activeTun + ')')
                            }
                            else {
                                New-NetFirewallRule -Name 'AI-Guard-Allow-TUN-Alt' -DisplayName 'AI-Guard-Allow-TUN-Alt' `
                                    -Direction Outbound -Action Allow -InterfaceAlias $activeTun -LocalAddress $tunLocalAddrsLate -Profile Any -Enabled True `
                                    -Description ('Allow outbound traffic routed into alternate TUN (' + $activeTun + ').') | Out-Null
                                Reset-RuleCache
                                $altRuleLate = Get-GuardRule 'AI-Guard-Allow-TUN-Alt'
                                $script:repairedItems += ('TUN-Alt(' + $activeTun + ')')
                            }
                        }
                        catch { }
                    }
                }

                Heal-StaleLoopbackProxyFast
            }

            if ($script:repairedItems.Count -gt 0) {
                Write-MonitorLog ('auto-repaired: ' + ($script:repairedItems -join ', '))
            }
            elseif (-not $OnNetworkEvent -and $Quiet) {
                Write-MonitorLog 'periodic fast verify ok (0 CIM loaded)'
            }

            $label = if ($protectedLockActive) { 'Protected (locked)' } elseif ($tunUp) { 'Guard (proxy on)' } else { 'Guard (proxy off)' }
            if ($protectedLockActive) {
                Say ('[+] ' + $label + ': static guard intact, CN direct disabled by Protected lock (full self-healing active)')
                Write-State -Label $label -CnEnabled $false -Sig $sig -TunState $tunUp -Missing $script:missingRules -B1 $script:B1State
            }
            elseif ($sig -eq 'POLICY-NO-CN') {
                Say ('[+] ' + $label + ': static guard intact, strict global lock (CN direct disabled by policy)')
                Write-State -Label $label -CnEnabled $false -Sig $sig -TunState $tunUp -Missing $script:missingRules -B1 $script:B1State
            }
            else {
                Say ('[+] ' + $label + ': static guard intact, CN direct allowed, foreign blocked')
                Write-State -Label $label -CnEnabled $true -Sig $sig -TunState $tunUp -Missing $script:missingRules -B1 $script:B1State
            }

            if ($Upgrade) {
                Install-WatchdogTasks
            }

            if (-not $Quiet) {
                Show-Status
            }

            if ($script:missingRules.Count -gt 0) {
                Write-MonitorLog ('WARNING: missing companion rules: ' + ($script:missingRules -join ','))
                $scriptExitCode = 3
            }
        }
}
}
finally {
    Exit-GuardWriteLock $modeWriteLock
}
exit $scriptExitCode
