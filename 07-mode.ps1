<#
.SYNOPSIS
    AI-Net-Guard v5.5 - zero-resident static guard, persistent GUI/CLI policy engine, multi-core auto node sync, drift quarantine, SMHNR hardening, and event-task manager.

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
    [int]$FallbackMinutes = 60,
    [switch]$Quiet,
    [string]$Root = $(if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\AI-Net-Guard' }),
    [string]$V2rayNRoot = '',
    [string]$TunName = 'xray_tun',
    [string]$DnsServer = '223.5.5.5'
)

$ErrorActionPreference = 'Continue'
$policyFile = Join-Path $Root 'backup\guard-policy.json'

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
    }
    if (Test-Path -LiteralPath $policyFile) {
        try {
            $raw = Get-Content -LiteralPath $policyFile -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($raw) {
                foreach ($k in @('AllowCnDirect', 'AllowLan', 'AllowNcsi', 'QuarantineRogueAllow', 'LockPhysicalDns',
                        'DisableSmhnr', 'DisableLlmnrNetbios', 'StrictNrptDoh', 'DisablePhysicalIpv6', 'PreferIpv4Prefix',
                        'ZeroResidentMonitor', 'AutoNodeSync', 'AutoHealStaleProxy', 'DomesticNtp', 'HardenInstallAcl')) {
                    if ($raw.PSObject.Properties.Name -contains $k -and $null -ne $raw.$k) {
                        $pol[$k] = [bool]$raw.$k
                    }
                }
                foreach ($sk in @('Version', 'Preset', 'DnsServer', 'V2rayNRoot')) {
                    if ($raw.PSObject.Properties.Name -contains $sk -and $raw.$sk) {
                        $pol[$sk] = [string]$raw.$sk
                    }
                }
            }
        }
        catch { }
    }
    return [pscustomobject]$pol
}

$guardPolicy = Get-GuardPolicy
if (-not $PSBoundParameters.ContainsKey('V2rayNRoot') -and $guardPolicy.V2rayNRoot -and (Test-Path -LiteralPath $guardPolicy.V2rayNRoot)) {
    $V2rayNRoot = $guardPolicy.V2rayNRoot
}
if (-not $PSBoundParameters.ContainsKey('DnsServer')) {
    if ($guardPolicy.StrictNrptDoh) { $DnsServer = '1.1.1.1' }
    elseif ($guardPolicy.DnsServer) { $DnsServer = $guardPolicy.DnsServer }
}
if (-not $PSBoundParameters.ContainsKey('DisableAutoNodeSync') -and (-not $guardPolicy.AutoNodeSync)) {
    $DisableAutoNodeSync = [switch]::Present
}
if (-not $PSBoundParameters.ContainsKey('SkipQuarantineAllowRules') -and (-not $guardPolicy.QuarantineRogueAllow)) {
    $SkipQuarantineAllowRules = [switch]::Present
}
if (-not $PSBoundParameters.ContainsKey('SkipStaleProxyHeal') -and (-not $guardPolicy.AutoHealStaleProxy)) {
    $SkipStaleProxyHeal = [switch]::Present
}

if (-not $V2rayNRoot) {
    if ($env:V2RAYN_ROOT -and (Test-Path -LiteralPath $env:V2RAYN_ROOT)) { $V2rayNRoot = $env:V2RAYN_ROOT }
    else {
        foreach ($cand in @('C:\v2rayN-windows-64', 'D:\v2rayN-windows-64', 'C:\v2rayN', 'D:\v2rayN', (Join-Path $env:LOCALAPPDATA 'v2rayN'), 'C:\Program Files\v2rayN')) {
            if ($cand -and ((Test-Path -LiteralPath (Join-Path $cand 'v2rayN.exe')) -or (Test-Path -LiteralPath (Join-Path $cand 'binConfigs')))) { $V2rayNRoot = $cand; break }
        }
        if (-not $V2rayNRoot) { try { $vp = [System.Diagnostics.Process]::GetProcessesByName('v2rayN'); if ($vp.Length -gt 0 -and $vp[0].MainModule.FileName) { $V2rayNRoot = Split-Path -Parent $vp[0].MainModule.FileName } } catch { } }
        if (-not $V2rayNRoot) { $V2rayNRoot = 'C:\v2rayN-windows-64' }
    }
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'ERROR: run this script in an elevated PowerShell (Run as Administrator).' -ForegroundColor Red
    Write-Host '       Win+X -> Terminal (Admin), then:' -ForegroundColor Yellow
    Write-Host ('       cd "' + $Root + '" ; .\07-mode.ps1 -Status') -ForegroundColor Yellow
    exit 1
}

function Say($msg) { if (-not $Quiet) { Write-Host $msg } }

$cnList = Join-Path $Root 'cn-ipv4.txt'
$cnSig = Join-Path $Root 'backup\cn-rule.sig'
$cnMeta = Join-Path $Root 'backup\cn-file.meta'
$nodeMeta = Join-Path $Root 'backup\node-sync.meta'
$v54Flag = Join-Path $Root 'backup\v54-migrated.flag'
$quarantineFile = Join-Path $Root 'backup\auto-disabled-outbound-allow.json'
$allowExceptionsFile = Join-Path $Root 'backup\allowed-outbound-rules.json'
$stateFile = Join-Path $Root 'backup\mode-state.json'
$hotplugFile = Join-Path $Root 'backup\hotplug-ipv6.json'
$logDir = Join-Path $Root 'logs'
$eventLog = Join-Path $logDir 'watchdog.log'
$cnRuleName = 'AI-Guard-Allow-CN'
$requiredRules = @('AI-Guard-Allow-TUN', 'AI-Guard-Allow-Node-TCP', 'AI-Guard-Allow-DoH-Ali', 'AI-Guard-Allow-DHCP')
if ($guardPolicy.AllowLan) { $requiredRules += 'AI-Guard-Allow-LAN' }
$knownTunNames = @($TunName, 'xray_tun', 'singbox_tun', 'mihomo_tun', 'Meta', 'Mihomo') | Select-Object -Unique

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
    return ,$names.ToArray()
}

function Test-TunUp {
    return ((Get-ActiveTunNamesFast).Count -gt 0)
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
    return ,$list
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
    # O1: SYSTEM tasks execute scripts / read allowlists from $Root, so no non-admin SID
    # may own or hold write / delete / ACL rights on it (fix: .\13-harden-acl.ps1).
    $trusted = @('S-1-5-32-544', 'S-1-5-18', 'S-1-3-0', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $writeMask = [int64]0x500D0156
    $issues = New-Object System.Collections.Generic.List[string]
    $targets = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
    $targets += @(Get-ChildItem -LiteralPath $Path -Force -File -ErrorAction SilentlyContinue)
    foreach ($sub in @('backup', 'logs')) {
        $sp = Join-Path $Path $sub
        if (Test-Path -LiteralPath $sp) { $targets += @(Get-Item -LiteralPath $sp -Force) }
    }
    foreach ($t in $targets) {
        if (-not $t) { continue }
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
        catch { $issues.Add($t.Name + ': ACL unreadable') }
    }
    # plain return (no leading comma) so callers can safely wrap with @()
    return $issues.ToArray()
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
            if ($isAiGuard) {
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
    $sNode = $Cfg.outbounds | Where-Object { $_.type -in @('hysteria2', 'hysteria', 'tuic', 'vless', 'vmess', 'trojan', 'shadowsocks', 'wireguard', 'anytls', 'socks', 'http') } | Select-Object -First 1
    if ($sNode) {
        $addr = [string]$sNode.server
        $ports = @()
        if ($sNode.server_port) { $ports += ([string]$sNode.server_port) }
        if ($sNode.server_ports) {
            foreach ($sp in @($sNode.server_ports)) {
                # sing-box uses "20000:30000" for Hysteria2 port-hopping ranges; Windows Firewall uses "20000-30000"
                $norm = ([string]$sp).Replace(':', '-').Trim()
                if ($norm) { $ports += $norm }
            }
        }
        if (-not $addr -and $sNode.peers) {
            $addr = [string]$sNode.peers[0].server
            if ($sNode.peers[0].server_port) { $ports += ([string]$sNode.peers[0].server_port) }
        }
        $ports = @($ports | Where-Object { $_ } | Select-Object -Unique)
        if (-not $addr -or $ports.Count -eq 0) { return $null }

        $proto = [string]$sNode.type
        $net = if ($sNode.transport -and $sNode.transport.type) { [string]$sNode.transport.type } else { $proto }
        $alpn = @()
        try { if ($sNode.tls -and $sNode.tls.alpn) { $alpn += @($sNode.tls.alpn) } } catch { }
        $isUdp = ($proto -in @('hysteria2', 'hysteria', 'tuic', 'wireguard')) -or ($net -match '(?i)quic') -or ($alpn -contains 'h3')
        $tPorts = if ($proto -in @('hysteria2', 'hysteria', 'tuic', 'wireguard')) { @($ports[0]) } else { $ports }
        $uPorts = if ($isUdp) { $ports } else { @() }
        return [pscustomobject]@{
            CoreType = 'sing-box'
            Protocol = $proto
            Network  = $net
            Address  = $addr
            TcpPorts = $tPorts
            Udp      = $isUdp
            UdpPorts = $uPorts
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
    $tcpActive = ($Analysis.States.ContainsKey('AI-Guard-Allow-Node-TCP') -and $Analysis.States['AI-Guard-Allow-Node-TCP'])
    $udpExists = $Analysis.States.ContainsKey('AI-Guard-Allow-Node-UDP')
    $udpActive = ($udpExists -and $Analysis.States['AI-Guard-Allow-Node-UDP'])

    # Fast path (<0.3 ms, 0 CIM): config.json unchanged AND live firewall rule still matches cached node + core metadata
    if ($tcpActive -and $rawTcp -and (Test-Path -LiteralPath $nodeMeta)) {
        try {
            $cached = (Get-Content -LiteralPath $nodeMeta -Raw -Encoding UTF8).Trim()
            if ($cached.StartsWith($stampPrefix)) {
                $parts = $cached.Split('|')
                if ($parts.Count -ge 4) {
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
                        if ($wantUdp.Count -gt 0 -and -not $udpActive) { $ok = $false }
                        elseif ($wantUdp.Count -eq 0 -and $udpExists) { $ok = $false }
                    }
                    if ($ok) { return }
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
        $address = $parsed.Address

        $ips = @()
        if ($address -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $ips = @($address)
        }
        else {
            $ips = @(Resolve-DomainIpsSafe -Domain $address)
        }
        if ($ips.Count -eq 0) { return }

        $udp = [bool]$parsed.Udp
        $udpPorts = @($parsed.UdpPorts)

        # Scan test configs in binConfigs (e.g. Reality port 443 while active config is Hysteria2 25000)
        $binCfgDir = Join-Path $V2rayNRoot 'binConfigs'
        if (Test-Path -LiteralPath $binCfgDir) {
            foreach ($testFile in (Get-ChildItem -LiteralPath $binCfgDir -Filter 'configTest*.json' -ErrorAction SilentlyContinue)) {
                try {
                    $tCfg = Get-Content -LiteralPath $testFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                    if ($tCfg.outbounds) {
                        foreach ($ob in $tCfg.outbounds) {
                            $tAddr = [string]$(if ($ob.server) { $ob.server } else { $ob.settings.address })
                            $tPort = [string]$(if ($ob.server_port) { $ob.server_port } else { $ob.settings.port })
                            if ($tAddr) {
                                if ($tAddr -match '^\d{1,3}(\.\d{1,3}){3}$') { $ips += @($tAddr) }
                                else { $ips += @(Resolve-DomainIpsSafe -Domain $tAddr) }
                            }
                            if ($tPort) {
                                $parsed.TcpPorts += @($tPort)
                                if ($ob.type -match 'hysteria|tuic|wireguard' -or $ob.protocol -match 'hysteria|wireguard') {
                                    $udpPorts += @($tPort)
                                    $udp = $true
                                }
                            }
                        }
                    }
                } catch { }
            }
        }
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

        # Check if raw registry rule already satisfies everything (avoids loading NetSecurity CIM on first meta write)
        $alreadyExact = $tcpActive -and
            $sameApp -and
            ($rawTcp -notmatch '\|IF=') -and
            (((($oldIps | Sort-Object) -join ',') -eq (($ips | Sort-Object) -join ','))) -and
            (((($oldPorts | Sort-Object) -join ',') -eq (($tcpPorts | Sort-Object) -join ','))) -and
            (($udp -and $udpActive) -or (-not $udp -and -not $udpExists))

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

            # Keep companion rules for all installed proxy cores synchronized
            foreach ($candRel in @('bin\xray\xray.exe', 'bin\sing_box\sing-box.exe', 'v2rayN.exe')) {
                $compExe = Join-Path $V2rayNRoot $candRel
                if ((Test-Path -LiteralPath $compExe) -and ($compExe -ine $coreExe)) {
                    $cName = if ($candRel -like '*xray*') { 'Xray' } elseif ($candRel -like '*sing*') { 'SingBox' } else { 'V2rayN' }
                    $cRuleTcp = Get-NetFirewallRule -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-TCP') -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($cRuleTcp) {
                        Set-NetFirewallRule -InputObject $cRuleTcp -Program $compExe -RemoteAddress $ips -RemotePort $tcpPorts -InterfaceAlias 'Any' -Enabled True -ErrorAction SilentlyContinue
                    }
                    else {
                        New-NetFirewallRule -Name ('AI-Guard-Allow-Core-' + $cName + '-TCP') -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-TCP') `
                            -Direction Outbound -Action Allow -Program $compExe -Protocol TCP `
                            -RemoteAddress $ips -RemotePort $tcpPorts -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
                    }
                    if ($udp) {
                        $cRuleUdp = Get-NetFirewallRule -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-UDP') -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($cRuleUdp) {
                            Set-NetFirewallRule -InputObject $cRuleUdp -Program $compExe -RemoteAddress $ips -RemotePort $udpPorts -InterfaceAlias 'Any' -Enabled True -ErrorAction SilentlyContinue
                        }
                        else {
                            New-NetFirewallRule -Name ('AI-Guard-Allow-Core-' + $cName + '-UDP') -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-UDP') `
                                -Direction Outbound -Action Allow -Program $compExe -Protocol UDP `
                                -RemoteAddress $ips -RemotePort $udpPorts -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
                        }
                    }
                }
            }

            # Ensure /32 physical host route for proxy node IPs so Xray connects directly on physical NIC (avoids TUN double-hop relay)
            try {
                $physRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Where-Object { $_.InterfaceAlias -notmatch '(?i)tun|wintun|sing|xray|meta|mihomo|loopback' -and $_.NextHop -ne '0.0.0.0' } |
                    Select-Object -First 1
                if ($physRoute -and $physRoute.NextHop) {
                    foreach ($nodeIp in $ips) {
                        if ($nodeIp -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                            $curHostRoute = Get-NetRoute -DestinationPrefix ($nodeIp + '/32') -ErrorAction SilentlyContinue
                            if (-not $curHostRoute) {
                                New-NetRoute -DestinationPrefix ($nodeIp + '/32') -InterfaceAlias $physRoute.InterfaceAlias -NextHop $physRoute.NextHop -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null
                            }
                            elseif ($curHostRoute.NextHop -ne $physRoute.NextHop -or $curHostRoute.InterfaceAlias -ne $physRoute.InterfaceAlias -or $curHostRoute.RouteMetric -ne 1) {
                                Remove-NetRoute -DestinationPrefix ($nodeIp + '/32') -Confirm:$false -ErrorAction SilentlyContinue
                                New-NetRoute -DestinationPrefix ($nodeIp + '/32') -InterfaceAlias $physRoute.InterfaceAlias -NextHop $physRoute.NextHop -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null
                            }
                        }
                    }
                }
            } catch { }

            $coreLabel = Split-Path -Leaf $coreExe
            $summary = ($ips -join ',') + ':' + ($tcpPorts -join ',') + $(if ($udp) { '/udp:' + ($udpPorts -join ',') } else { '' }) + ' [' + $coreLabel + ']'
            $script:repairedItems += ('node-synced(' + $summary + ')')
            Say ('    auto-synced node rule -> ' + $summary)
        }

        New-Item -ItemType Directory -Path (Split-Path $nodeMeta) -Force | Out-Null
        $metaLine = $stampPrefix + ($ips -join ',') + '|' + ($tcpPorts -join ',') + '|' + ($udpPorts -join ',') + '|' + $coreExe
        Set-Content -LiteralPath $nodeMeta -Value $metaLine -Encoding ASCII
    }
    catch { }
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

function Get-CnPrefixes {
    if (-not (Test-Path -LiteralPath $cnList)) { return @() }
    $rawLines = [System.IO.File]::ReadAllLines($cnList)
    $ok = New-Object System.Collections.Generic.List[string] ($rawLines.Length)
    foreach ($ln in $rawLines) {
        $t = $ln.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        if ($t -match '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') { $ok.Add($t) }
    }
    if ($ok.Count -lt 1000) { return @() }
    return ,$ok.ToArray()
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
    param([string]$Label, [bool]$CnEnabled, [string]$Sig, [bool]$TunState, [string[]]$Missing = @())
    New-Item -ItemType Directory -Path (Split-Path $stateFile) -Force | Out-Null
    [pscustomobject]@{
        Version      = '5.5'
        Mode         = $Label
        CnEnabled    = $CnEnabled
        Signature    = $Sig
        MissingRules = $Missing
        TunUp        = $TunState
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
    <Description>AI-Net-Guard v5.4 zero-resident network &amp; sleep-resume event handler (wakes on TUN/NIC connect/disconnect, boot, and standby resume; 0 MB idle RAM).</Description>
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
    $modePath = Join-Path $Root '07-mode.ps1'
    if (-not (Test-Path -LiteralPath $modePath)) { throw ('missing: ' + $modePath) }

    Stop-WatchdogTasksAndProcesses

    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $extraFlags = ''
    if ($DisableAutoNodeSync) { $extraFlags += ' -DisableAutoNodeSync' }
    if ($SkipQuarantineAllowRules) { $extraFlags += ' -SkipQuarantineAllowRules' }
    if ($SkipStaleProxyHeal) { $extraFlags += ' -SkipStaleProxyHeal' }

    if ($UseResidentWatchdog) {
        $watchdogPath = Join-Path $Root 'watchdog.ps1'
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

function Show-Status {
    # NOTE: these helpers 'return ,$array'; assign directly - wrapping in @() would always yield Count=1
    $activeTuns = Get-ActiveTunNamesFast
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
    Write-Host '=== AI-Net-Guard v5.5 Status (read-only) ===' -ForegroundColor Cyan
    Write-Host ('TUN : ' + $tunLabel + '   core : ' + $coreLabel)
    if (Test-Path -LiteralPath $policyFile) {
        Write-Host ('  policy preset     : ' + $guardPolicy.Preset + ' (guard-policy.json active)') -ForegroundColor Cyan
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

    foreach ($rn in $displayRules) {
        $optDisabled = ($rn -eq 'AI-Guard-Allow-LAN' -and -not $guardPolicy.AllowLan) -or ($rn -eq 'AI-Guard-Allow-NCSI' -and -not $guardPolicy.AllowNcsi)
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

    foreach ($ni in (Get-ActivePhysicalNicsFast)) {
        $v4Dns = @($ni.GetIPProperties().DnsAddresses |
            Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
            ForEach-Object { $_.IPAddressToString }) -join ','
        $v6On = $ni.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv6)
        Write-Host ('  NIC  {0,-12} : DNS={1}  IPv6Active={2}' -f $ni.Name, $v4Dns, $v6On)
    }

    $dnsPol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
    $llmnrOff = ($dnsPol -and $dnsPol.EnableMulticast -eq 0)
    $smhnrOff = ($dnsPol -and $dnsPol.DisableSmartNameResolution -eq 1)
    Write-Host ('  DNS leak-shield   : LLMNR={0}  SMHNR={1}' -f $(if ($llmnrOff) { 'off' } else { 'ON' }), $(if ($smhnrOff) { 'off' } else { 'pending (auto-applies on next event or .\07-mode.ps1)' }))

    $v4pol = Get-NetPrefixPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Prefix -eq '::ffff:0:0/96' } | Select-Object -First 1
    $v6pol = Get-NetPrefixPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Prefix -eq '::/0' } | Select-Object -First 1
    if ($v4pol -and $v6pol) {
        $preferV4 = ($v4pol.Precedence -gt $v6pol.Precedence)
        Write-Host ('  IPv4 precedence   : ::ffff:0:0/96={0} vs ::/0={1} (preferIPv4={2})' -f $v4pol.Precedence, $v6pol.Precedence, $preferV4)
    }

    $modeTasks = @(Get-ScheduledTask -TaskName 'AI-Guard-Mode-*' -ErrorAction SilentlyContinue)
    if ($modeTasks.Count -eq 0) {
        Write-Host '  monitor tasks     : none registered (run .\07-mode.ps1 -InstallTasks)' -ForegroundColor Yellow
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
    Say '[+] upgrading live installation in-place to AI-Net-Guard v5.4 (zero-resident + multi-core + SMHNR-off + sleep-resume)...'

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
        if (([string]$curNtp) -notmatch '(?i)(\.cn\b|aliyun|tencent|ntsc|203\.107\.6\.88)') {
            $newNtp = 'ntp.aliyun.com,0x9 ntp.tencent.com,0x9 www.time.ac.cn,0x9'
            New-ItemProperty -Path $w32Key -Name 'NtpServer' -Value $newNtp -PropertyType String -Force | Out-Null
            $w32svc = Get-Service -Name w32time -ErrorAction SilentlyContinue
            if ($w32svc -and $w32svc.Status -eq 'Running') { w32tm /config /update 2>$null | Out-Null }
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
if ($RemoveTasks) {
    Stop-WatchdogTasksAndProcesses
    exit 0
}
if ($InstallTasks) {
    Install-WatchdogTasks
    exit 0
}
if ($Status) {
    Show-Status
    exit 0
}
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
$refresher = Join-Path $Root '11-geo-cn.ps1'
if ((Test-Path -LiteralPath $refresher) -and
    ((-not (Test-Path -LiteralPath $cnList)) -or ((Test-Path -LiteralPath $geoFile) -and ((Get-Item -LiteralPath $geoFile).LastWriteTimeUtc -gt (Get-Item -LiteralPath $cnList).LastWriteTimeUtc)))) {
    try { & $refresher -Root $Root -V2rayNRoot $V2rayNRoot -GeoFile $geoFile -OutFile $cnList -Quiet }
    catch { Say ('    CN list refresh failed (keeping old list): ' + $_.Exception.Message) }
}

# ---------------------------------------------------------------- static state (zero-CIM fast path when healthy)
function Ensure-Guard {
    $script:missingRules = @()
    $script:repairedItems = @()

    # 0. One-time zero-touch v5.4 hot-migration (<0.2 ms Test-Path after first run)
    if (-not (Test-Path -LiteralPath $v54Flag)) {
        try {
            Backfill-DnsBaselineV54
            Set-SmhnrHardening -DisableLlmnr ([bool]$guardPolicy.DisableLlmnrNetbios) -DisableSmhnr ([bool]$guardPolicy.DisableSmhnr)
            $evTask = Get-ScheduledTask -TaskName 'AI-Guard-Mode-Event' -ErrorAction SilentlyContinue
            if ($evTask) {
                $modePath = Join-Path $Root '07-mode.ps1'
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
    if (-not $SkipQuarantineAllowRules -and $analysis.RogueOutboundAllows.Count -gt 0) {
        $qList = @()
        if (Test-Path -LiteralPath $quarantineFile) {
            try { $qList = @(Get-Content -LiteralPath $quarantineFile -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { $qList = @() }
        }
        $existingKeys = @($qList | ForEach-Object { $_.Name })
        $qChanged = $false
        $qDisabled = 0
        foreach ($rog in $analysis.RogueOutboundAllows) {
            if ($existingKeys -notcontains $rog.Key) {
                $qList += [pscustomobject]@{
                    Name          = $rog.Key
                    DisplayName   = $rog.DisplayName
                    QuarantinedAt = (Get-Date).ToString('o')
                }
                $existingKeys += $rog.Key
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
            New-Item -ItemType Directory -Path (Split-Path $quarantineFile) -Force | Out-Null
            $qList | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $quarantineFile -Encoding UTF8
        }
        if ($qDisabled -gt 0) {
            $script:repairedItems += ('quarantined-outbound-allow(' + $qDisabled + ')')
        }
    }

    # 3c. hands-free multi-core automatic node sync (<0.3 ms 0-CIM fast path when config.json is unchanged)
    Sync-NodeRuleFast -Analysis $analysis

    # 3d. multi-core dynamic TUN interface rule (e.g. singbox_tun / mihomo_tun / xray_tun)
    $mainTunRule = Get-NetFirewallRule -Name 'AI-Guard-Allow-TUN' -ErrorAction SilentlyContinue
    $mainTunAliases = if ($mainTunRule) { @(($mainTunRule | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue).InterfaceAlias) } else { @() }

    foreach ($activeTun in (Get-ActiveTunNamesFast)) {
        if ($mainTunAliases -contains $activeTun) { continue }
        try {
            if (-not $mainTunRule) {
                New-NetFirewallRule -Name 'AI-Guard-Allow-TUN' -DisplayName 'AI-Guard-Allow-TUN' `
                    -Direction Outbound -Action Allow -InterfaceAlias $activeTun -Profile Any -Enabled True `
                    -Description ('Allow outbound traffic routed into TUN (' + $activeTun + ').') | Out-Null
                $mainTunRule = Get-NetFirewallRule -Name 'AI-Guard-Allow-TUN' -ErrorAction SilentlyContinue
                $mainTunAliases = @($activeTun)
                $script:repairedItems += ('TUN(' + $activeTun + ')')
                Say ('    created AI-Guard-Allow-TUN for ' + $activeTun)
                continue
            }
            $altRule = Get-NetFirewallRule -Name 'AI-Guard-Allow-TUN-Alt' -ErrorAction SilentlyContinue
            if ($altRule) {
                $curAliases = @(($altRule | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue).InterfaceAlias)
                if ($altRule.Enabled -ne 'True' -or ($curAliases -notcontains $activeTun)) {
                    $mergedAliases = @($curAliases + @($activeTun) | Where-Object { $_ -and $_ -ne 'Any' } | Select-Object -Unique)
                    Set-NetFirewallRule -InputObject $altRule -InterfaceAlias $mergedAliases -Enabled True -ErrorAction Stop
                    $script:repairedItems += ('TUN-Alt(' + $activeTun + ')')
                    Say ('    authorized alternate TUN interface: ' + $activeTun)
                }
            }
            else {
                New-NetFirewallRule -Name 'AI-Guard-Allow-TUN-Alt' -DisplayName 'AI-Guard-Allow-TUN-Alt' `
                    -Direction Outbound -Action Allow -InterfaceAlias $activeTun -Profile Any -Enabled True `
                    -Description ('Allow outbound traffic routed into alternate TUN (' + $activeTun + ').') | Out-Null
                $script:repairedItems += ('TUN-Alt(' + $activeTun + ')')
                Say ('    created AI-Guard-Allow-TUN-Alt for ' + $activeTun)
            }
        }
        catch { }
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
            $cn = Get-NetFirewallRule -Name $cnRuleName -ErrorAction SilentlyContinue
            if ($cn) { $cn | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
            New-NetFirewallRule -Name $cnRuleName -DisplayName $cnRuleName -Direction Outbound -Action Allow `
                -Protocol Any -RemoteAddress $prefixes -Profile Any -Enabled True `
                -Description 'Allow direct egress to mainland-China IPv4 prefixes.' | Out-Null
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

    foreach ($ni in (Get-ActivePhysicalNicsFast)) {
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
            $needLlmnr = ($guardPolicy.DisableLlmnrNetbios -and (-not $dnsPol -or $dnsPol.EnableMulticast -ne 0))
            $needSmhnr = ($guardPolicy.DisableSmhnr -and (-not $dnsPol -or $dnsPol.DisableSmartNameResolution -ne 1))
            if ($needLlmnr -or $needSmhnr) {
                Set-SmhnrHardening -DisableLlmnr ([bool]$guardPolicy.DisableLlmnrNetbios) -DisableSmhnr ([bool]$guardPolicy.DisableSmhnr)
                $script:repairedItems += 'LLMNR+SMHNR-hardened'
                Say '    repaired: DNS leak-shield policy hardened'
            }
        }
    }
    catch { }

    # 8. cross-session dead loopback proxy auto-heal (<1 ms registry check when idle/healthy)
    Heal-StaleLoopbackProxyFast

    return $sig
}

# ---------------------------------------------------------------- mode dispatch
$prevState = Read-PrevState
$prevTun = if ($prevState -and $null -ne $prevState.TunUp) { [bool]$prevState.TunUp } else { $null }
$tunUp = Test-TunUp

if ($Mode -eq 'Protected') {
    Say '[+] PROTECTED: default deny, CN allow disabled (fail closed)'
    Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultOutboundAction Block -Enabled True
    Disable-NetFirewallRule -Name $cnRuleName -ErrorAction SilentlyContinue
    Write-State -Label 'Protected' -CnEnabled $false -Sig '' -TunState $tunUp
    Write-MonitorLog 'mode -> Protected (CN allow disabled, fail closed)'
    exit 0
}
else {
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
        Write-State -Label 'Protected' -CnEnabled $false -Sig '' -TunState $tunUp
        Write-MonitorLog 'verify: CN list invalid -> Protected (fail closed)'
        exit 2
    }

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
            $mainTunRuleLate = Get-NetFirewallRule -Name 'AI-Guard-Allow-TUN' -ErrorAction SilentlyContinue
            $mainTunAliasesLate = if ($mainTunRuleLate) { @(($mainTunRuleLate | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue).InterfaceAlias) } else { @() }
            foreach ($activeTun in (Get-ActiveTunNamesFast)) {
                if ($mainTunAliasesLate -contains $activeTun) { continue }
                try {
                    $altRuleLate = Get-NetFirewallRule -Name 'AI-Guard-Allow-TUN-Alt' -ErrorAction SilentlyContinue
                    if ($altRuleLate) {
                        $curAliasesLate = @(($altRuleLate | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue).InterfaceAlias)
                        if ($altRuleLate.Enabled -ne 'True' -or ($curAliasesLate -notcontains $activeTun)) {
                            $mergedAliasesLate = @($curAliasesLate + @($activeTun) | Where-Object { $_ -and $_ -ne 'Any' } | Select-Object -Unique)
                            Set-NetFirewallRule -InputObject $altRuleLate -InterfaceAlias $mergedAliasesLate -Enabled True -ErrorAction Stop
                            $script:repairedItems += ('TUN-Alt(' + $activeTun + ')')
                        }
                    }
                    else {
                        New-NetFirewallRule -Name 'AI-Guard-Allow-TUN-Alt' -DisplayName 'AI-Guard-Allow-TUN-Alt' `
                            -Direction Outbound -Action Allow -InterfaceAlias $activeTun -Profile Any -Enabled True `
                            -Description ('Allow outbound traffic routed into alternate TUN (' + $activeTun + ').') | Out-Null
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

    $label = if ($tunUp) { 'Guard (proxy on)' } else { 'Guard (proxy off)' }
    if ($sig -eq 'POLICY-NO-CN') {
        Say ('[+] ' + $label + ': static guard intact, strict global lock (CN direct disabled by policy)')
        Write-State -Label $label -CnEnabled $false -Sig $sig -TunState $tunUp -Missing $script:missingRules
    }
    else {
        Say ('[+] ' + $label + ': static guard intact, CN direct allowed, foreign blocked')
        Write-State -Label $label -CnEnabled $true -Sig $sig -TunState $tunUp -Missing $script:missingRules
    }

    if ($Upgrade) {
        Install-WatchdogTasks
    }

    if (-not $Quiet) {
        Show-Status
    }

    if ($script:missingRules.Count -gt 0) {
        Write-MonitorLog ('WARNING: missing companion rules: ' + ($script:missingRules -join ','))
        exit 3
    }
    exit 0
}
