<#
.SYNOPSIS
    AI-Net-Guard v5.8.5 - step 2: static default-deny firewall + CN & TUN allowlist.

.DESCRIPTION
    Configures Windows Defender Firewall for the v5.1 zero-switch static guard:

      * registers a SYSTEM scheduled task (AI-Guard-Test-Rollback) FIRST so any
        mistake auto-reverts in RollbackMinutes unless committed with 08-commit.ps1,
      * exports firewall-before-<ts>.wfw and every enabled outbound ALLOW rule,
      * disables those existing outbound ALLOW rules (otherwise they bypass
        DefaultOutboundAction = Block),
      * installs AI-Guard-* rules with matching -Name and -DisplayName:
          - AI-Guard-Allow-TUN      : traffic routed into xray_tun (all apps when TUN is on)
          - AI-Guard-Allow-CN       : mainland-China IPv4 prefixes from v2rayN geoip
                                      (always enabled unless -StrictKillSwitchOnly)
          - AI-Guard-Allow-Node-TCP : xray.exe -> proxy node IP : ports
          - AI-Guard-Allow-DoH-Ali  : xray.exe -> 223.5.5.5 / 223.6.6.6 : 443
          - AI-Guard-Allow-DHCP     : UDP 68 -> 67 (LocalSubnet / broadcast)
          - AI-Guard-Allow-LAN      : LocalSubnet
          - AI-Guard-Allow-NCSI     : TCP -> 13.107.4.52 : 80 (prevents Windows
                                      false "No Internet" globe icon when TUN is off)
      * sets DefaultOutboundAction = Block on Domain/Private/Public.

    v5.1 improvements:
      - Rules no longer lock DHCP / LAN / Node-TCP / DoH-Ali to the install-time
        adapter-name list, so hot-plugged USB NICs and phone USB tethering work
        out-of-the-box without re-running 02-killswitch.ps1 -Force.
      - Sets both -Name and -DisplayName identically for fast, exact registry checks.
      - Builds AI-Guard-Allow-CN directly during install (use -StrictKillSwitchOnly
        for the legacy total-blackout mode without CN direct access).

.NOTES
    Windows 11 24H2. Must be elevated. Undo: 09-rollback.ps1
#>

[CmdletBinding()]
param(
    [string]$Root = $(if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\AI-Net-Guard' }),
    [string]$V2rayNRoot = '',
    [string]$TunName = 'xray_tun',
    [string[]]$NodePorts = @(),
    [string[]]$NodeUdpPorts = @(),
    [int]$RollbackMinutes = 45,
    [switch]$KeepExistingAllowRules,
    [string[]]$KeepRuleNames = @(),
    [switch]$SkipRollbackTask,
    [switch]$SkipDnsCheck,
    [switch]$SkipLanRule,
    [switch]$SkipNcsiRule,
    [switch]$SkipWebRtcBlock,
    [switch]$StrictKillSwitchOnly,
    [switch]$AllowRemainingRules,
    [Alias('DohServer')]
    [string]$DnsServer = '223.5.5.5',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
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
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# The STUN/TURN port set is defined once, in lib-stun-guard.ps1 (see the header there), and
# read from that file here. Resolved BEFORE the first rule is created on purpose: a missing
# lib must abort the run, not fall back to a literal of its own. '-RemotePort' with an
# empty list blocks every port, i.e. it would black-hole all UDP instead of the twelve
# STUN/TURN ports, and the rules would still read Enabled=True.
$libStun = Join-Path $PSScriptRoot 'lib-stun-guard.ps1'
if (-not (Test-Path -LiteralPath $libStun)) {
    Write-Host ('[!] lib-stun-guard.ps1 not found next to this script: ' + $libStun) -ForegroundColor Red
    Write-Host '    refusing to build the STUN/TURN block rules without the shared port list.' -ForegroundColor Red
    exit 1
}
. $libStun

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'ERROR: run this script in an elevated PowerShell (Run as administrator).' -ForegroundColor Red
        exit 1
    }
}
function Write-Step($text) { Write-Host ('[+] ' + $text) -ForegroundColor Cyan }
function Write-Warn($text) { Write-Host ('[!] ' + $text) -ForegroundColor Yellow }

function Get-NodeEndpoint {
    param($Cfg)
    if (-not $Cfg -or -not $Cfg.outbounds) { throw 'no outbounds found in config.json' }

    # 1. Xray schema (outbounds[].protocol)
    $n = $Cfg.outbounds | Where-Object { $_.protocol -in @('vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'wireguard', 'socks', 'http') } | Select-Object -First 1
    if ($n) {
        $addr = [string]$n.settings.address
        $port = [string]$n.settings.port
        if (-not $addr -and $n.settings.vnext) {
            $addr = [string]$n.settings.vnext[0].address
            $port = [string]$n.settings.vnext[0].port
        }
        if (-not $addr -and $n.settings.servers) {
            $addr = [string]$n.settings.servers[0].address
            $port = [string]$n.settings.servers[0].port
        }
        if (-not $addr -and $n.settings.peers) {
            $ep = [string]$n.settings.peers[0].endpoint
            if ($ep -match '^(.+):(\d+)$') { $addr = $matches[1].Trim('[', ']'); $port = $matches[2] }
        }
        if (-not $addr) { throw ('cannot find node address in outbound "' + $n.tag + '" (' + $n.protocol + ')') }
        $net = [string]$n.streamSettings.network
        $proto = [string]$n.protocol
        $alpn = @()
        try { if ($n.streamSettings.tlsSettings.alpn) { $alpn += @($n.streamSettings.tlsSettings.alpn) } } catch { }
        try { if ($n.streamSettings.realitySettings.alpn) { $alpn += @($n.streamSettings.realitySettings.alpn) } } catch { }
        $isUdp = ($net -match '(?i)quic|kcp|hysteria|wireguard' -or $proto -match '(?i)hysteria|wireguard' -or ($alpn -contains 'h3'))
        $uPorts = if ($isUdp) { if ($net -match '(?i)kcp') { @('0-65535') } else { @($pt = $port; $pt) } } else { @() }
        return [pscustomobject]@{
            CoreType = 'xray'
            Address  = $addr
            Port     = $port
            TcpPorts = @($port)
            UdpPorts = $uPorts
            Network  = $net
            Protocol = $proto
        }
    }

    # 2. sing-box schema (outbounds[].type, e.g. Hysteria2 / TUIC / WireGuard / VLESS / AnyTLS)
    $sList = @($Cfg.outbounds | Where-Object { $_.type -in @('hysteria2', 'hysteria', 'tuic', 'vless', 'vmess', 'trojan', 'shadowsocks', 'wireguard', 'anytls', 'socks', 'http') })
    if ($sList.Count -gt 0) {
        $s = $sList[0]
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
        if ($addrs.Count -eq 0 -or $ports.Count -eq 0) { throw ('cannot find node address/port in sing-box outbound "' + $s.tag + '"') }
        $proto = [string]$s.type
        $net = if ($s.transport -and $s.transport.type) { [string]$s.transport.type } else { $proto }
        $uPorts = if ($isUdp) { $ports } else { @() }
        return [pscustomobject]@{
            CoreType  = 'sing-box'
            Address   = $addrs[0]
            Addresses = $addrs
            Port      = $tPorts[0]
            TcpPorts  = $tPorts
            UdpPorts  = $uPorts
            Network   = $net
            Protocol  = $proto
        }
    }

    throw 'no supported proxy outbound found in config.json'
}

Assert-Admin

$BackupDir = Join-Path $Root 'backup'
$LogDir = Join-Path $Root 'logs'
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

# ------------------------------------------------------------------ preflight
Write-Step 'preflight'

if (-not $SkipDnsCheck) {
    $nrptOk = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -like 'AI-Guard*' }).Count -gt 0
    $approvedResolvers = @($DnsServer, '223.5.5.5', '223.6.6.6', '1.1.1.1', '127.0.0.1') | Select-Object -Unique
    $badAdapters = @()
    foreach ($a in (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -notmatch 'Wintun' -and $_.Name -ne $TunName })) {
        try {
            foreach ($ip in @((Get-DnsClientServerAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses)) {
                if ($ip -and ($approvedResolvers -notcontains $ip)) { $badAdapters += ($a.Name + '=' + $ip) }
            }
        }
        catch { }
    }
    if (-not $nrptOk -and $badAdapters.Count -gt 0) {
        throw ('Step 1 (01-dns-hardening.ps1) does not look applied (unapproved resolvers configured: ' + ($badAdapters -join '; ') + '). Run 01 first, or pass -SkipDnsCheck to override.')
    }
    if ($nrptOk) { Write-Host '    DNS hardening: NRPT ok' }
    else { Write-Host ('    DNS hardening: adapters use approved static resolver (' + $DnsServer + ')') }
}

$BaselineFile = Join-Path $BackupDir 'baseline.json'
$baselineExisting = $null
if (Test-Path -LiteralPath $BaselineFile) {
    try { $baselineExisting = Get-Content -LiteralPath $BaselineFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
}
if ($baselineExisting -and $baselineExisting.Firewall -and -not $Force) {
    throw ('A firewall baseline already exists (' + $BaselineFile + '). Run 09-rollback.ps1 first, or pass -Force to re-apply.')
}

# Windows New-NetFirewallRule -InterfaceAlias requires the interface alias to
# exist at rule-creation time (once created, the rule persists across TUN restarts).
$tun = Get-NetAdapter -Name $TunName -ErrorAction SilentlyContinue
if (-not $tun) {
    $tun = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @('xray_tun', 'singbox_tun', 'mihomo_tun', 'Meta', 'Mihomo') -or $_.InterfaceDescription -match '(?i)Wintun|sing-tun|Mihomo' } |
        Select-Object -First 1
    if ($tun) { $TunName = $tun.Name }
}
if (-not $tun) {
    throw ("TUN adapter '" + $TunName + "' not found. Start v2rayN with TUN enabled once so Windows can bind AI-Guard-Allow-TUN.")
}
$tunUp = ($tun.Status -eq 'Up')
Write-Host ('    TUN: ' + $TunName + '  status=' + $tun.Status)
if (-not $tunUp -and -not $Force) {
    throw ('TUN adapter is not Up. Refusing to enable default-deny without an active tunnel (use -Force to override).')
}

# Node address & core type from generated v2rayN config
$cfgPath = Join-Path $V2rayNRoot 'binConfigs\config.json'
if (-not (Test-Path -LiteralPath $cfgPath)) { throw ('missing proxy config: ' + $cfgPath) }
$cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
$node = Get-NodeEndpoint -Cfg $cfg

# Collect all configured node endpoints (active config + test configs in binConfigs)
$allNodeAddresses = if ($node.PSObject.Properties.Name -contains 'Addresses' -and $node.Addresses) { @($node.Addresses) } else { @($node.Address) }
$allTcpPorts = @($node.TcpPorts)
$allUdpPorts = @($node.UdpPorts)

$binCfgDir = Join-Path $V2rayNRoot 'binConfigs'
if (Test-Path -LiteralPath $binCfgDir) {
    foreach ($testFile in (Get-ChildItem -LiteralPath $binCfgDir -Filter 'configTest*.json' -ErrorAction SilentlyContinue)) {
        try {
            $tCfg = Get-Content -LiteralPath $testFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            $tNode = Get-NodeEndpoint -Cfg $tCfg
            if ($tNode -and $tNode.Address) {
                $tAddrs = if ($tNode.PSObject.Properties.Name -contains 'Addresses' -and $tNode.Addresses) { @($tNode.Addresses) } else { @($tNode.Address) }
                $allNodeAddresses += $tAddrs
                $allTcpPorts += $tNode.TcpPorts
                $allUdpPorts += $tNode.UdpPorts
            }
        } catch { }
    }
}
if ($NodePorts.Count -gt 0) { $allTcpPorts += $NodePorts }
if ($NodeUdpPorts.Count -gt 0) { $allUdpPorts += $NodeUdpPorts }
$allNodeAddresses = @($allNodeAddresses | Where-Object { $_ } | Select-Object -Unique)
$allTcpPorts = @($allTcpPorts | Where-Object { $_ } | Select-Object -Unique)
$allUdpPorts = @($allUdpPorts | Where-Object { $_ } | Select-Object -Unique)
if ($allTcpPorts.Count -eq 0) { $allTcpPorts = @('443') }
if ($allUdpPorts.Count -eq 0) { $allUdpPorts = $allTcpPorts }

# Collect all candidate proxy core executables in v2rayN
$allCores = @{}
$candCoreFiles = @(
    @{ Key = 'xray'; Rel = 'bin\xray\xray.exe' },
    @{ Key = 'singbox'; Rel = 'bin\sing_box\sing-box.exe' },
    @{ Key = 'mihomo'; Rel = 'bin\mihomo\mihomo-windows-amd64-v1.exe' },
    @{ Key = 'mihomo_alt'; Rel = 'bin\mihomo\mihomo.exe' },
    @{ Key = 'v2rayn'; Rel = 'v2rayN.exe' }
)
foreach ($cf in $candCoreFiles) {
    $cp = Join-Path $V2rayNRoot $cf.Rel
    if (Test-Path -LiteralPath $cp) { $allCores[$cf.Key] = $cp }
}

$xrayExe = ''
if ($node.CoreType -eq 'sing-box' -and $allCores.ContainsKey('singbox')) { $xrayExe = $allCores['singbox'] }
elseif ($node.CoreType -eq 'xray' -and $allCores.ContainsKey('xray')) { $xrayExe = $allCores['xray'] }
if (-not $xrayExe -and $allCores.Count -gt 0) {
    $xrayExe = @($allCores.Values)[0]
}
if (-not $xrayExe) {
    throw ('proxy core executable not found under: ' + (Join-Path $V2rayNRoot 'bin'))
}
Write-Host ('    primary core: ' + $xrayExe + ' (detected cores: ' + ($allCores.Keys -join ', ') + ')')
Write-Host ('    node endpoints: ' + ($allNodeAddresses -join ', ') + '  TCP: ' + ($allTcpPorts -join ',') + '  UDP: ' + ($allUdpPorts -join ','))

$coreRunning = @(Get-Process -Name @('xray', 'sing-box', 'mihomo', 'mihomo-windows-amd64-v1') -ErrorAction SilentlyContinue)
if ($coreRunning.Count -eq 0) { Write-Warn 'proxy core is not running right now; rules are still installed correctly.' }

$physical = @(Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Status -eq 'Up' -and
        $_.InterfaceDescription -notmatch '(?i)Wintun|sing-tun|Mihomo' -and
        $_.Name -notin @($TunName, 'xray_tun', 'singbox_tun', 'mihomo_tun', 'Meta', 'Mihomo')
    } | Select-Object -ExpandProperty Name)
if ($physical.Count -eq 0) { throw 'No physical adapter is up. Connect to the network first.' }
Write-Host ('    active physical adapters: ' + ($physical -join ', '))

$physicalAll = @(Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object {
        $_.InterfaceDescription -notmatch '(?i)Wintun|sing-tun|Mihomo' -and
        $_.Name -notin @($TunName, 'xray_tun', 'singbox_tun', 'mihomo_tun', 'Meta', 'Mihomo') -and
        $_.Status -ne 'Not Present'
    } | Select-Object -ExpandProperty Name)
if ($physicalAll.Count -eq 0) { $physicalAll = $physical }

$nodeAddress = @([string]$node.Address)
$nodePort = [string]$node.Port
Write-Host ('    node: ' + $node.Address + ':' + ($node.TcpPorts -join ',') + ' (' + $node.Protocol + ', ' + $node.Network + ')')

if ($node.Address -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
    Write-Warn ('node address "' + $node.Address + '" is a domain, not an IP. Resolving over encrypted AliDNS DoH first...')
    $resolved = @()
    try {
        if ([int][Net.ServicePointManager]::SecurityProtocol -ne 0) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
        $rq = [System.Net.HttpWebRequest]::Create('https://223.5.5.5/resolve?name=' + [uri]::EscapeDataString($node.Address) + '&type=A')
        $rq.Proxy = $null; $rq.Timeout = 4000
        $rs = $rq.GetResponse()
        try {
            $js = (New-Object System.IO.StreamReader($rs.GetResponseStream())).ReadToEnd() | ConvertFrom-Json
            $resolved = @($js.Answer | Where-Object { $_.type -eq 1 -and $_.data -match '^\d{1,3}(\.\d{1,3}){3}$' } | ForEach-Object { [string]$_.data })
        }
        finally { $rs.Close() }
    }
    catch { }
    if ($resolved.Count -eq 0) {
        try {
            $resolved = @(Resolve-DnsName -Name $node.Address -Type A -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
        }
        catch { throw ('cannot resolve proxy node: ' + $_.Exception.Message) }
    }
    if ($resolved.Count -gt 0) { $nodeAddress = @($resolved | Select-Object -Unique); Write-Host ('    resolved to: ' + ($nodeAddress -join ', ')) }
}

$allPorts = @($NodePorts) + @($node.TcpPorts)
$allPorts = @($allPorts | Where-Object { $_ } | Select-Object -Unique)
if ($NodeUdpPorts.Count -eq 0 -and $node.UdpPorts.Count -gt 0) {
    $NodeUdpPorts = @($node.UdpPorts | Where-Object { $_ } | Select-Object -Unique)
}
Write-Host ('    allowed node ports/tcp: ' + ($allPorts -join ', ') + $(if ($NodeUdpPorts.Count -gt 0) { '  udp: ' + ($NodeUdpPorts -join ', ') } else { '' }))

# Prepare CN prefix list before touching firewall (unless -StrictKillSwitchOnly)
$cnPrefixes = @()
if (-not $StrictKillSwitchOnly) {
    $cnList = Join-Path $Root 'cn-ipv4.txt'
    $geoScript = if (Test-Path (Join-Path (Join-Path $Root 'scripts') '11-geo-cn.ps1')) { Join-Path (Join-Path $Root 'scripts') '11-geo-cn.ps1' } else { Join-Path $Root '11-geo-cn.ps1' }
    if ((-not (Test-Path -LiteralPath $cnList)) -and (Test-Path -LiteralPath $geoScript)) {
        Write-Step 'generating cn-ipv4.txt from v2rayN geoip'
        & $geoScript -Root $Root -V2rayNRoot $V2rayNRoot -OutFile $cnList
    }
    if (Test-Path -LiteralPath $cnList) {
        $cnPrefixes = @(Get-Content -LiteralPath $cnList -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and -not $_.StartsWith('#') -and $_ -match '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$' })
    }
    if ($cnPrefixes.Count -lt 1000) {
        throw ('CN prefix list missing or invalid (<1000 prefixes in ' + $cnList + '). Run 11-geo-cn.ps1 -Force or pass -StrictKillSwitchOnly.')
    }
    Write-Host ('    CN allowlist ready: ' + $cnPrefixes.Count + ' IPv4 prefixes')
}

# ------------------------------------------------------------------ rollback task FIRST
if (-not $SkipRollbackTask) {
    Write-Step ('registering auto-rollback task (fires in ' + $RollbackMinutes + ' min)')

    $rollback = if (Test-Path (Join-Path (Join-Path $Root 'scripts') '09-rollback.ps1')) { Join-Path (Join-Path $Root 'scripts') '09-rollback.ps1' } else { Join-Path $Root '09-rollback.ps1' }
    if (-not (Test-Path -LiteralPath $rollback)) { throw ('missing rollback script: ' + $rollback) }

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $rollback + '" -Auto -Root "' + $Root + '"')
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($RollbackMinutes)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName 'AI-Guard-Test-Rollback' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-Host ('    task "AI-Guard-Test-Rollback" -> ' + (Get-Date).AddMinutes($RollbackMinutes).ToString('HH:mm:ss'))
    Write-Host '    After verification run 08-commit.ps1 to cancel it, otherwise it reverts everything.'
}
else {
    Write-Warn 'rollback task skipped (-SkipRollbackTask).'
}

# ------------------------------------------------------------------ firewall backup
Write-Step 'exporting firewall and outbound-allow rule list'

$wfw = Join-Path $BackupDir ('firewall-before-' + $stamp + '.wfw')
netsh advfirewall export "$wfw" | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $wfw)) {
    throw ('firewall export failed (netsh exit ' + $LASTEXITCODE + '). Aborting before any change - without this backup rollback is unsafe.')
}
Write-Host ('    ' + $wfw)

$allowRules = @(Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -notlike 'AI-Guard-*' -and $_.Name -notlike 'AI-Guard-*' })
$allowJson = Join-Path $BackupDir ('disabled-outbound-allow-' + $stamp + '.json')
$allowRules | Select-Object Name, DisplayName, Profile, PolicyStoreSourceType | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath $allowJson -Encoding UTF8
Write-Host ('    enabled outbound ALLOW rules: ' + $allowRules.Count + '  -> ' + $allowJson)

$baseline = $null
if (Test-Path -LiteralPath $BaselineFile) {
    try { $baseline = Get-Content -LiteralPath $BaselineFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
}
if (-not $baseline) {
    [pscustomobject]@{
        Created    = (Get-Date).ToString('o')
        Firewall   = $wfw
        AllowRules = $allowJson
    } | ConvertTo-Json | Set-Content -LiteralPath $BaselineFile -Encoding UTF8
    Write-Host ('    baseline: ' + $BaselineFile) -ForegroundColor DarkGray
}
else {
    $changed = $false
    if (-not $baseline.Firewall) { $baseline | Add-Member -NotePropertyName Firewall -NotePropertyValue $wfw -Force; $changed = $true }
    if (-not $baseline.AllowRules) { $baseline | Add-Member -NotePropertyName AllowRules -NotePropertyValue $allowJson -Force; $changed = $true }
    if ($changed) { $baseline | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $BaselineFile -Encoding UTF8 }
}

$gpoAllow = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -notlike 'AI-Guard-*' -and $_.PolicyStoreSourceType -in @('GroupPolicy', 'MDM') })
if ($gpoAllow.Count -gt 0 -and -not $AllowRemainingRules) {
    throw ('Group Policy/MDM outbound ALLOW rules would bypass default-deny: ' + (($gpoAllow | ForEach-Object { $_.DisplayName }) -join '; ') + '. Remove them, or pass -AllowRemainingRules to accept the risk.')
}

# ------------------------------------------------------------------ disable old allow rules
if (-not $KeepExistingAllowRules) {
    Write-Step 'disabling existing outbound ALLOW rules (otherwise they override default-deny)'
    $disabled = 0
    $failed = @()
    $kept = @()
    foreach ($r in $allowRules) {
        if ($KeepRuleNames -contains $r.DisplayName) { $kept += $r.DisplayName; continue }
        try {
            Disable-NetFirewallRule -InputObject $r -ErrorAction Stop
            $disabled++
        }
        catch {
            $failed += $r.DisplayName
        }
    }
    Write-Host ('    disabled: ' + $disabled)
    if ($kept.Count -gt 0) {
        Write-Warn ('kept by -KeepRuleNames: ' + ($kept -join '; '))
        foreach ($r in $allowRules) {
            if ($KeepRuleNames -notcontains $r.DisplayName) { continue }
            try {
                $prog = [string](($r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program)
                $addr = (@(($r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue).RemoteAddress) -join ',')
                if (($prog -match 'Any' -or -not $prog) -and ($addr -match 'Any' -or -not $addr)) {
                    Write-Warn ('  kept rule is any/any and defeats default-deny: ' + $r.DisplayName)
                }
                else {
                    Write-Warn ('  kept scoped rule: ' + $r.DisplayName + ' [' + $prog + ' -> ' + $addr + ']')
                }
            }
            catch { }
        }
    }
    if ($failed.Count -gt 0) {
        Write-Warn ('could not disable ' + $failed.Count + ' rule(s) (policy/GPO owned): ' + ($failed -join '; '))
    }
}
else {
    Write-Warn '-KeepExistingAllowRules given: existing ALLOW rules stay active (weaker isolation).'
}

# ------------------------------------------------------------------ AI-Guard rules
Write-Step 'installing AI-Guard v5.1 rules'

Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'AI-Guard-*' -or $_.DisplayName -like 'AI-Guard-*' } | Remove-NetFirewallRule -ErrorAction SilentlyContinue




function New-AiRule {
    param([hashtable]$Params)
    if (-not $Params.ContainsKey('Name')) {
        $Params['Name'] = $Params['DisplayName']
    }
    Remove-NetFirewallRule -Name $Params['Name'] -ErrorAction SilentlyContinue
    New-NetFirewallRule @Params -Profile Any -Enabled True | Out-Null
    Write-Host ('    ' + $Params.DisplayName)
}

# ------------------------------------------------------------------ IPv4 subnet helpers
# The WebRTC LocalAddress block used to store the exact DHCP lease (e.g. 192.168.1.165).
# That value is a snapshot: the moment the router hands out a different address the rule
# keeps pointing at an address the machine no longer owns, so it silently stops blocking.
# Widening each leased address to its own subnet makes the rule survive a renumber inside
# the same LAN.  A /32 fallback is kept whenever the subnet would also cover a TUN address,
# because that would black-hole proxied WebRTC instead of unproxied leaks.
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

function Get-IPv4NetworkText([string]$Ip, [byte[]]$Mask) {
    $ipb = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
    $n = New-Object 'byte[]' 4
    for ($i = 0; $i -lt 4; $i++) { $n[$i] = [byte]($ipb[$i] -band $Mask[$i]) }
    return (([string]$n[0]) + '.' + ([string]$n[1]) + '.' + ([string]$n[2]) + '.' + ([string]$n[3]))
}

function Get-PhysicalEgressCidrs([string[]]$PhysicalAlias, [string[]]$TunAlias) {
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
        $mask = Get-IPv4MaskBytes $plen
        $net = Get-IPv4NetworkText $ip $mask
        $overlapsTun = $false
        if ($plen -lt 32) {
            foreach ($ti in $tunIps) {
                if ((Get-IPv4NetworkText $ti $mask) -eq $net) { $overlapsTun = $true; break }
            }
        }
        $cidr = if ($plen -ge 32 -or $overlapsTun) { ($ip + '/32') } else { ($net + '/' + [string]$plen) }
        if (-not $out.Contains($cidr)) { $out.Add($cidr) }
    }
    return $out.ToArray()   # plain return (no leading comma) so callers can wrap with @()
}

# 1. everything routed into TUN interfaces is allowed (support all cores: xray_tun, singbox_tun, mihomo_tun, Meta)
# Scope LocalAddress to TUN subnets + active TUN IPs (never physical NIC IPs) so sockets
# explicitly bound to a physical IP cannot match AI-Guard-Allow-TUN via 0.0.0.0/0 metric 0.
$existingAdapterNames = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Not Present' } | Select-Object -ExpandProperty Name)
$tunCandidates = @($TunName, 'xray_tun', 'singbox_tun', 'mihomo_tun', 'Meta', 'Mihomo', 'wintun') | Select-Object -Unique
$allTunAliases = @($tunCandidates | Where-Object { $existingAdapterNames -contains $_ })
if ($allTunAliases.Count -eq 0) { $allTunAliases = if ($TunName) { @($TunName) } else { @('singbox_tun') } }
$physIpSet = @(Get-NetIPAddress -InterfaceAlias $physicalAll -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -and $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
    Select-Object -ExpandProperty IPAddress -Unique)
$tunActualIps = @(Get-NetIPAddress -InterfaceAlias $allTunAliases -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -and $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -notlike 'fe80::*' -and ($physIpSet -notcontains $_.IPAddress) } |
    ForEach-Object { ($_.IPAddress -split '%')[0] } | Select-Object -Unique)
$tunLocalAddrs = @($tunActualIps)
foreach ($cidr in @('172.18.0.0/16', '172.19.0.0/16', '172.20.0.0/16', '198.18.0.0/15', '100.64.0.0/10')) {
    $overlap = $false
    $cp = $cidr -split '/'
    $nb = ([System.Net.IPAddress]::Parse($cp[0])).GetAddressBytes()
    $plen = [int]$cp[1]
    $mask = if ($plen -eq 0) { [uint32]0 } else { [uint32]::MaxValue -shl (32 - $plen) }
    $nhost = ([uint32]$nb[0] -shl 24) -bor ([uint32]$nb[1] -shl 16) -bor ([uint32]$nb[2] -shl 8) -bor [uint32]$nb[3]
    foreach ($pip in $physIpSet) {
        $pb = ([System.Net.IPAddress]::Parse($pip)).GetAddressBytes()
        $ph = ([uint32]$pb[0] -shl 24) -bor ([uint32]$pb[1] -shl 16) -bor ([uint32]$pb[2] -shl 8) -bor [uint32]$pb[3]
        if (($ph -band $mask) -eq ($nhost -band $mask)) { $overlap = $true; break }
    }
    if (-not $overlap -and ($tunLocalAddrs -notcontains $cidr)) { $tunLocalAddrs += $cidr }
}
$tunLocalAddrs += @('fc00::/7', 'fe80::/10')
$tunLocalAddrs = @($tunLocalAddrs | Select-Object -Unique)
New-AiRule @{
    DisplayName    = 'AI-Guard-Allow-TUN'
    Direction      = 'Outbound'
    Action         = 'Allow'
    InterfaceAlias = $allTunAliases
    LocalAddress   = $tunLocalAddrs
    Protocol       = 'Any'
    Description    = 'Traffic routed into TUN interface (TUN-scoped LocalAddress prevents physical-IP bypass).'
}
if ($physIpSet.Count -gt 0 -and $allTunAliases.Count -gt 0) {
    New-AiRule @{
        DisplayName    = 'AI-Guard-Block-PhysicalIP-On-TUN'
        Direction      = 'Outbound'
        Action         = 'Block'
        InterfaceAlias = $allTunAliases
        LocalAddress   = $physIpSet
        Protocol       = 'Any'
        Description    = 'Explicitly block sockets bound to physical NIC IPs from matching Xray TUN soft-permit on TUN interface.'
    }
}

# 2. authorized proxy cores may talk to the proxy nodes across all configured ports
New-AiRule @{
    DisplayName   = 'AI-Guard-Allow-Node-TCP'
    Direction     = 'Outbound'
    Action        = 'Allow'
    Program       = $xrayExe
    Protocol      = 'TCP'
    RemoteAddress = $allNodeAddresses
    RemotePort    = $allTcpPorts
    Description   = 'Active proxy core -> authorized proxy node (TCP).'
}

New-AiRule @{
    DisplayName   = 'AI-Guard-Allow-Node-UDP'
    Direction     = 'Outbound'
    Action        = 'Allow'
    Program       = $xrayExe
    Protocol      = 'UDP'
    RemoteAddress = $allNodeAddresses
    RemotePort    = $allUdpPorts
    Description   = 'Active proxy core -> authorized proxy node (UDP transports).'
}

# Companion core allow rules for other installed cores in v2rayN (Xray, Sing-box, v2rayN)
foreach ($ck in @('xray', 'singbox', 'v2rayn')) {
    if ($allCores.ContainsKey($ck) -and $allCores[$ck] -ne $xrayExe) {
        $cExe = $allCores[$ck]
        $cName = if ($ck -eq 'xray') { 'Xray' } elseif ($ck -eq 'singbox') { 'SingBox' } else { 'V2rayN' }
        New-AiRule @{
            DisplayName   = ('AI-Guard-Allow-Core-' + $cName + '-TCP')
            Direction     = 'Outbound'
            Action        = 'Allow'
            Program       = $cExe
            Protocol      = 'TCP'
            RemoteAddress = $allNodeAddresses
            RemotePort    = $allTcpPorts
            Description   = ($cName + ' -> authorized proxy node (TCP).')
        }
        if ($allUdpPorts.Count -gt 0) {
            New-AiRule @{
                DisplayName   = ('AI-Guard-Allow-Core-' + $cName + '-UDP')
                Direction     = 'Outbound'
                Action        = 'Allow'
                Program       = $cExe
                Protocol      = 'UDP'
                RemoteAddress = $allNodeAddresses
                RemotePort    = $allUdpPorts
                Description   = ($cName + ' -> authorized proxy node (UDP).')
            }
        }
    }
}

# 3. Proxy cores domestic DoH (v2rayN DirectDNS to AliDNS; active core + companion cores for dual-core / fast core-switch)
New-AiRule @{
    DisplayName   = 'AI-Guard-Allow-DoH-Ali'
    Direction     = 'Outbound'
    Action        = 'Allow'
    Program       = $xrayExe
    Protocol      = 'TCP'
    RemoteAddress = @('223.5.5.5', '223.6.6.6')
    RemotePort    = @('443')
    Description   = 'Active proxy core -> Domestic AliDNS DoH.'
}
foreach ($ck in @('xray', 'singbox', 'v2rayn')) {
    if ($allCores.ContainsKey($ck) -and $allCores[$ck] -ine $xrayExe) {
        $cName = if ($ck -eq 'xray') { 'Xray' } elseif ($ck -eq 'singbox') { 'SingBox' } else { 'V2rayN' }
        New-AiRule @{
            DisplayName   = ('AI-Guard-Allow-Core-' + $cName + '-DoH')
            Direction     = 'Outbound'
            Action        = 'Allow'
            Program       = $allCores[$ck]
            Protocol      = 'TCP'
            RemoteAddress = @('223.5.5.5', '223.6.6.6')
            RemotePort    = @('443')
            Description   = ($cName + ' -> Domestic AliDNS DoH (dual-core safe).')
        }
    }
}

# 4. DHCP lease renewal (works on any hot-plugged Ethernet / USB tethering NIC)
New-AiRule @{
    DisplayName   = 'AI-Guard-Allow-DHCP'
    Direction     = 'Outbound'
    Action        = 'Allow'
    Protocol      = 'UDP'
    LocalPort     = @('68')
    RemotePort    = @('67')
    RemoteAddress = @('LocalSubnet', '255.255.255.255')
    Description   = 'DHCP client lease renewal (all adapters).'
}

# 5. local subnet (router UI, printers, NAS - works across Wi-Fi / Ethernet / USB hotspot)
if (-not $SkipLanRule) {
    New-AiRule @{
        DisplayName   = 'AI-Guard-Allow-LAN'
        Direction     = 'Outbound'
        Action        = 'Allow'
        RemoteAddress = @('LocalSubnet', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
        Description   = 'Local subnet and private LAN subnets (RFC1918).'
    }
}

# 6. Windows NCSI connectivity probe (HTTP 80 only to Microsoft's static connecttest VIP)
if (-not $SkipNcsiRule) {
    New-AiRule @{
        DisplayName   = 'AI-Guard-Allow-NCSI'
        Direction     = 'Outbound'
        Action        = 'Allow'
        Protocol      = 'TCP'
        RemoteAddress = '13.107.4.52'
        RemotePort    = @('80')
        Description   = 'Windows NCSI connecttest.txt HTTP-80 probe (prevents false No-Internet globe when TUN is off).'
    }
}

# 6.5 WebRTC STUN/TURN leak shield on physical network interfaces (anti-leak for all proxy cores)
if (-not $SkipWebRtcBlock -and $physicalAll.Count -gt 0) {
    $webrtcPorts = @(Get-StunGuardPortStrings)
    New-AiRule @{
        DisplayName    = 'AI-Guard-Block-WebRTC-UDP'
        Direction      = 'Outbound'
        Action         = 'Block'
        Protocol       = 'UDP'
        RemotePort     = $webrtcPorts
        InterfaceAlias = $physicalAll
        Description    = 'Block WebRTC STUN/TURN outbound UDP on physical NICs (anti-leak for all proxy cores).'
    }
    New-AiRule @{
        DisplayName    = 'AI-Guard-Block-WebRTC-TCP'
        Direction      = 'Outbound'
        Action         = 'Block'
        Protocol       = 'TCP'
        RemotePort     = $webrtcPorts
        InterfaceAlias = $physicalAll
        Description    = 'Block WebRTC STUN/TURN outbound TCP on physical NICs (anti-leak for all proxy cores).'
    }

    # Scope: local subnet(s) of the physical NICs, not the single leased address, so a DHCP
    # renumber inside the same LAN does not silently void the block.  TUN subnets are never
    # included (Get-PhysicalEgressCidrs falls back to /32 on overlap).
    $physCidrs = @(Get-PhysicalEgressCidrs -PhysicalAlias $physicalAll -TunAlias $allTunAliases)
    if ($physCidrs.Count -gt 0) {
        New-AiRule @{
            DisplayName  = 'AI-Guard-Block-WebRTC-LocalIP-UDP'
            Direction    = 'Outbound'
            Action       = 'Block'
            Protocol     = 'UDP'
            LocalAddress = $physCidrs
            RemotePort   = $webrtcPorts
            Description  = 'Block WebRTC STUN/TURN UDP sockets bound to physical NIC subnets even when TUN metric 0 captures ALE routing.'
        }
        New-AiRule @{
            DisplayName  = 'AI-Guard-Block-WebRTC-LocalIP-TCP'
            Direction    = 'Outbound'
            Action       = 'Block'
            Protocol     = 'TCP'
            LocalAddress = $physCidrs
            RemotePort   = $webrtcPorts
            Description  = 'Block WebRTC STUN/TURN TCP sockets bound to physical NIC subnets even when TUN metric 0 captures ALE routing.'
        }
        Write-Host ('    WebRTC LocalIP scope: ' + ($physCidrs -join ','))
    }

    # 6.6 Browser-scoped, port-independent UDP block.  The port list above misses
    #     TURN over 443 and any custom STUN/TURN port, and AI-Guard-Allow-CN lets
    #     domestic destinations through on every port.  Scoping the block to the
    #     browser executable closes that gap without touching DHCP (67/68), plain
    #     DNS (53), NTP (123) or the node's own UDP transport - Windows Firewall
    #     gives Block precedence over Allow at equal weight, so a blanket UDP block
    #     would break those.
    $shieldPath = Join-Path $PSScriptRoot '15-webrtc-browser-shield.ps1'
    if (-not (Test-Path -LiteralPath $shieldPath)) { $shieldPath = Join-Path $Root 'scripts\15-webrtc-browser-shield.ps1' }
    if (Test-Path -LiteralPath $shieldPath) {
        try {
            # child process: the shield ends with 'exit', which would terminate this
            # script if invoked in-process via & (exit kills the calling runspace).
            & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $shieldPath -Apply -Quiet | Out-Null
            Write-Host '    AI-Guard-Block-WebRTC-*-PhysUDP'
        }
        catch {
            Write-Warn ('browser WebRTC shield skipped: ' + $_.Exception.Message)
        }
    }

    try {
        $cPolKey = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
        $ePolKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        if (-not (Test-Path -LiteralPath $cPolKey)) { New-Item -Path $cPolKey -Force | Out-Null }
        New-ItemProperty -Path $cPolKey -Name 'WebRtcIPHandlingPolicy' -Value 'disable_non_proxied_udp' -PropertyType String -Force | Out-Null
        if (-not (Test-Path -LiteralPath $ePolKey)) { New-Item -Path $ePolKey -Force | Out-Null }
        New-ItemProperty -Path $ePolKey -Name 'WebRtcIPHandlingPolicy' -Value 'disable_non_proxied_udp' -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $ePolKey -Name 'WebRtcLocalhostIpHandling' -Value 'disable_non_proxied_udp' -PropertyType String -Force | Out-Null
    } catch { }
}

# 7. Mainland-China IPv4 allowlist (v5.1 static mode) OR strict port-53/853 kill
if (-not $StrictKillSwitchOnly) {
    New-AiRule @{
        DisplayName   = 'AI-Guard-Allow-CN'
        Direction     = 'Outbound'
        Action        = 'Allow'
        Protocol      = 'Any'
        RemoteAddress = $cnPrefixes
        Description   = 'Allow direct egress to mainland-China IPv4 prefixes.'
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $sigBytes = [System.Text.Encoding]::ASCII.GetBytes(($cnPrefixes -join "`n"))
        $sig = $cnPrefixes.Count.ToString() + ':' + [System.BitConverter]::ToString($sha.ComputeHash($sigBytes)).Replace('-', '')
        Set-Content -LiteralPath (Join-Path $BackupDir 'cn-rule.sig') -Value $sig -Encoding ASCII
        $cnFileItem = Get-Item -LiteralPath (Join-Path $Root 'cn-ipv4.txt') -ErrorAction SilentlyContinue
        if ($cnFileItem) {
            $cnMetaVal = ($cnFileItem.Length.ToString() + ':' + $cnFileItem.LastWriteTimeUtc.Ticks.ToString() + ':' + $sig)
            Set-Content -LiteralPath (Join-Path $BackupDir 'cn-file.meta') -Value $cnMetaVal -Encoding ASCII
        }
        $cfgFileItem = Get-Item -LiteralPath $cfgPath -ErrorAction SilentlyContinue
        if ($cfgFileItem) {
            $nodeMetaVal = ($cfgFileItem.Length.ToString() + ':' + $cfgFileItem.LastWriteTimeUtc.Ticks.ToString() + '|' + ($nodeAddress -join ',') + '|' + ($allPorts -join ',') + '|' + ($NodeUdpPorts -join ',') + '|' + $xrayExe)
            Set-Content -LiteralPath (Join-Path $BackupDir 'node-sync.meta') -Value $nodeMetaVal -Encoding ASCII
        }
        Set-Content -LiteralPath (Join-Path $BackupDir 'legacy-rules-cleaned-v51.flag') -Value (Get-Date).ToString('o') -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $BackupDir 'v54-migrated.flag') -Value (Get-Date).ToString('o') -Encoding ASCII
    }
    finally { $sha.Dispose() }
}
else {
    foreach ($proto in @('UDP', 'TCP')) {
        New-AiRule @{
            DisplayName    = ('AI-Guard-Block-DNS-' + $proto)
            Direction      = 'Outbound'
            Action         = 'Block'
            Protocol       = $proto
            RemotePort     = @('53')
            InterfaceAlias = $physicalAll
            Description    = 'Block plaintext DNS on physical NICs (strict mode).'
        }
    }
    New-AiRule @{
        DisplayName    = 'AI-Guard-Block-DoT'
        Direction      = 'Outbound'
        Action         = 'Block'
        Protocol       = 'TCP'
        RemotePort     = @('853')
        InterfaceAlias = $physicalAll
        Description    = 'Block DNS-over-TLS on physical NICs (strict mode).'
    }
}

# Explicit physical-NIC foreign IPv4 block (vetoes third-party WFP soft-permit callouts)
try {
    $libForeign = if ($PSScriptRoot -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'lib-foreign-block.ps1'))) {
        Join-Path $PSScriptRoot 'lib-foreign-block.ps1'
    }
    else {
        Join-Path $Root 'scripts\lib-foreign-block.ps1'
    }
    if (Test-Path -LiteralPath $libForeign) {
        . $libForeign
        $resolvedNodes = @($nodeAddress + @($allNodeAddresses) | Where-Object { $_ -and ($_ -match '^\d{1,3}(\.\d{1,3}){3}$') } | Select-Object -Unique)
        if (Sync-ForeignPhysicalBlockRule -Root $Root -PhysicalAliases $physicalAll -NodeIps $resolvedNodes `
            -AllowCnDirect (-not [bool]$StrictKillSwitchOnly) -AllowLan (-not [bool]$SkipLanRule) -AllowNcsi (-not [bool]$SkipNcsiRule) -Force) {
            Write-Host '    AI-Guard-Block-Foreign-Physical'
        }
    }
}
catch {
    Write-Warn ('AI-Guard-Block-Foreign-Physical skipped: ' + $_.Exception.Message)
}

# ------------------------------------------------------------------ default deny
Write-Step 'setting DefaultOutboundAction = Block (Domain, Private, Public)'

$profiles = Get-NetFirewallProfile
foreach ($p in $profiles) {
    if (-not $p.Enabled) {
        Write-Warn ('firewall profile ' + $p.Name + ' is disabled; enabling it')
        Set-NetFirewallProfile -Profile $p.Name -Enabled True
    }
}
Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultOutboundAction Block
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize

$diag = Join-Path $LogDir ('killswitch-' + $stamp + '.txt')
@(
    ('version: 5.4'),
    ('timestamp: ' + (Get-Date).ToString('o')),
    ('node: ' + ($nodeAddress -join ',') + ' ports ' + ($allPorts -join ',')),
    ('tun: ' + $TunName + ' status ' + $tun.Status),
    ('active physical: ' + ($physical -join ',')),
    ('cn prefixes: ' + $cnPrefixes.Count),
    ('disabled allow rules: ' + $allowRules.Count)
) | Set-Content -LiteralPath $diag -Encoding UTF8

Write-Host ''
Write-Host 'Static default-deny guard (v5.4) is active.' -ForegroundColor Green
Write-Host 'NEXT (within ' -NoNewline
Write-Host ($RollbackMinutes.ToString() + ' min') -NoNewline -ForegroundColor Yellow
Write-Host '):'
Write-Host '  1. run .\03-verify.ps1 -WfpCheck   -> all checks must pass'
Write-Host '  2. run .\08-commit.ps1             -> cancels auto-rollback & installs v5.4 zero-resident event tasks'
Write-Host ''
Write-Host 'If anything is broken: .\09-rollback.ps1 (or wait for auto-rollback).' -ForegroundColor Yellow
