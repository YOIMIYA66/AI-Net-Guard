<#
.SYNOPSIS
    AI-Net-Guard v5.7.1 - maintenance: re-sync node allow rule after switching proxy node or core.

.DESCRIPTION
    Note: In v5.4, 07-mode.ps1 automatically syncs AI-Guard-Allow-Node-TCP/UDP
    whenever v2rayN rewrites binConfigs\config.json (default ON). You only need
    to run this script manually if you disabled auto-sync (-DisableAutoNodeSync),
    want to preview (-WhatIfOnly), or want to force-replace merged ports (-ReplacePorts).

    v5.4 improvements:
      - Multi-core support: parses BOTH Xray (outbounds[].protocol) and sing-box
        (outbounds[].type, server, server_port, and Hysteria2 port-hopping ranges
        server_ports "20000:30000" -> "20000-30000") and binds -Program to the
        active core executable (xray.exe / sing-box.exe / mihomo.exe).
      - Resolves domain-based nodes over encrypted https://223.5.5.5/resolve first
        (immune to plaintext UDP-53 spoofing even when TUN is off).
      - Updates backup\node-sync.meta so 07-mode.ps1's fast path stays synchronized.
#>

[CmdletBinding()]
param(
    [string]$Root = $(if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\AI-Net-Guard' }),
    [string]$V2rayNRoot = '',
    [string[]]$ExtraTcpPorts = @(),
    [switch]$ReplacePorts,
    [switch]$WhatIfOnly
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

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object Security.Principal.WindowsPrincipal($id)
$isAdmin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Resolve-NodeDomainSafe([string]$Domain) {
    $res = @()
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
            $res = @($json.Answer | Where-Object { $_.type -eq 1 -and $_.data -match '^\d{1,3}(\.\d{1,3}){3}$' } | ForEach-Object { [string]$_.data })
        }
        finally { $resp.Close() }
    }
    catch { }
    if ($res.Count -eq 0) {
        $res = @(Resolve-DnsName -Name $Domain -Type A -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
    }
    return @($res | Where-Object { $_ } | Select-Object -Unique)
}

function Resolve-CoreExe([string]$CoreType) {
    foreach ($pn in @('xray', 'sing-box', 'mihomo', 'mihomo-windows-amd64-v1')) {
        foreach ($pr in @([System.Diagnostics.Process]::GetProcessesByName($pn))) {
            try {
                $mp = $pr.MainModule.FileName
                if ($mp -and (Test-Path -LiteralPath $mp)) {
                    if ($CoreType -eq 'sing-box' -and $pn -eq 'sing-box') { return $mp }
                    if ($CoreType -eq 'xray' -and $pn -eq 'xray') { return $mp }
                    if ($CoreType -eq 'mihomo' -and $pn -like 'mihomo*') { return $mp }
                }
            }
            catch { }
        }
    }
    if ($CoreType -eq 'sing-box') {
        $sb = Join-Path $V2rayNRoot 'bin\sing_box\sing-box.exe'
        if (Test-Path -LiteralPath $sb) { return $sb }
    }
    return (Join-Path $V2rayNRoot 'bin\xray\xray.exe')
}

$cfgPath = Join-Path $V2rayNRoot 'binConfigs\config.json'
if (-not (Test-Path -LiteralPath $cfgPath)) { throw ('missing proxy config: ' + $cfgPath) }
$cfgItem = Get-Item -LiteralPath $cfgPath

$cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
$coreType = 'xray'
$address = ''
$proto = ''
$network = ''
$udp = $false
$baseTcpPorts = @()
$baseUdpPorts = @()

$xNode = $cfg.outbounds | Where-Object { $_.protocol -in @('vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'wireguard', 'socks', 'http') } | Select-Object -First 1
if ($xNode) {
    $address = [string]$xNode.settings.address
    $port = [string]$xNode.settings.port
    if (-not $address -and $xNode.settings.vnext) {
        $address = [string]$xNode.settings.vnext[0].address
        $port = [string]$xNode.settings.vnext[0].port
    }
    if (-not $address -and $xNode.settings.servers) {
        $address = [string]$xNode.settings.servers[0].address
        $port = [string]$xNode.settings.servers[0].port
    }
    if (-not $address -and $xNode.settings.peers) {
        $ep = [string]$xNode.settings.peers[0].endpoint
        if ($ep -match '^(.+):(\d+)$') { $address = $matches[1].Trim('[', ']'); $port = $matches[2] }
    }
    $network = [string]$xNode.streamSettings.network
    $proto = [string]$xNode.protocol
    $alpn = @($xNode.streamSettings.tlsSettings.alpn) + @($xNode.streamSettings.realitySettings.alpn)
    if ($network -match '(?i)quic|kcp|hysteria|wireguard' -or $proto -match '(?i)hysteria|wireguard' -or ($alpn -contains 'h3')) { $udp = $true }
    $baseTcpPorts = @($port)
    if ($udp) { $baseUdpPorts = if ($network -match '(?i)kcp') { @('0-65535') } else { @($port) } }
}
else {
    $sNode = $cfg.outbounds | Where-Object { $_.type -in @('hysteria2', 'hysteria', 'tuic', 'vless', 'vmess', 'trojan', 'shadowsocks', 'wireguard', 'anytls', 'socks', 'http') } | Select-Object -First 1
    if (-not $sNode) { throw 'no proxy outbound found in config.json (checked Xray and sing-box schemas)' }
    $coreType = 'sing-box'
    $address = [string]$sNode.server
    $ports = @()
    if ($sNode.server_port) { $ports += ([string]$sNode.server_port) }
    if ($sNode.server_ports) {
        foreach ($sp in @($sNode.server_ports)) {
            $norm = ([string]$sp).Replace(':', '-').Trim()
            if ($norm) { $ports += $norm }
        }
    }
    if (-not $address -and $sNode.peers) {
        $address = [string]$sNode.peers[0].server
        if ($sNode.peers[0].server_port) { $ports += ([string]$sNode.peers[0].server_port) }
    }
    $ports = @($ports | Where-Object { $_ } | Select-Object -Unique)
    $proto = [string]$sNode.type
    $network = if ($sNode.transport -and $sNode.transport.type) { [string]$sNode.transport.type } else { $proto }
    $alpn = @()
    try { if ($sNode.tls -and $sNode.tls.alpn) { $alpn += @($sNode.tls.alpn) } } catch { }
    $udp = ($proto -in @('hysteria2', 'hysteria', 'tuic', 'wireguard')) -or ($network -match '(?i)quic') -or ($alpn -contains 'h3')
    $baseTcpPorts = @(if ($proto -in @('hysteria2', 'hysteria', 'tuic', 'wireguard')) { $ports[0] } else { $ports })
    if ($udp) { $baseUdpPorts = @($ports) }
}

if (-not $address) { throw 'cannot find node address in config.json' }
$coreExe = Resolve-CoreExe -CoreType $coreType

$ips = @()
if ($address -match '^\d{1,3}(\.\d{1,3}){3}$') {
    $ips = @($address)
}
else {
    $ips = @(Resolve-NodeDomainSafe -Domain $address)
    if ($ips.Count -eq 0) { throw ('cannot resolve node address: ' + $address) }
}

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
                        else { $ips += @(Resolve-NodeDomainSafe -Domain $tAddr) }
                    }
                    if ($tPort) {
                        $baseTcpPorts += @($tPort)
                        if ($ob.type -match 'hysteria|tuic|wireguard' -or $ob.protocol -match 'hysteria|wireguard') {
                            $baseUdpPorts += @($tPort)
                            $udp = $true
                        }
                    }
                }
            }
        } catch { }
    }
}
$ips = @($ips | Where-Object { $_ } | Select-Object -Unique)
$baseTcpPorts = @($baseTcpPorts | Where-Object { $_ } | Select-Object -Unique)
$baseUdpPorts = @($baseUdpPorts | Where-Object { $_ } | Select-Object -Unique)

# Detect all installed proxy core binaries
$allCores = @{}
foreach ($candRel in @('bin\xray\xray.exe', 'bin\sing_box\sing-box.exe', 'bin\mihomo\mihomo-windows-amd64-v1.exe', 'bin\mihomo\mihomo.exe', 'v2rayN.exe')) {
    $cp = Join-Path $V2rayNRoot $candRel
    if (Test-Path -LiteralPath $cp) {
        $key = (Split-Path -Leaf $cp).Replace('.exe', '').ToLowerInvariant()
        $allCores[$key] = $cp
    }
}

$tcpRule = Get-NetFirewallRule -DisplayName 'AI-Guard-Allow-Node-TCP' -ErrorAction SilentlyContinue | Select-Object -First 1
$tcpPorts = @($baseTcpPorts) + @($ExtraTcpPorts)
if ($tcpRule -and -not $ReplacePorts) {
    $oldApp = [string](($tcpRule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program)
    $oldAddrs = @(($tcpRule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue).RemoteAddress)
    if (($oldApp -ieq $coreExe) -and ((($oldAddrs | Sort-Object) -join ',') -eq (($ips | Sort-Object) -join ','))) {
        $oldPorts = @(($tcpRule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue).RemotePort)
        if ($oldPorts -and ($oldPorts -notcontains 'Any')) {
            $tcpPorts = @($oldPorts) + @($tcpPorts)
        }
    }
}
$tcpPorts = @($tcpPorts | Where-Object { $_ } | Select-Object -Unique)

Write-Host ('core: ' + (Split-Path -Leaf $coreExe) + '  node: ' + $address + '  protocol=' + $proto + '  network=' + $network) -ForegroundColor Cyan
Write-Host ('allowed IPs: ' + ($ips -join ', '))
Write-Host ('allowed TCP ports: ' + ($tcpPorts -join ', '))
Write-Host ('transport uses UDP: ' + $udp + $(if ($udp) { ' (' + ($baseUdpPorts -join ', ') + ')' } else { '' }))

if ($WhatIfOnly) { Write-Host 'WhatIfOnly: no firewall change made.'; return }
if (-not $isAdmin) { throw 'run elevated to modify firewall rules' }

# TCP
if ($tcpRule) {
    Set-NetFirewallRule -InputObject $tcpRule -Program $coreExe -RemoteAddress $ips -RemotePort $tcpPorts -InterfaceAlias 'Any' -Enabled True -ErrorAction Stop
    Write-Host '[+] AI-Guard-Allow-Node-TCP updated' -ForegroundColor Green
}
else {
    New-NetFirewallRule -Name 'AI-Guard-Allow-Node-TCP' -DisplayName 'AI-Guard-Allow-Node-TCP' `
        -Direction Outbound -Action Allow -Program $coreExe -Protocol TCP `
        -RemoteAddress $ips -RemotePort $tcpPorts -Profile Any -Enabled True | Out-Null
    Write-Host '[+] AI-Guard-Allow-Node-TCP created' -ForegroundColor Green
}

# UDP (hysteria2 / QUIC / KCP / WireGuard / HTTP3 transports)
$udpPorts = @($baseUdpPorts)
$udpRule = Get-NetFirewallRule -DisplayName 'AI-Guard-Allow-Node-UDP' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($udp) {
    if ($udpRule) {
        Set-NetFirewallRule -InputObject $udpRule -Program $coreExe -RemoteAddress $ips -RemotePort $udpPorts -InterfaceAlias 'Any' -Enabled True -ErrorAction Stop
        Write-Host '[+] AI-Guard-Allow-Node-UDP updated' -ForegroundColor Green
    }
    else {
        New-NetFirewallRule -Name 'AI-Guard-Allow-Node-UDP' -DisplayName 'AI-Guard-Allow-Node-UDP' `
            -Direction Outbound -Action Allow -Program $coreExe -Protocol UDP `
            -RemoteAddress $ips -RemotePort $udpPorts -Profile Any -Enabled True | Out-Null
        Write-Host '[+] AI-Guard-Allow-Node-UDP created' -ForegroundColor Green
    }
}
elseif ($udpRule) {
    $udpRule | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Host '[+] AI-Guard-Allow-Node-UDP removed (node uses TCP)' -ForegroundColor Green
}

# Ensure /32 physical host route for proxy node IPs so Xray connects directly on physical NIC (avoids TUN double-hop relay)
try {
    # Clean up stale node /32 host routes if node IP changed
    $nodeMetaOld = Join-Path $Root 'backup\node-sync.meta'
    if (Test-Path -LiteralPath $nodeMetaOld) {
        $oldMetaContent = Get-Content -LiteralPath $nodeMetaOld -Raw -ErrorAction SilentlyContinue
        if ($oldMetaContent -match '\|([\d\.,]+)\|') {
            $prevIps = $Matches[1].Split(',')
            foreach ($pIp in $prevIps) {
                if ($pIp -match '^\d{1,3}(\.\d{1,3}){3}$' -and ($ips -notcontains $pIp)) {
                    Remove-NetRoute -DestinationPrefix ($pIp + '/32') -Confirm:$false -ErrorAction SilentlyContinue
                    Write-Host ('[-] removed stale node host route: ' + $pIp + '/32') -ForegroundColor Yellow
                }
            }
        }
    }
    $physRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -notmatch '(?i)tun|wintun|sing|xray|meta|mihomo|loopback' -and $_.NextHop -ne '0.0.0.0' } |
        Select-Object -First 1
    if ($physRoute -and $physRoute.NextHop) {
        foreach ($nodeIp in $ips) {
            if ($nodeIp -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                $curHostRoute = Get-NetRoute -DestinationPrefix ($nodeIp + '/32') -ErrorAction SilentlyContinue
                if (-not $curHostRoute) {
                    New-NetRoute -DestinationPrefix ($nodeIp + '/32') -InterfaceAlias $physRoute.InterfaceAlias -NextHop $physRoute.NextHop -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null
                    Write-Host ('[+] proxy node physical /32 host route added: ' + $nodeIp + '/32 -> ' + $physRoute.NextHop + ' on ' + $physRoute.InterfaceAlias) -ForegroundColor Green
                }
                elseif ($curHostRoute.NextHop -ne $physRoute.NextHop -or $curHostRoute.InterfaceAlias -ne $physRoute.InterfaceAlias -or $curHostRoute.RouteMetric -ne 1) {
                    Remove-NetRoute -DestinationPrefix ($nodeIp + '/32') -Confirm:$false -ErrorAction SilentlyContinue
                    New-NetRoute -DestinationPrefix ($nodeIp + '/32') -InterfaceAlias $physRoute.InterfaceAlias -NextHop $physRoute.NextHop -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null
                    Write-Host ('[+] proxy node physical /32 host route updated: ' + $nodeIp + '/32 -> ' + $physRoute.NextHop + ' on ' + $physRoute.InterfaceAlias) -ForegroundColor Green
                }
            }
        }
    }
} catch { }

$dohRule = Get-NetFirewallRule -DisplayName 'AI-Guard-Allow-DoH-Ali' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($dohRule) {
    Set-NetFirewallRule -InputObject $dohRule -RemoteAddress @('223.5.5.5', '223.6.6.6') -RemotePort @('443') -Enabled True -ErrorAction SilentlyContinue
}

# Sync companion rules for all other detected cores
foreach ($ck in $allCores.Keys) {
    $cExe = $allCores[$ck]
    if ($cExe -ieq $coreExe) { continue }
    $cName = if ($ck -like '*xray*') { 'Xray' } elseif ($ck -like '*sing*') { 'SingBox' } elseif ($ck -like '*v2rayn*') { 'V2rayN' } else { $ck }
    $cRuleTcp = Get-NetFirewallRule -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-TCP') -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cRuleTcp) {
        Set-NetFirewallRule -InputObject $cRuleTcp -Program $cExe -RemoteAddress $ips -RemotePort $tcpPorts -InterfaceAlias 'Any' -Enabled True -ErrorAction SilentlyContinue
    }
    else {
        New-NetFirewallRule -Name ('AI-Guard-Allow-Core-' + $cName + '-TCP') -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-TCP') `
            -Direction Outbound -Action Allow -Program $cExe -Protocol TCP `
            -RemoteAddress $ips -RemotePort $tcpPorts -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
    }
    if ($udp) {
        $cRuleUdp = Get-NetFirewallRule -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-UDP') -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cRuleUdp) {
            Set-NetFirewallRule -InputObject $cRuleUdp -Program $cExe -RemoteAddress $ips -RemotePort $udpPorts -InterfaceAlias 'Any' -Enabled True -ErrorAction SilentlyContinue
        }
        else {
            New-NetFirewallRule -Name ('AI-Guard-Allow-Core-' + $cName + '-UDP') -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-UDP') `
                -Direction Outbound -Action Allow -Program $cExe -Protocol UDP `
                -RemoteAddress $ips -RemotePort $udpPorts -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
        }
    }
}

$nodeMeta = Join-Path $Root 'backup\node-sync.meta'
New-Item -ItemType Directory -Path (Split-Path $nodeMeta) -Force | Out-Null
$metaLine = ($cfgItem.Length.ToString() + ':' + $cfgItem.LastWriteTimeUtc.Ticks.ToString() + '|' + ($ips -join ',') + '|' + ($tcpPorts -join ',') + '|' + ($udpPorts -join ',') + '|' + $coreExe)
Set-Content -LiteralPath $nodeMeta -Value $metaLine -Encoding ASCII

Get-NetFirewallRule -DisplayName 'AI-Guard-Allow-Node-*' |
    Select-Object DisplayName, Enabled, @{n = 'Program'; e = { Split-Path -Leaf (($_ | Get-NetFirewallApplicationFilter).Program) } }, @{n = 'RemoteAddress'; e = { ($_ | Get-NetFirewallAddressFilter).RemoteAddress -join ',' } }, @{n = 'RemotePort'; e = { ($_ | Get-NetFirewallPortFilter).RemotePort -join ',' } } |
    Format-Table -AutoSize
