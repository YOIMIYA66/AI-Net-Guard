<#
.SYNOPSIS
    AI-Net-Guard v5.9.7 - maintenance: re-sync node allow rule after switching proxy node or core.

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
    [string]$Root = $(if ($PSScriptRoot) { if ((Split-Path -Leaf $PSScriptRoot) -ieq 'scripts') { Split-Path -Parent $PSScriptRoot } else { $PSScriptRoot } } else { 'C:\AI-Net-Guard' }),
    [string]$V2rayNRoot = '',
    [string[]]$ExtraTcpPorts = @(),
    [switch]$ReplacePorts,
    [switch]$IncludeAllNodes,
    [switch]$ClearCandidateNodes,
    [switch]$PruneStaleNodeRoutes,
    [switch]$WhatIfOnly
)

$ErrorActionPreference = 'Stop'
if ($IncludeAllNodes -and $ClearCandidateNodes) {
    throw 'Pass either -IncludeAllNodes or -ClearCandidateNodes, not both.'
}
if (-not $V2rayNRoot) {
    if ($env:V2RAYN_ROOT -and (Test-Path -LiteralPath $env:V2RAYN_ROOT)) { $V2rayNRoot = $env:V2RAYN_ROOT }
    else {
        foreach ($cand in @('D:\v2rayN-windows-64-desktop\v2rayN-windows-64', 'D:\v2rayN-windows-64-desktop', 'C:\v2rayN-windows-64-desktop\v2rayN-windows-64', 'C:\v2rayN-windows-64', 'D:\v2rayN-windows-64', 'C:\v2rayN', 'D:\v2rayN', (Join-Path $env:LOCALAPPDATA 'v2rayN'), 'C:\Program Files\v2rayN')) {
            if ($cand -and ((Test-Path -LiteralPath (Join-Path $cand 'v2rayN.exe')) -or (Test-Path -LiteralPath (Join-Path $cand 'binConfigs')))) { $V2rayNRoot = $cand; break }
        }
        if (-not $V2rayNRoot) { try { $vp = [System.Diagnostics.Process]::GetProcessesByName('v2rayN'); if ($vp.Length -gt 0 -and $vp[0].MainModule.FileName) { $V2rayNRoot = Split-Path -Parent $vp[0].MainModule.FileName } } catch { } }
        if (-not $V2rayNRoot) { $V2rayNRoot = 'C:\v2rayN-windows-64' }
    }
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object Security.Principal.WindowsPrincipal($id)
$isAdmin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$libCommonSync = ''
foreach ($cand in @((Join-Path $PSScriptRoot 'lib-guard-common.ps1'), (Join-Path (Join-Path $Root 'scripts') 'lib-guard-common.ps1'), (Join-Path $Root 'lib-guard-common.ps1'))) {
    if ($cand -and (Test-Path -LiteralPath $cand)) { $libCommonSync = $cand; break }
}
if ($libCommonSync) { . $libCommonSync }

function Resolve-NodeDomainSafe {
    param(
        [string]$Domain,
        [switch]$IncludeIpv6
    )

    $res = @()
    $qTypes = if ($IncludeIpv6) { @('A', 'AAAA') } else { @('A') }
    foreach ($qt in $qTypes) {
        $wantType = if ($qt -eq 'AAAA') { 28 } else { 1 }
        $qtRes = @()
        try {
            if ([int][Net.ServicePointManager]::SecurityProtocol -ne 0) {
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            }
            $uri = 'https://223.5.5.5/resolve?name=' + [uri]::EscapeDataString($Domain) + '&type=' + $qt
            $req = [System.Net.HttpWebRequest]::Create($uri)
            $req.Proxy = $null
            $req.Timeout = 4000
            $req.ReadWriteTimeout = 4000
            $resp = $req.GetResponse()
            try {
                $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
                $json = $sr.ReadToEnd() | ConvertFrom-Json
                foreach ($ans in @($json.Answer)) {
                    if (-not $ans -or [int]$ans.type -ne $wantType) { continue }
                    $d = [string]$ans.data
                    if ($wantType -eq 1 -and (Test-GuardPublicNodeIpv4 -IpStr $d)) {
                        $qtRes += $d.Trim()
                    }
                    elseif ($wantType -eq 28 -and (Test-GuardPublicNodeIpv6 -IpStr $d)) {
                        $qtRes += ([System.Net.IPAddress]::Parse($d.Trim().Trim('[', ']'))).IPAddressToString.ToLowerInvariant()
                    }
                }
            }
            finally { $resp.Close() }
        }
        catch { }
        if ($qtRes.Count -eq 0) {
            try {
                foreach ($dnsRec in @(Resolve-DnsName -Name $Domain -Type $qt -ErrorAction Stop | Where-Object { $_.IPAddress })) {
                    $ipText = [string]$dnsRec.IPAddress
                    if ($wantType -eq 1 -and (Test-GuardPublicNodeIpv4 -IpStr $ipText)) {
                        $qtRes += $ipText.Trim()
                    }
                    elseif ($wantType -eq 28 -and (Test-GuardPublicNodeIpv6 -IpStr $ipText)) {
                        $qtRes += ([System.Net.IPAddress]::Parse($ipText.Trim().Trim('[', ']'))).IPAddressToString.ToLowerInvariant()
                    }
                }
            }
            catch { }
        }
        $res += @($qtRes)
    }
    if (-not $IncludeIpv6 -and $res.Count -eq 0) {
        throw ('cannot resolve A record for domain: ' + $Domain)
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

function Get-V2rayNCandidateNodes {
    param(
        [Parameter(Mandatory = $true)][string]$DbPath,
        [switch]$IncludeIpv6
    )

    if (-not (Test-Path -LiteralPath $DbPath)) {
        throw ('missing v2rayN database: ' + $DbPath)
    }
    $pyExe = ''
    foreach ($candPy in @('python', 'python3', 'py')) {
        $cmdPy = Get-Command $candPy -ErrorAction SilentlyContinue
        if ($cmdPy) { $pyExe = $cmdPy.Source; break }
    }
    if (-not $pyExe) {
        throw 'python 3 is required to read guiNDB.db in read-only mode'
    }

    $pySrc = @'
import json
import sqlite3
import sys

db_path = sys.argv[1]
uri = 'file:%s?mode=ro' % db_path.replace('%', '%25').replace('?', '%3f').replace('#', '%23')
con = sqlite3.connect(uri, uri=True, timeout=5)
try:
    cur = con.cursor()
    cols = {str(c[1]).lower(): str(c[1]) for c in cur.execute("PRAGMA table_info(ProfileItem)").fetchall()}
    sel = [
        cols.get('configtype', 'ConfigType'),
        cols.get('address', 'Address'),
        cols.get('port', 'Port'),
        cols['ports'] if 'ports' in cols else "''",
        cols['network'] if 'network' in cols else "''",
        cols['alpn'] if 'alpn' in cols else "''",
        cols['protoextra'] if 'protoextra' in cols else "''",
    ]
    sql = (
        "SELECT " + ", ".join(sel) + " FROM ProfileItem "
        "WHERE Address IS NOT NULL AND Address != '' AND Port IS NOT NULL AND Port > 0"
    )
    rows = cur.execute(sql).fetchall()
    out = []
    for r in rows:
        port_parts = []
        if r[3]:
            port_parts.append(str(r[3]).strip())
        if r[6]:
            try:
                pe = json.loads(str(r[6]))
                if isinstance(pe, dict):
                    ep = pe.get('Ports')
                    if ep is None:
                        ep = pe.get('ports')
                    if isinstance(ep, list):
                        for item in ep:
                            if item is not None and str(item).strip():
                                port_parts.append(str(item).strip())
                    elif ep is not None and str(ep).strip():
                        port_parts.append(str(ep).strip())
            except Exception:
                pass
        out.append({
            'ConfigType': int(r[0]) if r[0] is not None else 0,
            'Address': str(r[1]).strip(),
            'Port': int(r[2]),
            'Ports': ','.join([p for p in port_parts if p]),
            'Network': str(r[4]).strip() if r[4] is not None else '',
            'Alpn': str(r[5]).strip() if r[5] is not None else '',
        })
    print(json.dumps(out, ensure_ascii=True))
finally:
    con.close()
'@
    $tmpPy = Join-Path ([System.IO.Path]::GetTempPath()) ('ai-guard-cand-' + $PID + '.py')
    [System.IO.File]::WriteAllText($tmpPy, $pySrc, (New-Object System.Text.UTF8Encoding($false)))
    try {
        $jsonOut = & $pyExe $tmpPy $DbPath
        if ($LASTEXITCODE -ne 0) {
            throw ('failed reading guiNDB.db (exit ' + $LASTEXITCODE + ')')
        }
    }
    finally {
        Remove-Item -LiteralPath $tmpPy -Force -ErrorAction SilentlyContinue
    }

    $rows = @($jsonOut | ConvertFrom-Json)
    if ($rows.Count -eq 1 -and ($rows[0] -is [System.Array])) {
        $rows = @($rows[0])
    }
    $addrSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $addrList = New-Object System.Collections.Generic.List[string]
    $tcpSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $udpSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)

    foreach ($row in $rows) {
        $ct = [int]$row.ConfigType
        if ($ct -ge 100) { continue }
        $addr = ([string]$row.Address).Trim().Trim('[', ']')
        if (-not $addr) { continue }
        if ($addr -match '^(?i)localhost$') { continue }
        if ($addr -match '^\d{1,3}(\.\d{1,3}){3}$') {
            if (-not (Test-GuardPublicNodeIpv4 -IpStr $addr)) { continue }
        }
        elseif ($addr -like '*:*') {
            if (-not $IncludeIpv6 -or -not (Test-GuardPublicNodeIpv6 -IpStr $addr)) { continue }
            $addr = ([System.Net.IPAddress]::Parse($addr)).IPAddressToString.ToLowerInvariant()
        }
        [void]$addrSet.Add($addr)
        if (-not $addrList.Contains($addr)) { [void]$addrList.Add($addr) }

        $pStr = [string]$row.Port
        if (Test-GuardPortSpec -Spec $pStr) {
            if ($ct -in @(7, 8, 9)) {
                [void]$udpSet.Add($pStr)
                [void]$tcpSet.Add($pStr)
            }
            else {
                [void]$tcpSet.Add($pStr)
                $net = [string]$row.Network
                $alpn = [string]$row.Alpn
                if (($net -match '(?i)quic|kcp|hysteria|wireguard') -or ($alpn -match '(?i)\bh3\b')) {
                    [void]$udpSet.Add($pStr)
                }
            }
        }
        if ($row.Ports) {
            foreach ($seg in @(([string]$row.Ports).Split([char[]]@(',', ';', ' ', "`t"), [System.StringSplitOptions]::RemoveEmptyEntries))) {
                $normSeg = $seg.Trim().Replace(':', '-')
                if (Test-GuardPortSpec -Spec $normSeg) {
                    if ($ct -in @(7, 8, 9)) { [void]$udpSet.Add($normSeg) }
                    else { [void]$tcpSet.Add($normSeg) }
                }
            }
        }
    }

    $ipSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $resolvedIps = New-Object System.Collections.Generic.List[string]
    $v6Set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $resolvedIpv6 = New-Object System.Collections.Generic.List[string]
    $unresolvedDomains = 0
    foreach ($a in $addrList) {
        if ($a -match '^\d{1,3}(\.\d{1,3}){3}$') {
            if ((Test-GuardPublicNodeIpv4 -IpStr $a) -and $ipSet.Add($a)) { [void]$resolvedIps.Add($a) }
        }
        elseif ($a -like '*:*') {
            if ($IncludeIpv6 -and (Test-GuardPublicNodeIpv6 -IpStr $a)) {
                $normV6 = ([System.Net.IPAddress]::Parse($a)).IPAddressToString.ToLowerInvariant()
                if ($v6Set.Add($normV6)) { [void]$resolvedIpv6.Add($normV6) }
            }
        }
        else {
            try {
                $gotAny = $false
                foreach ($rip in @(Resolve-NodeDomainSafe -Domain $a -IncludeIpv6:$IncludeIpv6)) {
                    if ((Test-GuardPublicNodeIpv4 -IpStr $rip) -and $ipSet.Add($rip)) {
                        [void]$resolvedIps.Add($rip)
                        $gotAny = $true
                    }
                    elseif ($IncludeIpv6 -and (Test-GuardPublicNodeIpv6 -IpStr $rip)) {
                        $normV6 = ([System.Net.IPAddress]::Parse($rip)).IPAddressToString.ToLowerInvariant()
                        if ($v6Set.Add($normV6)) { [void]$resolvedIpv6.Add($normV6) }
                        $gotAny = $true
                    }
                }
                if (-not $gotAny) { $unresolvedDomains++ }
            }
            catch {
                $unresolvedDomains++
            }
        }
    }

    $rawTcpArr = New-Object string[] $tcpSet.Count
    $tcpSet.CopyTo($rawTcpArr)
    $rawUdpArr = New-Object string[] $udpSet.Count
    $udpSet.CopyTo($rawUdpArr)
    $mergedTcp = Merge-GuardPortSpecs -Specs $rawTcpArr
    $mergedUdp = Merge-GuardPortSpecs -Specs $rawUdpArr
    return [pscustomobject]@{
        ProfileCount      = $rows.Count
        UniqueAddresses   = $addrList.Count
        Ips               = [string[]]($resolvedIps.ToArray() | Sort-Object)
        Ipv6Ips           = [string[]]($resolvedIpv6.ToArray() | Sort-Object)
        TcpPorts          = [string[]]$mergedTcp
        UdpPorts          = [string[]]$mergedUdp
        UnresolvedDomains = $unresolvedDomains
    }
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
    $sList = @($cfg.outbounds | Where-Object { $_.type -in @('hysteria2', 'hysteria', 'tuic', 'vless', 'vmess', 'trojan', 'shadowsocks', 'wireguard', 'anytls', 'socks', 'http') })
    if ($sList.Count -eq 0) { throw 'no proxy outbound found in config.json (checked Xray and sing-box schemas)' }
    $sNode = $sList[0]
    $coreType = 'sing-box'
    $addresses = @()
    $ports = @()
    $baseTcpPorts = @()
    $udp = $false
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
        if ($ia) { $addresses += $ia }
        $ipList = @($ipList | Where-Object { $_ } | Select-Object -Unique)
        if ($ipList.Count -gt 0) {
            $ports += $ipList
            $pType = [string]$item.type
            $pNet = if ($item.transport -and $item.transport.type) { [string]$item.transport.type } else { $pType }
            $pAlpn = @()
            try { if ($item.tls -and $item.tls.alpn) { $pAlpn += @($item.tls.alpn) } } catch { }
            if (($pType -in @('hysteria2', 'hysteria', 'tuic', 'wireguard')) -or ($pNet -match '(?i)quic') -or ($pAlpn -contains 'h3')) {
                $udp = $true
            }
            if ($pType -in @('hysteria2', 'hysteria', 'tuic', 'wireguard')) { $baseTcpPorts += $ipList[0] }
            else { $baseTcpPorts += $ipList }
        }
    }
    $addresses = @($addresses | Where-Object { $_ } | Select-Object -Unique)
    $ports = @($ports | Where-Object { $_ } | Select-Object -Unique)
    $baseTcpPorts = @($baseTcpPorts | Where-Object { $_ } | Select-Object -Unique)
    $address = if ($addresses.Count -gt 0) { $addresses[0] } else { '' }
    $proto = [string]$sNode.type
    $network = if ($sNode.transport -and $sNode.transport.type) { [string]$sNode.transport.type } else { $proto }
    if ($udp) { $baseUdpPorts = @($ports) }
}

if (-not $address) { throw 'cannot find node address in config.json' }
$coreExe = Resolve-CoreExe -CoreType $coreType

$allowCn = $true; $allowLan = $true; $allowNcsi = $true; $blockPhysIpv6 = $true
$polPath = Join-Path $Root 'backup\guard-policy.json'
if (Test-Path -LiteralPath $polPath) {
    try {
        $rawP = Get-Content -LiteralPath $polPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($rawP) {
            if ($rawP.PSObject.Properties.Name -contains 'AllowCnDirect' -and ($rawP.AllowCnDirect -is [bool])) { $allowCn = [bool]$rawP.AllowCnDirect }
            if ($rawP.PSObject.Properties.Name -contains 'AllowLan' -and ($rawP.AllowLan -is [bool])) { $allowLan = [bool]$rawP.AllowLan }
            if ($rawP.PSObject.Properties.Name -contains 'AllowNcsi' -and ($rawP.AllowNcsi -is [bool])) { $allowNcsi = [bool]$rawP.AllowNcsi }
            if ($rawP.PSObject.Properties.Name -contains 'DisablePhysicalIpv6' -and ($rawP.DisablePhysicalIpv6 -is [bool])) { $blockPhysIpv6 = [bool]$rawP.DisablePhysicalIpv6 }
        }
    } catch { }
}
$allowIpv6Nodes = (-not $blockPhysIpv6)

$rawAddrList = if ($addresses -and $addresses.Count -gt 0) { $addresses } else { @($address) }
$ips = @()
$usedDomain = $false
foreach ($raItem in $rawAddrList) {
    if (-not $raItem) { continue }
    $cleanRa = ([string]$raItem).Trim().Trim('[', ']')
    if ($cleanRa -match '^\d{1,3}(\.\d{1,3}){3}$') {
        $ips += @($cleanRa)
    }
    elseif ($cleanRa -like '*:*') {
        if ($allowIpv6Nodes -and (Test-GuardPublicNodeIpv6 -IpStr $cleanRa)) {
            $ips += @(([System.Net.IPAddress]::Parse($cleanRa)).IPAddressToString.ToLowerInvariant())
        }
    }
    else {
        $usedDomain = $true
        $ips += @(Resolve-NodeDomainSafe -Domain $cleanRa -IncludeIpv6:$allowIpv6Nodes)
    }
}
if ($ips.Count -eq 0) { throw ('cannot resolve node address: ' + $address) }

# Only active config.json outbounds are authorized (ignore transient configTest*.json)
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

$candFile = Join-Path $Root 'backup\candidate-nodes.json'
$candPreview = $null
if ($IncludeAllNodes) {
    $dbPath = Join-Path $V2rayNRoot 'guiConfigs\guiNDB.db'
    Write-Host ('scanning candidate nodes (read-only): ' + $dbPath) -ForegroundColor Cyan
    $candPreview = Get-V2rayNCandidateNodes -DbPath $dbPath -IncludeIpv6:$allowIpv6Nodes
    $v6Cnt = if ($candPreview.PSObject.Properties['Ipv6Ips']) { $candPreview.Ipv6Ips.Count } else { 0 }
    Write-Host ('candidate nodes: profiles=' + $candPreview.ProfileCount + ', uniqueAddresses=' + $candPreview.UniqueAddresses + ', resolvedIPs=' + $candPreview.Ips.Count + $(if ($v6Cnt -gt 0) { ', resolvedIPv6=' + $v6Cnt } else { '' }) + ', unresolvedDomains=' + $candPreview.UnresolvedDomains) -ForegroundColor Cyan
    Write-Host ('candidate TCP ports: ' + $(if ($candPreview.TcpPorts.Count -gt 0) { $candPreview.TcpPorts -join ', ' } else { '(none)' }))
    Write-Host ('candidate UDP ports: ' + $(if ($candPreview.UdpPorts.Count -gt 0) { $candPreview.UdpPorts -join ', ' } else { '(none)' }))
}
elseif ($ClearCandidateNodes) {
    Write-Host 'candidate nodes: will CLEAR backup\candidate-nodes.json and remove AI-Guard-Allow-Candidates-* rules' -ForegroundColor Yellow
}

if ($WhatIfOnly) { Write-Host 'WhatIfOnly: no firewall change made.'; return }
if (-not $isAdmin) { throw 'run elevated to modify firewall rules' }

$syncWriteLock = $null
if (Get-Command Enter-GuardWriteLock -ErrorAction SilentlyContinue) {
    $syncWriteLock = Enter-GuardWriteLock -TimeoutMs 30000
}
try {

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

# Ensure /32 physical host route for proxy node IPs (ActiveStore only - never PersistentStore)
$nodeRoutesMeta = Join-Path $Root 'backup\node-routes.meta'
try {
    $staleCandidates = @()
    $nodeMetaOld = Join-Path $Root 'backup\node-sync.meta'
    if (Test-Path -LiteralPath $nodeMetaOld) {
        $oldMetaContent = Get-Content -LiteralPath $nodeMetaOld -Raw -ErrorAction SilentlyContinue
        if ($oldMetaContent -match '\|([\d\.,]+)\|') {
            $staleCandidates += @($Matches[1].Split(','))
        }
    }
    if (Test-Path -LiteralPath $nodeRoutesMeta) {
        $oldRoutesRaw = [System.IO.File]::ReadAllText($nodeRoutesMeta, [System.Text.Encoding]::UTF8).Trim()
        if ($oldRoutesRaw) {
            $staleCandidates += @($oldRoutesRaw.Split(','))
        }
    }
    $staleCandidatesV4 = @($staleCandidates | Where-Object { $_ -and ($_ -match '^\d{1,3}(\.\d{1,3}){3}$') } | Select-Object -Unique)
    foreach ($pIp in $staleCandidatesV4) {
        if ($ips -notcontains $pIp) {
            Remove-NetRoute -DestinationPrefix ($pIp + '/32') -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
            Remove-NetRoute -DestinationPrefix ($pIp + '/32') -PolicyStore PersistentStore -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host ('[-] removed stale node host route: ' + $pIp + '/32') -ForegroundColor Yellow
        }
    }
    $staleCandidatesV6 = @($staleCandidates | Where-Object { $_ -and (Test-GuardPublicNodeIpv6 -IpStr $_) } | ForEach-Object { ([System.Net.IPAddress]::Parse($_)).IPAddressToString.ToLowerInvariant() } | Select-Object -Unique)
    foreach ($pV6 in $staleCandidatesV6) {
        if ($ips -notcontains $pV6) {
            Remove-NetRoute -DestinationPrefix ($pV6 + '/128') -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
            Remove-NetRoute -DestinationPrefix ($pV6 + '/128') -PolicyStore PersistentStore -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host ('[-] removed stale node IPv6 host route: ' + $pV6 + '/128') -ForegroundColor Yellow
        }
    }

    if ($PruneStaleNodeRoutes) {
        $persistRoutes = @(Get-NetRoute -PolicyStore PersistentStore -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.DestinationPrefix -like '*/32' -and
                $_.RouteMetric -eq 1 -and
                $_.InterfaceAlias -notmatch '(?i)tun|wintun|sing|xray|meta|mihomo|loopback'
            })
        $toDropPersist = New-Object System.Collections.Generic.List[object]
        $toDropActiveSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($pr in $persistRoutes) {
            $rip = ($pr.DestinationPrefix -split '/')[0]
            if (-not $rip -or ($rip -notmatch '^\d{1,3}(\.\d{1,3}){3}$')) { continue }
            if ($rip -match '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)') { continue }
            $oct0 = [int]($rip.Split('.')[0])
            if ($oct0 -ge 224) { continue }
            $toDropPersist.Add($pr)
            if ($ips -notcontains $rip) {
                [void]$toDropActiveSet.Add($pr.DestinationPrefix)
            }
        }
        if ($toDropPersist.Count -gt 0) {
            $toDropPersist | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        }
        if ($toDropActiveSet.Count -gt 0) {
            @(Get-NetRoute -PolicyStore ActiveStore -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object {
                    $toDropActiveSet.Contains($_.DestinationPrefix) -and
                    $_.RouteMetric -eq 1 -and
                    $_.InterfaceAlias -notmatch '(?i)tun|wintun|sing|xray|meta|mihomo|loopback'
                }) | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        }
        Write-Host ('[-] pruned orphaned PersistentStore /32 host routes: ' + $toDropPersist.Count) -ForegroundColor Green
    }

    $physRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -notmatch '(?i)tun|wintun|sing|xray|meta|mihomo|loopback' -and $_.NextHop -ne '0.0.0.0' } |
        Select-Object -First 1
    if ($physRoute -and $physRoute.NextHop) {
        foreach ($nodeIp in $ips) {
            if ($nodeIp -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                # Never leave a PersistentStore duplicate for active node either
                Remove-NetRoute -DestinationPrefix ($nodeIp + '/32') -PolicyStore PersistentStore -Confirm:$false -ErrorAction SilentlyContinue
                $curHostRoute = @(Get-NetRoute -DestinationPrefix ($nodeIp + '/32') -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
                if ($curHostRoute.Count -eq 0) {
                    New-NetRoute -DestinationPrefix ($nodeIp + '/32') -InterfaceAlias $physRoute.InterfaceAlias -NextHop $physRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
                    Write-Host ('[+] proxy node physical /32 host route added (ActiveStore): ' + $nodeIp + '/32 -> ' + $physRoute.NextHop + ' on ' + $physRoute.InterfaceAlias) -ForegroundColor Green
                }
                elseif ($curHostRoute[0].NextHop -ne $physRoute.NextHop -or $curHostRoute[0].InterfaceAlias -ne $physRoute.InterfaceAlias -or $curHostRoute[0].RouteMetric -ne 1) {
                    Remove-NetRoute -DestinationPrefix ($nodeIp + '/32') -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
                    New-NetRoute -DestinationPrefix ($nodeIp + '/32') -InterfaceAlias $physRoute.InterfaceAlias -NextHop $physRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
                    Write-Host ('[+] proxy node physical /32 host route updated (ActiveStore): ' + $nodeIp + '/32 -> ' + $physRoute.NextHop + ' on ' + $physRoute.InterfaceAlias) -ForegroundColor Green
                }
            }
        }
    }
    $physRouteV6 = Get-NetRoute -DestinationPrefix '::/0' -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -notmatch '(?i)tun|wintun|sing|xray|meta|mihomo|loopback' -and $_.NextHop -ne '::' } |
        Select-Object -First 1
    if ($allowIpv6Nodes -and $physRouteV6 -and $physRouteV6.NextHop) {
        foreach ($nodeV6 in @($ips | Where-Object { Test-GuardPublicNodeIpv6 -IpStr $_ })) {
            Remove-NetRoute -DestinationPrefix ($nodeV6 + '/128') -PolicyStore PersistentStore -Confirm:$false -ErrorAction SilentlyContinue
            $curV6Route = @(Get-NetRoute -DestinationPrefix ($nodeV6 + '/128') -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
            if ($curV6Route.Count -eq 0) {
                New-NetRoute -DestinationPrefix ($nodeV6 + '/128') -InterfaceAlias $physRouteV6.InterfaceAlias -NextHop $physRouteV6.NextHop -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
                Write-Host ('[+] proxy node physical /128 IPv6 route added (ActiveStore): ' + $nodeV6 + '/128 -> ' + $physRouteV6.NextHop + ' on ' + $physRouteV6.InterfaceAlias) -ForegroundColor Green
            }
            elseif ($curV6Route[0].NextHop -ne $physRouteV6.NextHop -or $curV6Route[0].InterfaceAlias -ne $physRouteV6.InterfaceAlias -or $curV6Route[0].RouteMetric -ne 1) {
                Remove-NetRoute -DestinationPrefix ($nodeV6 + '/128') -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
                New-NetRoute -DestinationPrefix ($nodeV6 + '/128') -InterfaceAlias $physRouteV6.InterfaceAlias -NextHop $physRouteV6.NextHop -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
                Write-Host ('[+] proxy node physical /128 IPv6 route updated (ActiveStore): ' + $nodeV6 + '/128 -> ' + $physRouteV6.NextHop + ' on ' + $physRouteV6.InterfaceAlias) -ForegroundColor Green
            }
        }
    }
    New-Item -ItemType Directory -Path (Split-Path $nodeRoutesMeta) -Force | Out-Null
    [System.IO.File]::WriteAllText($nodeRoutesMeta, ($ips -join ','), (New-Object System.Text.UTF8Encoding($false)))
} catch { }

$dohRule = Get-NetFirewallRule -DisplayName 'AI-Guard-Allow-DoH-Ali' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($dohRule) {
    Set-NetFirewallRule -InputObject $dohRule -Program $coreExe -RemoteAddress @('223.5.5.5', '223.6.6.6') -RemotePort @('443') -Enabled True -ErrorAction SilentlyContinue
}

# Sync companion rules (TCP/UDP node + AliDNS DoH) for standby cores, and prune redundant Core-* rules for active core
foreach ($ck in $allCores.Keys) {
    $cExe = $allCores[$ck]
    $cName = if ($ck -like '*xray*') { 'Xray' } elseif ($ck -like '*sing*') { 'SingBox' } elseif ($ck -like '*v2rayn*') { 'V2rayN' } else { $ck }
    if ($cExe -ieq $coreExe) {
        foreach ($sfx in @('TCP', 'UDP', 'DoH')) {
            $dup = Get-NetFirewallRule -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-' + $sfx) -ErrorAction SilentlyContinue
            if ($dup) { $dup | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
        }
        continue
    }
    $cRuleTcp = Get-NetFirewallRule -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-TCP') -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cRuleTcp) {
        Set-NetFirewallRule -InputObject $cRuleTcp -Program $cExe -RemoteAddress $ips -RemotePort $tcpPorts -InterfaceAlias 'Any' -Enabled True -ErrorAction SilentlyContinue
    }
    else {
        New-NetFirewallRule -Name ('AI-Guard-Allow-Core-' + $cName + '-TCP') -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-TCP') `
            -Direction Outbound -Action Allow -Program $cExe -Protocol TCP `
            -RemoteAddress $ips -RemotePort $tcpPorts -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
    }
    $cRuleUdp = Get-NetFirewallRule -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-UDP') -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($udp) {
        if ($cRuleUdp) {
            Set-NetFirewallRule -InputObject $cRuleUdp -Program $cExe -RemoteAddress $ips -RemotePort $udpPorts -InterfaceAlias 'Any' -Enabled True -ErrorAction SilentlyContinue
        }
        else {
            New-NetFirewallRule -Name ('AI-Guard-Allow-Core-' + $cName + '-UDP') -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-UDP') `
                -Direction Outbound -Action Allow -Program $cExe -Protocol UDP `
                -RemoteAddress $ips -RemotePort $udpPorts -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
        }
    }
    elseif ($cRuleUdp) {
        $cRuleUdp | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }
    $cRuleDoh = Get-NetFirewallRule -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-DoH') -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cRuleDoh) {
        Set-NetFirewallRule -InputObject $cRuleDoh -Program $cExe -RemoteAddress @('223.5.5.5', '223.6.6.6') -RemotePort @('443') -InterfaceAlias 'Any' -Enabled True -ErrorAction SilentlyContinue
    }
    else {
        New-NetFirewallRule -Name ('AI-Guard-Allow-Core-' + $cName + '-DoH') -DisplayName ('AI-Guard-Allow-Core-' + $cName + '-DoH') `
            -Direction Outbound -Action Allow -Program $cExe -Protocol TCP `
            -RemoteAddress @('223.5.5.5', '223.6.6.6') -RemotePort @('443') -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
    }
}
if (-not $udp) {
    Get-NetFirewallRule -DisplayName 'AI-Guard-Allow-Core-*-UDP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

$nodeMeta = Join-Path $Root 'backup\node-sync.meta'
New-Item -ItemType Directory -Path (Split-Path $nodeMeta) -Force | Out-Null
$domainTag = if ($usedDomain) { '|domain' } else { '|ip' }
$metaLine = ($cfgItem.Length.ToString() + ':' + $cfgItem.LastWriteTimeUtc.Ticks.ToString() + '|' + ($ips -join ',') + '|' + ($tcpPorts -join ',') + '|' + ($udpPorts -join ',') + '|' + $coreExe + $domainTag)
Set-Content -LiteralPath $nodeMeta -Value $metaLine -Encoding ASCII

# Optional opt-in candidate subscription node rules (AI-Guard-Allow-Candidates-*)
if ($ClearCandidateNodes) {
    if (Test-Path -LiteralPath $candFile) {
        Remove-Item -LiteralPath $candFile -Force -ErrorAction SilentlyContinue
    }
    @(Get-NetFirewallRule -DisplayName 'AI-Guard-Allow-Candidates-*' -ErrorAction SilentlyContinue) |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Host '[+] cleared candidate node allowlist and AI-Guard-Allow-Candidates-* rules' -ForegroundColor Green
}
elseif ($IncludeAllNodes -and $candPreview) {
    $candIpv6 = if ($candPreview.PSObject.Properties['Ipv6Ips']) { @($candPreview.Ipv6Ips) } else { @() }
    $candAllIps = @(@($candPreview.Ips) + @($candIpv6) | Where-Object { $_ } | Select-Object -Unique)
    if ($candAllIps.Count -eq 0) {
        throw 'no valid public candidate node IPs found in guiNDB.db; refusing to clear/write empty candidate rules'
    }
    Write-GuardCandidateNodes -Path $candFile -Ips $candPreview.Ips -Ipv6Ips $candIpv6 -TcpPorts $candPreview.TcpPorts -UdpPorts $candPreview.UdpPorts
    foreach ($ck in $allCores.Keys) {
        $cExe = $allCores[$ck]
        $cName = if ($ck -like '*xray*') { 'Xray' } elseif ($ck -like '*sing*') { 'SingBox' } elseif ($ck -like '*v2rayn*') { 'V2rayN' } else { $ck }
        $candTcpName = 'AI-Guard-Allow-Candidates-' + $cName + '-TCP'
        $candUdpName = 'AI-Guard-Allow-Candidates-' + $cName + '-UDP'
        $candTcpRule = Get-NetFirewallRule -DisplayName $candTcpName -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($candPreview.TcpPorts.Count -gt 0) {
            if ($candTcpRule) {
                Set-NetFirewallRule -InputObject $candTcpRule -Program $cExe -RemoteAddress $candAllIps -RemotePort $candPreview.TcpPorts -InterfaceAlias 'Any' -Enabled True -ErrorAction Stop
            }
            else {
                New-NetFirewallRule -Name $candTcpName -DisplayName $candTcpName `
                    -Direction Outbound -Action Allow -Program $cExe -Protocol TCP `
                    -RemoteAddress $candAllIps -RemotePort $candPreview.TcpPorts -Profile Any -Enabled True -ErrorAction Stop | Out-Null
            }
        }
        elseif ($candTcpRule) {
            $candTcpRule | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        }

        $candUdpRule = Get-NetFirewallRule -DisplayName $candUdpName -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($candPreview.UdpPorts.Count -gt 0) {
            if ($candUdpRule) {
                Set-NetFirewallRule -InputObject $candUdpRule -Program $cExe -RemoteAddress $candAllIps -RemotePort $candPreview.UdpPorts -InterfaceAlias 'Any' -Enabled True -ErrorAction Stop
            }
            else {
                New-NetFirewallRule -Name $candUdpName -DisplayName $candUdpName `
                    -Direction Outbound -Action Allow -Program $cExe -Protocol UDP `
                    -RemoteAddress $candAllIps -RemotePort $candPreview.UdpPorts -Profile Any -Enabled True -ErrorAction Stop | Out-Null
            }
        }
        elseif ($candUdpRule) {
            $candUdpRule | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        }
    }
    Write-Host ('[+] AI-Guard-Allow-Candidates-* updated (' + $candPreview.Ips.Count + ' IPv4 + ' + $candIpv6.Count + ' IPv6 across ' + $allCores.Count + ' core binary/binaries)') -ForegroundColor Green
}

$foreignNodeIps = @($ips | Where-Object { $_ -and ($_ -match '^\d{1,3}(\.\d{1,3}){3}$') })
if (Get-Command Read-GuardCandidateNodes -ErrorAction SilentlyContinue) {
    $candStored = Read-GuardCandidateNodes -Path $candFile
    if ($candStored.Enabled -and $candStored.Ips.Count -gt 0) {
        $foreignNodeIps = @($foreignNodeIps + @($candStored.Ips) | Sort-Object -Unique)
    }
}

# Sync explicit physical-NIC foreign IPv4 block rule with active (+ opt-in candidate) node IPs
try {
    $libForeign = if ($PSScriptRoot -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'lib-foreign-block.ps1'))) {
        Join-Path $PSScriptRoot 'lib-foreign-block.ps1'
    }
    else {
        Join-Path $Root 'scripts\lib-foreign-block.ps1'
    }
    if (Test-Path -LiteralPath $libForeign) {
        . $libForeign
        $physAliases = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
            $_.Status -ne 'Not Present' -and
            $_.InterfaceDescription -notmatch '(?i)Wintun|sing-tun|Mihomo|Loopback' -and
            $_.Name -notmatch '(?i)tun|loopback|xray|singbox|mihomo'
        } | Select-Object -ExpandProperty Name)
        if ($physAliases.Count -gt 0) {
            if (Sync-ForeignPhysicalBlockRule -Root $Root -PhysicalAliases $physAliases -NodeIps $foreignNodeIps `
                -AllowCnDirect $allowCn -AllowLan $allowLan -AllowNcsi $allowNcsi -BlockPhysicalIpv6 $blockPhysIpv6) {
                Write-Host '[+] AI-Guard-Block-Foreign-Physical updated for new node/policy' -ForegroundColor Green
            }
        }
    }
}
catch { }

Get-NetFirewallRule -DisplayName 'AI-Guard-Allow-Node-*' |
    Select-Object DisplayName, Enabled, @{n = 'Program'; e = { Split-Path -Leaf (($_ | Get-NetFirewallApplicationFilter).Program) } }, @{n = 'RemoteAddress'; e = { ($_ | Get-NetFirewallAddressFilter).RemoteAddress -join ',' } }, @{n = 'RemotePort'; e = { ($_ | Get-NetFirewallPortFilter).RemotePort -join ',' } } |
    Format-Table -AutoSize
}
finally {
    if (Get-Command Exit-GuardWriteLock -ErrorAction SilentlyContinue) {
        Exit-GuardWriteLock $syncWriteLock
    }
}
