<#
.SYNOPSIS
    AI-Net-Guard v5.6 - acceptance test: does xray.exe's own "direct" outbound
    bypass the node allow list? (run as Administrator, AFTER 02-killswitch.ps1)

.DESCRIPTION
    Xray's TUN leak protection installs a hard permit for its own executable
    (see 04-wfp-audit.ps1). If that is true on this machine, then with
    DefaultOutboundAction = Block and only node:ports allowed for xray.exe,
    xray should STILL be able to dial any public IP directly.

    This script detects exactly that: it watches xray's established TCP
    connections while you browse Chinese sites in "Whitelist" routing mode
    (geosite:cn -> direct). Any xray connection to a public address that is
    not the node / the AliDNS DoH servers / private / loopback proves the
    exemption.

    Two outcomes:
      * "BYPASS CONFIRMED"  -> Windows Firewall cannot constrain Xray. Enforce
        xray's egress at the router, or disable autoSystemWfpBlockLeak.
      * "no direct egress"  -> either routing was not direct, or the permit is
        absent; re-check with 04-wfp-audit.ps1 and verify the routing profile.

    READ-ONLY: it only reads firewall state, the generated config and the TCP
    table. Nothing is changed.
#>

[CmdletBinding()]
param(
    [string]$Root = $(if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\AI-Net-Guard' }),
    [string]$V2rayNRoot = '',
    [int]$Seconds = 60,
    [string[]]$NodePorts = @()
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
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'ERROR: run this script in an elevated PowerShell.' -ForegroundColor Red
    exit 1
}

$logDir = Join-Path $Root 'logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$report = Join-Path $logDir ('xray-direct-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')

function Log {
    param([string]$msg = '', [string]$ForegroundColor = '')
    if ($ForegroundColor) { Write-Host $msg -ForegroundColor $ForegroundColor }
    else { Write-Host $msg }
    Add-Content -LiteralPath $report -Value $msg -Encoding UTF8
}

function Get-NodeEndpoint {
    param($Cfg)
    $n = $Cfg.outbounds | Where-Object { $_.protocol -in @('vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'wireguard') } | Select-Object -First 1
    if (-not $n) { throw 'no proxy outbound in config.json' }
    $a = [string]$n.settings.address
    if (-not $a -and $n.settings.vnext) { $a = [string]$n.settings.vnext[0].address }
    if (-not $a -and $n.settings.servers) { $a = [string]$n.settings.servers[0].address }
    [pscustomobject]@{ Address = $a; Protocol = [string]$n.protocol }
}

Write-Host ''
Write-Host 'Xray direct-egress test' -ForegroundColor Cyan
Write-Host ''

# ---------------------------------------------------------------- preconditions
$prof = @(Get-NetFirewallProfile | Where-Object { $_.DefaultOutboundAction -ne 'Block' })
if ($prof.Count -gt 0) {
    Write-Host 'WARNING: default outbound is not Block yet. The test is meaningless before 02-killswitch.ps1.' -ForegroundColor Yellow
}

$tun = Get-NetAdapter -Name 'xray_tun' -ErrorAction SilentlyContinue
if (-not $tun -or $tun.Status -ne 'Up') {
    Write-Host 'ERROR: xray_tun is not up. Turn TUN on first (this test needs the WFP filters).' -ForegroundColor Red
    exit 1
}

$xray = Get-Process -Name xray -ErrorAction SilentlyContinue
if (-not $xray) { Write-Host 'ERROR: xray.exe is not running.' -ForegroundColor Red; exit 1 }
$xrayPid = @($xray)[0].Id

$cfgPath = Join-Path $V2rayNRoot 'binConfigs\config.json'
$cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
$node = Get-NodeEndpoint -Cfg $cfg
Log ('node: ' + $node.Address + ' (' + $node.Protocol + ')')

# routing profile check: whitelist has a "direct" rule for geosite:cn
$directCn = $false
foreach ($r in @($cfg.routing.rules)) {
    if ($r.outboundTag -ne 'direct') { continue }
    foreach ($d in @($r.domain)) {
        if ($d -and $d -like '*geosite:cn*') { $directCn = $true }
    }
}
if (-not $directCn) {
    Log 'WARNING: this config does not route geosite:cn to direct.'
    Log '         The test needs the "Whitelist" routing profile; switch it in v2rayN, or open a direct-routed site.'
}
else {
    Log 'routing: whitelist (geosite:cn -> direct) detected'
}

$aliDns = @('223.5.5.5', '223.6.6.6')

function Test-Expected {
    param([string]$ip)
    if (-not $ip) { return $true }
    if ($ip -eq '::1' -or $ip -match '^127\.' -or $ip -match '^fe80:' -or $ip -match '^169\.254\.') { return $true }
    if ($ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') { return $true }
    if ($ip -eq $node.Address) { return $true }
    if ($aliDns -contains $ip) { return $true }
    return $false
}

Write-Host ''
Write-Host ('Open a few Chinese sites in the browser for ' + $Seconds + ' seconds (e.g. baidu.com, qq.com).') -ForegroundColor Yellow
Write-Host 'These go through the "direct" outbound of xray, which the allow list should block.' -ForegroundColor DarkGray
Read-Host 'Press Enter to start the observation' | Out-Null

# ---------------------------------------------------------------- observe
$seen = @{}
$deadline = (Get-Date).AddSeconds($Seconds)
while ((Get-Date) -lt $deadline) {
    try {
        $conns = @(Get-NetTCPConnection -OwningProcess $xrayPid -State Established -ErrorAction SilentlyContinue)
    }
    catch { $conns = @() }
    foreach ($c in $conns) {
        $ra = [string]$c.RemoteAddress
        if (Test-Expected -ip $ra) { continue }
        $seen[$ra + ':' + $c.RemotePort] = $true
    }
    Start-Sleep -Seconds 2
}

# ---------------------------------------------------------------- verdict
Log ''
Log ('observation window: ' + $Seconds + ' s')
Log ('xray pid: ' + $xrayPid)

if ($seen.Count -gt 0) {
    Log ''
    Log 'RESULT: BYPASS CONFIRMED' -ForegroundColor Red
    Log 'xray.exe dialed public addresses that are NOT in the allow list:' -ForegroundColor Red
    foreach ($k in ($seen.Keys | Sort-Object)) { Log ('  ' + $k) }
    Log ''
    Log 'Interpretation: the WFP hard permit is active, so Windows Firewall cannot' -ForegroundColor Yellow
    Log 'constrain xray.exe. The node allow list still constrains every other process.'
    Log 'To enforce xray itself: router egress whitelist, or disable' -ForegroundColor Yellow
    Log 'autoSystemWfpBlockLeak (see README 9.3).'
}
else {
    Log ''
    Log 'RESULT: no direct egress observed from xray.exe' -ForegroundColor Green
    Log 'Either the hard permit is absent (run 04-wfp-audit.ps1 to confirm),'
    Log 'or the routing profile was not whitelist, or nothing was direct-routed'
    Log 'during the window. Re-run with more sites / longer window if unsure.'
}
Log ''
Log ('report: ' + $report) -ForegroundColor DarkGray
