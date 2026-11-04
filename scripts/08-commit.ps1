<#
.SYNOPSIS
    AI-Net-Guard v5.7.3 - step 4: commit (cancel auto-rollback & install monitor tasks).

.DESCRIPTION
    Run this only after 03-verify.ps1 passed. Before removing the auto-rollback
    safety net it re-checks core invariants:
        - firewall default outbound = Block on all profiles
        - AI-Guard-Allow-TUN and AI-Guard-Allow-Node-TCP exist and are enabled
        - physical adapter DNS uses approved static resolver (223.5.5.5 / 1.1.1.1 / NRPT)
        - TUN up, xray running, egress IP equals proxy node (supports VLESS vnext)
    Then removes AI-Guard-Test-Rollback and (unless -SkipInstallTasks) registers
    the v5.1 event-driven watchdog & 15-min fallback tasks via 07-mode.ps1.
#>

[CmdletBinding()]
param(
    [string]$Root = $(if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\AI-Net-Guard' }),
    [string]$V2rayNRoot = '',
    [string]$TunName = 'xray_tun',
    [switch]$SkipInstallTasks,
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

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'ERROR: run this script in an elevated PowerShell.' -ForegroundColor Red
    exit 1
}

$fails = @()

$prof = @(Get-NetFirewallProfile | Where-Object { $_.DefaultOutboundAction -ne 'Block' -or -not $_.Enabled })
if ($prof.Count -gt 0) { $fails += ('profiles not blocking: ' + (($prof | ForEach-Object { $_.Name }) -join ',')) }

foreach ($n in @('AI-Guard-Allow-TUN', 'AI-Guard-Allow-Node-TCP')) {
    $r = Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $r -or $r.Enabled -ne 'True') { $fails += ('missing/disabled rule: ' + $n) }
}

$nrptOk = [bool](Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -like 'AI-Guard*' })
$approvedDns = @('223.5.5.5', '223.6.6.6', '1.1.1.1', '127.0.0.1')
$badDns = @()
foreach ($a in (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.Name -ne $TunName -and $_.InterfaceDescription -notmatch 'Wintun|Loopback' })) {
    try {
        foreach ($ip in @((Get-DnsClientServerAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses)) {
            if ($ip -and ($approvedDns -notcontains $ip)) { $badDns += ($a.Name + '=' + $ip) }
        }
    }
    catch { }
}
if (-not $nrptOk -and $badDns.Count -gt 0) {
    $fails += ('DNS not hardened: ' + ($badDns -join '; '))
}

$tun = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and ($_.Name -in @($TunName, 'xray_tun', 'singbox_tun', 'mihomo_tun', 'Meta') -or $_.InterfaceDescription -match 'Wintun|sing-tun|Mihomo') } | Select-Object -First 1
if (-not $tun) { $fails += 'TUN not up' }
if (-not (Get-Process -Name @('xray', 'sing-box', 'mihomo', 'mihomo-windows-amd64-v1') -ErrorAction SilentlyContinue)) { $fails += 'proxy core not running' }

try {
    if ([int][Net.ServicePointManager]::SecurityProtocol -ne 0) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    $cfg = Get-Content -LiteralPath (Join-Path $V2rayNRoot 'binConfigs\config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $want = ''
    $node = $cfg.outbounds | Where-Object { $_.protocol -in @('vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'wireguard', 'socks', 'http') } | Select-Object -First 1
    if ($node) {
        $want = [string]$node.settings.address
        if (-not $want -and $node.settings.vnext) { $want = [string]$node.settings.vnext[0].address }
        if (-not $want -and $node.settings.servers) { $want = [string]$node.settings.servers[0].address }
    }
    else {
        $snode = $cfg.outbounds | Where-Object { $_.type -in @('hysteria2', 'hysteria', 'tuic', 'vless', 'vmess', 'trojan', 'shadowsocks', 'wireguard', 'anytls', 'socks', 'http') } | Select-Object -First 1
        if ($snode) { $want = [string]$snode.server }
    }
    $wantIps = @($want)
    if ($want -and $want -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        $wantIps = @()
        try {
            $rq = [System.Net.HttpWebRequest]::Create('https://223.5.5.5/resolve?name=' + [uri]::EscapeDataString($want) + '&type=A')
            $rq.Proxy = $null; $rq.Timeout = 4000
            $rs = $rq.GetResponse()
            try { $js = (New-Object System.IO.StreamReader($rs.GetResponseStream())).ReadToEnd() | ConvertFrom-Json; $wantIps = @($js.Answer | Where-Object { $_.type -eq 1 } | ForEach-Object { [string]$_.data }) } finally { $rs.Close() }
        }
        catch { }
        if ($wantIps.Count -eq 0) {
            $wantIps = @(Resolve-DnsName -Name $want -Type A -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
        }
    }
    $erq = [System.Net.HttpWebRequest]::Create('https://api.ipify.org')
    $erq.Proxy = $null; $erq.Timeout = 15000
    $ers = $erq.GetResponse()
    try { $egress = (New-Object System.IO.StreamReader($ers.GetResponseStream())).ReadToEnd().Trim() } finally { $ers.Close() }
    if ($want -and ($wantIps -notcontains $egress) -and ($egress -ne $want)) {
        $fails += ('egress ' + $egress + ' != node ' + $want)
    }
}
catch { $fails += ('egress check failed: ' + $_.Exception.Message) }

if ($fails.Count -gt 0) {
    Write-Host 'Refusing to commit - invariants are not satisfied:' -ForegroundColor Red
    $fails | ForEach-Object { Write-Host ('  - ' + $_) -ForegroundColor Red }
    if (-not $Force) {
        Write-Host 'Fix them, re-run 03-verify.ps1, or pass -Force to commit anyway.' -ForegroundColor Yellow
        exit 1
    }
    Write-Host '-Force given, committing anyway.' -ForegroundColor Yellow
}

$task = Get-ScheduledTask -TaskName 'AI-Guard-Test-Rollback' -ErrorAction SilentlyContinue
if ($task) {
    Unregister-ScheduledTask -TaskName 'AI-Guard-Test-Rollback' -Confirm:$false
    Write-Host '[+] auto-rollback task removed' -ForegroundColor Green
}
else {
    Write-Host '[i] auto-rollback task was not present' -ForegroundColor Yellow
}

if (-not $SkipInstallTasks) {
    $modeScript = if (Test-Path (Join-Path (Join-Path $Root 'scripts') '07-mode.ps1')) { Join-Path (Join-Path $Root 'scripts') '07-mode.ps1' } else { Join-Path $Root '07-mode.ps1' }
    if (Test-Path -LiteralPath $modeScript) {
        & $modeScript -InstallTasks -Root $Root -V2rayNRoot $V2rayNRoot -TunName $TunName
    }
}

$logDir = Join-Path $Root 'logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
@(
    ('version: 5.4'),
    ('committed: ' + (Get-Date).ToString('o')),
    ('user: ' + $id.Name)
) | Set-Content -LiteralPath (Join-Path $logDir 'committed.txt') -Encoding UTF8

Write-Host ''
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultOutboundAction | Format-Table -AutoSize
Write-Host 'Configuration v5.4 is now persistent across reboots.' -ForegroundColor Green
Write-Host 'Rollback any time with 09-rollback.ps1.' -ForegroundColor DarkGray
