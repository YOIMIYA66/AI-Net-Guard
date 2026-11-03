<#
.SYNOPSIS
    AI-Net-Guard v5.4 - step 0: read-only audit (run as Administrator).

.DESCRIPTION
    Collects every fact the kill-switch / DNS-leak plan depends on:
    adapters, routes, per-interface DNS, NRPT/DoH state, firewall profiles,
    every enabled outbound ALLOW rule, proxy processes, v2rayN / Xray config.

    This script changes NOTHING. It only writes reports under C:\AI-Net-Guard\audit-*.

.NOTES
    Windows 11 24H2 / PowerShell 5.1 or 7.x. Must be elevated.
#>

[CmdletBinding()]
param(
    [string]$Root = $(if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\AI-Net-Guard' }),
    [string]$V2rayNRoot = '',
    [switch]$Deep
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

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'ERROR: run this script in an elevated PowerShell (Run as administrator).' -ForegroundColor Red
        exit 1
    }
}

function Save-Report {
    param([string]$Name, [scriptblock]$Body)
    $path = Join-Path $script:OutDir $Name
    try {
        $text = & $Body | Out-String -Width 400
        Set-Content -LiteralPath $path -Value $text -Encoding UTF8
        Write-Host ("  [ok]   {0}" -f $Name) -ForegroundColor DarkGray
    }
    catch {
        Set-Content -LiteralPath $path -Value ("ERROR: " + $_.Exception.Message) -Encoding UTF8
        Write-Host ("  [warn] {0} : {1}" -f $Name, $_.Exception.Message) -ForegroundColor Yellow
    }
}

Assert-Admin

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:OutDir = Join-Path $Root ("audit-" + $stamp)
New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null

Write-Host ''
Write-Host 'AI-Net-Guard audit' -ForegroundColor Cyan
Write-Host ("output: " + $script:OutDir)
Write-Host ''

# ---------------------------------------------------------------- system
Save-Report '01-system.txt' {
    'OS: ' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ProductName
    'DisplayVersion: ' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion
    'Build: ' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild + '.' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
    'PowerShell: ' + $PSVersionTable.PSVersion
    'User: ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name
}

# ---------------------------------------------------------------- adapters
Save-Report '02-adapters.txt' {
    Get-NetAdapter -IncludeHidden | Select-Object ifIndex, Name, InterfaceDescription, Status, MacAddress, LinkSpeed, MtuSize | Sort-Object ifIndex | Format-Table -AutoSize
}

Save-Report '03-ipconfig-all.txt' { ipconfig /all }

# ---------------------------------------------------------------- routes
Save-Report '04-default-routes.txt' {
    Get-NetRoute -ErrorAction SilentlyContinue |
        Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') } |
        Select-Object InterfaceAlias, InterfaceIndex, DestinationPrefix, NextHop, RouteMetric, ifMetric |
        Sort-Object DestinationPrefix, RouteMetric | Format-Table -AutoSize
    ''
    'Full IPv4 table:'
    route print -4
}

# ---------------------------------------------------------------- DNS
Save-Report '05-dns-servers.txt' {
    Get-DnsClientServerAddress |
        Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses |
        Sort-Object InterfaceAlias, AddressFamily | Format-Table -AutoSize
}

Save-Report '06-dns-policy.txt' {
    'Global:'
    Get-DnsClientGlobalSetting | Format-List
    ''
    'NRPT rules:'
    Get-DnsClientNrptRule | Select-Object Name, Namespace, NameServers, Comment, Version | Format-List
    ''
    'Known DoH servers:'
    Get-DnsClientDohServerAddress | Select-Object ServerAddress, DohTemplate, AllowFallbackToUdp, AutoUpgrade | Format-Table -AutoSize
}

Save-Report '07-dns-registry.txt' {
    'DNSClient policy key:'
    $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    if (Test-Path $k) { Get-ItemProperty $k | Out-String } else { '(not present)' }
    ''
    'Dnscache parameters:'
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' | Out-String
    ''
    'IPv6 Tcpip6 DisabledComponents & Prefix Policy:'
    $t6 = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
    if (Test-Path $t6) { Get-ItemProperty $t6 | Select-Object DisabledComponents | Out-String }
    Get-NetPrefixPolicy -ErrorAction SilentlyContinue | Select-Object Prefix, Precedence, Label | Format-Table -AutoSize
    ''
    'W32Time NTP parameters:'
    $w32 = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
    if (Test-Path $w32) { Get-ItemProperty $w32 | Select-Object NtpServer, Type | Format-List }
    ''
    'Per-interface resolver config (static NameServer vs DHCP):'
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces' | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath
        [pscustomobject]@{
            Guid           = $_.PSChildName
            NameServer     = $p.NameServer
            DhcpNameServer = $p.DhcpNameServer
            EnableDHCP     = $p.EnableDHCP
        }
    } | Format-Table -AutoSize
}

# ---------------------------------------------------------------- firewall
Save-Report '08-firewall-profiles.txt' {
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, NotifyOnListen | Format-Table -AutoSize
    ''
    netsh advfirewall show allprofiles
}

Save-Report '09-firewall-outbound-allow.txt' {
    $rules = Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue
    'Enabled outbound ALLOW rules: ' + $rules.Count
    ''
    $rules | Select-Object DisplayName, Group, Profile, PolicyStoreSourceType, Direction, Action, Enabled |
        Sort-Object DisplayName | Format-Table -AutoSize
}

Save-Report '10-firewall-outbound-allow-csv.txt' {
    $rules = Get-NetFirewallRule -Direction Outbound -Action Allow -ErrorAction SilentlyContinue
    $rules | ForEach-Object {
        $prog = ($_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program
        $port = ($_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)
        [pscustomobject]@{
            Name         = $_.Name
            DisplayName  = $_.DisplayName
            Enabled      = $_.Enabled
            Profile      = $_.Profile
            Store        = $_.PolicyStoreSourceType
            Program      = $prog
            Protocol     = $port.Protocol
            RemotePort   = $port.RemotePort
            RemoteAddr   = (($_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue).RemoteAddress -join ';')
            Interface    = (($_ | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue).InterfaceAlias -join ';')
        }
    } | Export-Csv -LiteralPath (Join-Path $script:OutDir '10-firewall-outbound-allow.csv') -NoTypeInformation -Encoding UTF8
    'CSV written: 10-firewall-outbound-allow.csv'
}

Save-Report '11-firewall-export.txt' {
    $wfw = Join-Path $script:OutDir 'firewall-before.wfw'
    netsh advfirewall export "$wfw"
    'Exported to ' + $wfw
}

# ---------------------------------------------------------------- proxies
Save-Report '12-proxy-processes.txt' {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '(?i)xray|v2rayN|sing-box|mihomo|clash' } |
        Select-Object ProcessId, Name, ExecutablePath, CommandLine | Format-List
    ''
    'Listening ports:'
    netstat -ano | Select-String 'LISTENING'
}

Save-Report '13-proxy-settings.txt' {
    'WinHTTP:'
    netsh winhttp show proxy
    ''
    'WinINET (HKCU):'
    Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' |
        Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL | Format-List
    ''
    'Process environment:'
    Get-ChildItem Env: | Where-Object { $_.Name -match '(?i)proxy' } | Format-Table -AutoSize
}

# ---------------------------------------------------------------- v2rayN
$cfgPath = Join-Path $V2rayNRoot 'binConfigs\config.json'
$guiPath = Join-Path $V2rayNRoot 'guiConfigs\guiNConfig.json'

Save-Report '14-v2rayn-config.txt' {
    'v2rayN exe: ' + (Join-Path $V2rayNRoot 'v2rayN.exe')
    if (Test-Path (Join-Path $V2rayNRoot 'v2rayN.exe')) {
        (Get-Item (Join-Path $V2rayNRoot 'v2rayN.exe')).VersionInfo | Select-Object FileVersion, ProductVersion | Format-List
    }
    $xrayExe = Join-Path $V2rayNRoot 'bin\xray\xray.exe'
    if (Test-Path $xrayExe) {
        'Xray:'
        & $xrayExe -version 2>&1
    }
    ''
    '--- generated Xray config: ' + $cfgPath + ' ---'
    if (Test-Path $cfgPath) {
        $cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
        'TUN inbound:'
        $tun = $cfg.inbounds | Where-Object { $_.protocol -eq 'tun' }
        if ($tun) { $tun.settings | ConvertTo-Json -Depth 8 }
        'DNS servers:'
        $cfg.dns.servers | ConvertTo-Json -Depth 8
        'Outbounds (address/port/network/security):'
        $cfg.outbounds | Where-Object { $_.protocol -ne 'blackhole' } | ForEach-Object {
            $oa = [string]$_.settings.address
            $op = [string]$_.settings.port
            if (-not $oa -and $_.settings.vnext) { $oa = [string]$_.settings.vnext[0].address; $op = [string]$_.settings.vnext[0].port }
            if (-not $oa -and $_.settings.servers) { $oa = [string]$_.settings.servers[0].address; $op = [string]$_.settings.servers[0].port }
            [pscustomobject]@{
                Tag      = $_.tag
                Protocol = $_.protocol
                Address  = $oa
                Port     = $op
                Network  = $_.streamSettings.network
                Security = $_.streamSettings.security
            }
        } | Format-Table -AutoSize
    }
    else { 'missing' }
    ''
    '--- guiNConfig: TUN / DNS / SystemProxy ---'
    if (Test-Path $guiPath) {
        $g = Get-Content -LiteralPath $guiPath -Raw -Encoding UTF8 | ConvertFrom-Json
        'TunModeItem:'
        $g.TunModeItem | ConvertTo-Json -Depth 6
        'SimpleDNSItem:'
        $g.SimpleDNSItem | ConvertTo-Json -Depth 6
        'SystemProxyItem:'
        $g.SystemProxyItem | ConvertTo-Json -Depth 6
    }
    else { 'missing' }
}

# ---------------------------------------------------------------- WFP (optional)
if ($Deep) {
    Save-Report '15-wfp-state.txt' {
        $f = Join-Path $script:OutDir 'wfp-state.xml'
        netsh wfp show state file="$f"
        'WFP state written to ' + $f + ' (large XML; search for Xray/Wintun filters)'
    }
}

# ---------------------------------------------------------------- tasks
Save-Report '16-scheduled-tasks.txt' {
    Get-ScheduledTask -TaskName 'AI-Guard*' -ErrorAction SilentlyContinue |
        Select-Object TaskName, State, @{n = 'Actions'; e = { ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; ' } } |
        Format-List
}

Write-Host ''
Write-Host 'Audit finished. Reports: ' -NoNewline
Write-Host $script:OutDir -ForegroundColor Green
Write-Host ''
Write-Host 'Send these two files back for a final review:' -ForegroundColor Cyan
Write-Host '  08-firewall-profiles.txt'
Write-Host '  09-firewall-outbound-allow.txt'
Write-Host '  (10-firewall-outbound-allow.csv is the detailed version)'
Write-Host ''
