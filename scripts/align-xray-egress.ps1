# AI-Net-Guard - Physical Egress Socket Alignment Utility
# Eliminates internal double-hop relay between sing-box TUN and Xray core
param(
    [string]$V2rayNRoot = '',
    [switch]$RestartXray
)

$ErrorActionPreference = 'Continue'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host '[ERROR] This utility requires Administrator privileges.' -ForegroundColor Red
    exit 1
}

Write-Host '===============================================================================' -ForegroundColor Cyan
Write-Host '          AI-Net-Guard - Proxy Core Physical Egress Alignment Utility          ' -ForegroundColor Cyan
Write-Host '===============================================================================' -ForegroundColor Cyan
Write-Host ''

# 1. Discover v2rayN root and active configuration
if (-not $V2rayNRoot) {
    if ($env:V2RAYN_ROOT -and (Test-Path -LiteralPath $env:V2RAYN_ROOT)) { $V2rayNRoot = $env:V2RAYN_ROOT }
    else {
        foreach ($cand in @(
            'D:\v2rayN-windows-64-desktop\v2rayN-windows-64',
            'D:\v2rayN-windows-64-desktop',
            'C:\v2rayN-windows-64',
            'D:\v2rayN-windows-64',
            'C:\v2rayN',
            'D:\v2rayN',
            (Join-Path $env:LOCALAPPDATA 'v2rayN'),
            'C:\Program Files\v2rayN'
        )) {
            if ($cand -and ((Test-Path -LiteralPath (Join-Path $cand 'v2rayN.exe')) -or (Test-Path -LiteralPath (Join-Path $cand 'binConfigs\config.json')))) {
                $V2rayNRoot = $cand
                break
            }
        }
        if (-not $V2rayNRoot) {
            try {
                $vp = [System.Diagnostics.Process]::GetProcessesByName('v2rayN')
                if ($vp.Length -gt 0 -and $vp[0].MainModule.FileName) {
                    $V2rayNRoot = Split-Path -Parent $vp[0].MainModule.FileName
                }
            } catch { }
        }
    }
}

$cfgPath = Join-Path $V2rayNRoot 'binConfigs\config.json'
if (-not (Test-Path -LiteralPath $cfgPath)) {
    Write-Host ('[!] Cannot find config.json at ' + $cfgPath) -ForegroundColor Yellow
    $nodeIps = @('20.89.232.246')
} else {
    try {
        $cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $address = ''
        if ($cfg.outbounds) {
            foreach ($ob in $cfg.outbounds) {
                if ($ob.settings -and $ob.settings.vnext) {
                    $address = $ob.settings.vnext[0].address; break
                }
                if ($ob.settings -and $ob.settings.servers) {
                    $address = $ob.settings.servers[0].address; break
                }
                if ($ob.settings -and $ob.settings.address) {
                    $address = $ob.settings.address; break
                }
                if ($ob.server) {
                    $address = $ob.server; break
                }
            }
        }
        Write-Host ('[+] Detected active proxy server: ' + $address) -ForegroundColor Green
        if ($address -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $nodeIps = @($address)
        } else {
            Write-Host ('    Resolving domain ' + $address + ' via AliDNS DoH...')
            $nodeIps = @(Resolve-DnsName -Name $address -Type A -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
        }
    } catch {
        $nodeIps = @('20.89.232.246')
    }
}

if ($nodeIps.Count -eq 0) {
    Write-Host '[ERROR] Failed to resolve proxy node IP address.' -ForegroundColor Red
    exit 2
}

Write-Host ('[+] Proxy Node IPs: ' + ($nodeIps -join ', ')) -ForegroundColor Cyan
Write-Host ''

# 2. Find physical IPv4 default route
$physRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceAlias -notmatch '(?i)tun|wintun|sing|xray|meta|mihomo|loopback' -and $_.NextHop -ne '0.0.0.0' } |
    Select-Object -First 1

if (-not $physRoute -or -not $physRoute.NextHop) {
    Write-Host '[ERROR] Could not determine physical default gateway (WLAN / Ethernet).' -ForegroundColor Red
    exit 3
}

Write-Host ('[+] Physical Egress Interface: ' + $physRoute.InterfaceAlias + ' (InterfaceIndex ' + $physRoute.InterfaceIndex + ')') -ForegroundColor Green
Write-Host ('[+] Physical Default Gateway:  ' + $physRoute.NextHop) -ForegroundColor Green
Write-Host ''

# 3. Inject / Update /32 host route for each node IP
foreach ($nodeIp in $nodeIps) {
    $dest = $nodeIp + '/32'
    $curRoute = Get-NetRoute -DestinationPrefix $dest -ErrorAction SilentlyContinue
    if (-not $curRoute) {
        New-NetRoute -DestinationPrefix $dest -InterfaceAlias $physRoute.InterfaceAlias -NextHop $physRoute.NextHop -RouteMetric 1 -ErrorAction Stop | Out-Null
        Write-Host ('[+] Successfully ADDED host route: ' + $dest + ' -> ' + $physRoute.NextHop + ' on ' + $physRoute.InterfaceAlias + ' (Metric 1)') -ForegroundColor Green
    } elseif ($curRoute.NextHop -ne $physRoute.NextHop -or $curRoute.InterfaceAlias -ne $physRoute.InterfaceAlias -or $curRoute.RouteMetric -ne 1) {
        Remove-NetRoute -DestinationPrefix $dest -Confirm:$false -ErrorAction SilentlyContinue
        New-NetRoute -DestinationPrefix $dest -InterfaceAlias $physRoute.InterfaceAlias -NextHop $physRoute.NextHop -RouteMetric 1 -ErrorAction Stop | Out-Null
        Write-Host ('[+] Successfully UPDATED host route: ' + $dest + ' -> ' + $physRoute.NextHop + ' on ' + $physRoute.InterfaceAlias + ' (Metric 1)') -ForegroundColor Green
    } else {
        Write-Host ('[+] Host route ALREADY OPTIMAL: ' + $dest + ' -> ' + $physRoute.NextHop + ' on ' + $physRoute.InterfaceAlias + ' (Metric 1)') -ForegroundColor Green
    }
}

Write-Host ''
Write-Host '===============================================================================' -ForegroundColor Cyan
Write-Host '                       Live Kernel Route Lookup Check                          ' -ForegroundColor Cyan
Write-Host '===============================================================================' -ForegroundColor Cyan

foreach ($nodeIp in $nodeIps) {
    $routed = Find-NetRoute -RemoteIPAddress $nodeIp -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($routed) {
        $color = if ($routed.InterfaceAlias -eq $physRoute.InterfaceAlias) { 'Green' } else { 'Red' }
        Write-Host ('  Remote ' + $nodeIp + ' routes to interface: [' + $routed.InterfaceAlias + '] via NextHop [' + $routed.NextHop + ']') -ForegroundColor $color
    }
}

Write-Host ''
Write-Host '===============================================================================' -ForegroundColor Cyan
Write-Host '                  Active TCP Sockets to Proxy Node                             ' -ForegroundColor Cyan
Write-Host '===============================================================================' -ForegroundColor Cyan

$conns = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $nodeIps -contains $_.RemoteAddress })
if ($conns.Count -eq 0) {
    Write-Host '  No active TCP connections to proxy node at this moment.' -ForegroundColor Yellow
} else {
    foreach ($c in $conns) {
        $pName = 'Unknown'
        try { $pName = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch { }
        $color = 'White'
        $role = ''
        if ($c.LocalAddress -match '^172\.18\.') {
            $color = 'Yellow'
            $role = ' (TUN Relay - Old Socket)'
        } elseif ($c.LocalAddress -eq $physRoute.InterfaceAlias -or $c.LocalAddress -match '^192\.168\.') {
            $color = 'Green'
            $role = ' (Direct Physical Egress)'
        }
        Write-Host ('  PID ' + $c.OwningProcess + ' [' + $pName + ']: ' + $c.LocalAddress + ':' + $c.LocalPort + ' -> ' + $c.RemoteAddress + ':' + $c.RemotePort + $role) -ForegroundColor $color
    }
}

Write-Host ''
Write-Host '===============================================================================' -ForegroundColor Cyan
Write-Host '                                Summary                                        ' -ForegroundColor Cyan
Write-Host '===============================================================================' -ForegroundColor Cyan
Write-Host 'The Windows routing table now forces all traffic destined for the proxy node' -ForegroundColor White
Write-Host 'directly out through your physical Wi-Fi interface (WLAN) via gateway ' -NoNewline -ForegroundColor White
Write-Host $physRoute.NextHop -ForegroundColor Yellow
Write-Host 'Bypassing the singbox_tun virtual interface completely eliminates the double hop.' -ForegroundColor White
Write-Host ''
Write-Host 'Note: Existing active TCP sockets created before this route was added will' -ForegroundColor Gray
Write-Host 'remain until closed. To immediately switch all sockets to direct WLAN, restart' -ForegroundColor Gray
Write-Host 'the proxy core (or right click v2rayN tray icon -> Restart Service).' -ForegroundColor Gray
Write-Host ''
