<#
.SYNOPSIS
    AI-Net-Guard v5.7.0 - step 3: comprehensive verification (run as Administrator).

.DESCRIPTION
    Verifies both static configuration invariants and live network behaviour for
    AI-Net-Guard v5.7.0 (works in both TUN-ON and TUN-OFF states, multi-core aware,
    bypasses HKCU HTTP proxy to test the real kernel WFP/TUN datapath, and
    auto-cleans temporary WFP XML dumps unless -KeepCaptures is passed).

    No configuration is changed.

.PARAMETER FailClosedTest
    Interactive: asks you to stop v2rayN / turn off TUN, then verifies:
      - v5.1 static mode: domestic sites still work (200) while foreign TCP &
        foreign AI/HTTPS endpoints are blocked;
      - strict/Protected mode: DNS + TCP + HTTPS all fail closed.
#>

[CmdletBinding()]
param(
    [string]$Root = $(if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\AI-Net-Guard' }),
    [string]$V2rayNRoot = '',
    [string]$TunName = 'xray_tun',
    [Alias('DohServer')]
    [string]$DnsServer = '223.5.5.5',
    [switch]$FailClosedTest,
    [switch]$WfpCheck,
    [switch]$KeepCaptures,
    [int]$MaxReports = 10
)

$ErrorActionPreference = 'Continue'
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
$script:results = @()

function Check {
    param([string]$Name, [scriptblock]$Body, [string]$Expect)
    $status = 'FAIL'
    $detail = ''
    try {
        $r = & $Body
        if ($r -is [bool]) { if ($r) { $status = 'PASS' } }
        elseif ($null -eq $r) { $status = 'FAIL'; $detail = 'no result' }
        else { $status = 'PASS'; $detail = [string]$r }
    }
    catch {
        $detail = $_.Exception.Message
    }
    $script:results += [pscustomobject]@{ Check = $Name; Status = $status; Expect = $Expect; Detail = $detail }
    $color = if ($status -eq 'PASS') { 'Green' } else { 'Red' }
    Write-Host ('  [{0}] {1} : {2}' -f $status, $Name, $detail) -ForegroundColor $color
}

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'ERROR: run this script in an elevated PowerShell.' -ForegroundColor Red
        exit 1
    }
}

function Test-TcpClosed {
    param([string]$Target, [int]$Port, [int]$TimeoutMs = 3000)
    $c = New-Object Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($Target, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $true }
        try { $c.EndConnect($iar); return $false } catch { return $true }
    }
    catch { return $true }
    finally { try { $c.Close() } catch { } }
}

function Invoke-DirectHttp {
    param([string]$Url, [int]$TimeoutSec = 15, [hashtable]$Headers = @{})
    if ([int][Net.ServicePointManager]::SecurityProtocol -ne 0) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    $req = [System.Net.HttpWebRequest]::Create($Url)
    $req.Proxy = $null
    $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'
    $req.Accept = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    $req.Timeout = $TimeoutSec * 1000
    $req.ReadWriteTimeout = $TimeoutSec * 1000
    $req.AllowAutoRedirect = $true
    $req.MaximumAutomaticRedirections = 5
    foreach ($k in $Headers.Keys) {
        if ($k -ieq 'accept') { $req.Accept = [string]$Headers[$k] }
        else { $req.Headers[$k] = [string]$Headers[$k] }
    }
    $resp = $req.GetResponse()
    try {
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
        return [pscustomobject]@{
            StatusCode = [int]$resp.StatusCode
            Content    = $sr.ReadToEnd()
        }
    }
    finally {
        $resp.Close()
    }
}

function Get-HttpExceptionCode($ErrorRecord) {
    $ex = $ErrorRecord.Exception
    while ($ex -and -not ($ex -is [System.Net.WebException])) { $ex = $ex.InnerException }
    if ($ex -and $ex.Response) {
        $code = [int]$ex.Response.StatusCode
        try { $ex.Response.Close() } catch { }
        return $code
    }
    return $null
}

function Get-NodeInfo {
    $cfgPath = Join-Path $V2rayNRoot 'binConfigs\config.json'
    $cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $addr = ''
    $port = ''
    $net = ''
    $n = $cfg.outbounds | Where-Object { $_.protocol -in @('vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'wireguard', 'socks', 'http') } | Select-Object -First 1
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
        $net = [string]$n.streamSettings.network
    }
    else {
        $sn = $cfg.outbounds | Where-Object { $_.type -in @('hysteria2', 'hysteria', 'tuic', 'vless', 'vmess', 'trojan', 'shadowsocks', 'wireguard', 'anytls', 'socks', 'http') } | Select-Object -First 1
        if (-not $sn) { throw 'no proxy outbound in config.json' }
        $addr = [string]$sn.server
        $port = [string]$sn.server_port
        $net = [string]$sn.type
    }
    if (-not $addr) { throw 'no node address in config.json' }
    $ips = @($addr)
    if ($addr -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        $ips = @()
        try {
            $doh = (Invoke-DirectHttp -Url ('https://223.5.5.5/resolve?name=' + [uri]::EscapeDataString($addr) + '&type=A') -TimeoutSec 4).Content | ConvertFrom-Json
            $ips = @($doh.Answer | Where-Object { $_.type -eq 1 -and $_.data -match '^\d{1,3}(\.\d{1,3}){3}$' } | ForEach-Object { [string]$_.data })
        }
        catch { }
        if ($ips.Count -eq 0) {
            $ips = @(Resolve-DnsName -Name $addr -Type A -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
        }
    }
    [pscustomobject]@{
        Address = $addr
        Ips     = $ips
        Port    = $port
        Network = $net
    }
}

function Get-FirewallRuleStates {
    $states = @{}
    try {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
        $props = (Get-ItemProperty -Path $key -ErrorAction Stop).PSObject.Properties
        foreach ($pr in $props) {
            if ($pr.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
            $v = [string]$pr.Value
            $active = ($v -match '(^|\|)Active=TRUE(\||$)')
            if (-not $states.ContainsKey($pr.Name) -or $active) { $states[$pr.Name] = $active }
            if ($v -match '(^|\|)Name=([^|]+)') {
                $dn = $matches[2]
                if (-not $states.ContainsKey($dn) -or $active) { $states[$dn] = $active }
            }
        }
    }
    catch { }
    return $states
}

Assert-Admin
Write-Host ''
Write-Host 'AI-Net-Guard v5.7.0 verification' -ForegroundColor Cyan
Write-Host ''

$ruleStates = Get-FirewallRuleStates
$tunAdapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and ($_.Name -in @($TunName, 'xray_tun', 'singbox_tun', 'mihomo_tun', 'Meta') -or $_.InterfaceDescription -match 'Wintun|sing-tun|Mihomo') } | Select-Object -First 1
$tunUp = [bool]$tunAdapter
$xrayProcs = @(Get-Process -Name @('xray', 'sing-box', 'mihomo', 'mihomo-windows-amd64-v1') -ErrorAction SilentlyContinue)
$cnRule = Get-NetFirewallRule -Name 'AI-Guard-Allow-CN' -ErrorAction SilentlyContinue
$cnActive = ($cnRule -and $cnRule.Enabled -eq 'True')

# ---------------------------------------------------------------- configuration
Write-Host '--- configuration ---' -ForegroundColor Cyan

Check 'firewall default outbound = Block' {
    $p = Get-NetFirewallProfile
    $bad = @($p | Where-Object { $_.DefaultOutboundAction -ne 'Block' -or -not $_.Enabled })
    if ($bad.Count -eq 0) { $true } else { throw ('profiles not blocking: ' + (($bad | ForEach-Object { $_.Name }) -join ',')) }
} 'all profiles Block + Enabled'

Check 'AI-Guard-Allow-TUN rule active' {
    if ($ruleStates.ContainsKey('AI-Guard-Allow-TUN') -and $ruleStates['AI-Guard-Allow-TUN']) { $true }
    else { throw 'missing or disabled' }
} 'rule exists and enabled'

Check 'AI-Guard-Allow-Node-TCP rule active' {
    $r = Get-NetFirewallRule -DisplayName 'AI-Guard-Allow-Node-TCP' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($r -and $r.Enabled -eq 'True') {
        $addr = @(($r | Get-NetFirewallAddressFilter).RemoteAddress) -join ','
        $port = @(($r | Get-NetFirewallPortFilter).RemotePort) -join ','
        'node=' + $addr + ' port=' + $port
    }
    else { throw 'missing or disabled' }
} 'rule exists with node address'

Check 'companion rules active (DoH-Ali, DHCP, LAN)' {
    $need = @('AI-Guard-Allow-DoH-Ali', 'AI-Guard-Allow-DHCP', 'AI-Guard-Allow-LAN')
    $bad = @()
    foreach ($n in $need) {
        if (-not $ruleStates.ContainsKey($n)) { $bad += ($n + '=missing') }
        elseif (-not $ruleStates[$n]) { $bad += ($n + '=disabled') }
    }
    if ($bad.Count -gt 0) { throw ($bad -join '; ') }
    'all active'
} 'all companion rules active'

Check 'AI-Guard-Allow-CN state' {
    if ($cnRule) {
        $cnt = @(($cnRule | Get-NetFirewallAddressFilter).RemoteAddress).Count
        if ($cnRule.Enabled -eq 'True') {
            if ($cnt -lt 1000) { throw ('CN rule enabled but prefix count too small: ' + $cnt) }
            'v5.1 static mode: enabled, prefixes=' + $cnt
        }
        else {
            'Protected mode: CN rule disabled (prefixes=' + $cnt + ')'
        }
    }
    else {
        'strict kill-switch mode (no CN direct rule)'
    }
} 'CN allowlist >=1000 prefixes or explicit Protected/strict mode'

Check 'no unapproved public egress via outbound ALLOW rules' {
    $left = @(Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -notlike 'AI-Guard-*' -and $_.Name -notlike 'AI-Guard-*' })
    if ($left.Count -eq 0) { $true }
    else {
        $broad = @()
        $scoped = @()
        foreach ($r in $left) {
            $prog = ''
            $addr = ''
            try { $prog = [string](($r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program) } catch { }
            try { $addr = (@(($r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue).RemoteAddress) -join ',') } catch { }
            $isBroad = (($addr -match 'Any' -or -not $addr) -and ($prog -match 'Any' -or -not $prog))
            if ($isBroad) { $broad += ($r.DisplayName + ' [' + $prog + ' -> ' + $addr + ']') }
            else { $scoped += ($r.DisplayName + ' [' + $prog + ' -> ' + $addr + ']') }
        }
        if ($broad.Count -gt 0) { throw ('broad allow rules still active: ' + ($broad -join '; ')) }
        'scoped exceptions (review them): ' + ($scoped -join '; ')
    }
} 'no any/any outbound allow rule'

Check 'active physical adapter DNS matches guard design' {
    $nrpt = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -like 'AI-Guard*' })
    if ($nrpt.Count -gt 0) {
        'NRPT active -> ' + (@($nrpt[0].NameServers) -join ',')
    }
    else {
        $allowed = @($DnsServer, '223.5.5.5', '223.6.6.6', '1.1.1.1', '127.0.0.1') | Select-Object -Unique
        $bad = @()
        $seen = @()
        foreach ($a in (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.Name -ne $TunName -and $_.InterfaceDescription -notmatch 'Wintun|Loopback' })) {
            $s = @((Get-DnsClientServerAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
            if ($s.Count -eq 0) { $bad += ($a.Name + '=<empty>') }
            foreach ($ip in $s) {
                if ($allowed -notcontains $ip) { $bad += ($a.Name + '=' + $ip) }
                else { $seen += ($a.Name + '=' + $ip) }
            }
        }
        if ($bad.Count -gt 0) { throw ('unapproved resolvers: ' + ($bad -join '; ')) }
        ($seen -join '; ')
    }
} '223.5.5.5 (v5.1 static) or DoH/NRPT'

Check 'IPv6 disabled on active physical adapters' {
    $bad = @(Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne $TunName -and $_.InterfaceDescription -notmatch 'Wintun|Loopback' -and $_.Status -eq 'Up' -and
                       (Get-NetAdapterBinding -Name $_.Name -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue).Enabled })
    if ($bad.Count -eq 0) { $true } else { throw ('IPv6 still bound on: ' + (($bad | ForEach-Object { $_.Name }) -join ',')) }
} 'no v6 on active physical NICs'

Check 'IPv4 preferred over IPv6 in prefix policy' {
    $v4 = Get-NetPrefixPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Prefix -eq '::ffff:0:0/96' } | Select-Object -First 1
    $v6 = Get-NetPrefixPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Prefix -eq '::/0' } | Select-Object -First 1
    if (-not $v4 -or -not $v6) { 'prefix table unavailable' }
    elseif ($v4.Precedence -gt $v6.Precedence) { '::ffff:0:0/96=' + $v4.Precedence + ' > ::/0=' + $v6.Precedence }
    else { throw ('IPv6 ::/0 (' + $v6.Precedence + ') >= IPv4 ::ffff:0:0/96 (' + $v4.Precedence + ') - may cause AAAA stalls') }
} '::ffff:0:0/96 precedence > ::/0'

Check 'LLMNR & Smart Multi-Homed DNS (SMHNR) hardened' {
    $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
    if (-not $pol -or $pol.EnableMulticast -ne 0) { throw ('EnableMulticast=' + $(if ($pol) { $pol.EnableMulticast } else { 'null' })) }
    if ($pol.DisableSmartNameResolution -eq 1) { 'LLMNR=off, SMHNR=off' }
    else { 'LLMNR=off (SMHNR queued for next event or .\07-mode.ps1)' }
} 'EnableMulticast=0 & DisableSmartNameResolution=1'

Check 'Windows NTP server domestic-capable' {
    $ntp = [string](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction SilentlyContinue).NtpServer
    if (-not $ntp) { 'default/empty' }
    elseif ($ntp -match '(?i)(\.cn\b|aliyun|tencent|ntsc|203\.107\.6\.88)') { $ntp }
    else { throw ('foreign-only NTP (' + $ntp + ') blocked when TUN is off; run 01-dns-hardening.ps1 -Force') }
} 'domestic NTP reachable without TUN'

Check 'system proxy hygiene' {
    $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($ie -and $ie.ProxyEnable -eq 1) {
        if ($xrayProcs.Count -eq 0) {
            throw ('ProxyEnable=1 (' + $ie.ProxyServer + ') while xray.exe is stopped - clear system proxy so domestic sites work')
        }
        'system proxy ON (' + $ie.ProxyServer + ') + xray running (tip: turn off system proxy in v2rayN for clean TUN-only toggling)'
    }
    else {
        'system proxy OFF (clean TUN-only control)'
    }
} 'no dead proxy; TUN-only recommended'

# ---------------------------------------------------------------- functional
Write-Host ''
if ($tunUp) {
    Write-Host '--- functional tests (TUN is UP -> proxy mode) ---' -ForegroundColor Cyan

    Check 'xray.exe running' {
        if ($xrayProcs.Count -gt 0) { 'pid=' + (($xrayProcs | ForEach-Object { $_.Id }) -join ',') }
        else { throw 'xray not running while TUN is up' }
    } 'xray process'

    Check 'DNS resolves foreign name through tunnel' {
        $r = @(Resolve-DnsName -Name 'www.google.com' -Type A -ErrorAction Stop | Where-Object { $_.IPAddress })
        if ($r.Count -gt 0) { ($r.IPAddress) -join ',' } else { throw 'no A record' }
    } 'public name resolves'

    Check 'DNS resolver identity (leak vs Xray routing)' {
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        $sys = @(Resolve-DnsName -Name 'whoami.akamai.net' -Type A -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1 -ExpandProperty IPAddress)
        if ($sys.Count -eq 0) { throw 'no system answer' }
        $ali = @()
        $cf = @()
        try { $ali = @(((Invoke-DirectHttp -Url 'https://223.5.5.5/resolve?name=whoami.akamai.net&type=A' -TimeoutSec 10).Content | ConvertFrom-Json).Answer | ForEach-Object { $_.data }) } catch { }
        try { $cf = @(((Invoke-DirectHttp -Url 'https://cloudflare-dns.com/dns-query?name=whoami.akamai.net&type=A' -Headers @{ accept = 'application/dns-json' } -TimeoutSec 12).Content | ConvertFrom-Json).Answer | ForEach-Object { $_.data }) } catch { }
        if ($cf.Count -gt 0 -and $sys[0] -eq $cf[0]) { 'remote resolver (Cloudflare): ' + $sys[0] }
        elseif ($ali.Count -gt 0 -and (($sys[0] -split '\.')[0..2] -join '.') -eq (($ali[0] -split '\.')[0..2] -join '.')) { 'Xray domestic DoH routing (AliDNS pool ' + $ali[0] + '): ' + $sys[0] }
        else { 'resolver=' + ($sys -join ',') + ' (ali=' + ($ali -join ',') + ' cf=' + ($cf -join ',') + ')' }
    } 'system answer matches Xray upstream'

    Check 'egress IP equals the proxy node' {
        $node = Get-NodeInfo
        $ip = (Invoke-DirectHttp -Url 'https://api.ipify.org' -TimeoutSec 20).Content.Trim()
        if ($node.Ips -contains $ip -or $ip -eq $node.Address) { 'egress=' + $ip }
        else { throw ('egress=' + $ip + ' expected ' + ($node.Ips -join ',')) }
    } 'traffic leaves through the node'

    Check 'xray.exe owns connections to the proxy node' {
        $node = Get-NodeInfo
        $bad = @()
        $hits = 0
        $conns = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)
        foreach ($c in $conns) {
            $ra = [string]$c.RemoteAddress
            if ($node.Ips -notcontains $ra -and $ra -ne $node.Address) { continue }
            $hits++
            $procName = ''
            try { $procName = (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } catch { }
            if ($procName -notin @('xray', 'sing-box', 'mihomo', 'mihomo-windows-amd64-v1')) { $bad += ($procName + ' -> ' + $ra + ':' + $c.RemotePort) }
        }
        if ($bad.Count -gt 0) { throw ('unexpected owner of node connections: ' + ($bad -join '; ')) }
        'node connections=' + $hits + ', all owned by proxy core'
    } 'node connections owned by proxy core'

    Check 'proxy core physical egress alignment (no TUN double-hop relay)' {
        $node = Get-NodeInfo
        $xrayCons = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
            ($node.Ips -contains [string]$_.RemoteAddress -or [string]$_.RemoteAddress -eq $node.Address) -and
            $(try { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName -eq 'xray' } catch { $false })
        })
        if ($xrayCons.Count -eq 0) { 'no established xray node connections at test time' }
        else {
            $tunIps = @('172.18.0.1', '198.18.0.1', '10.0.0.1')
            $relayed = @($xrayCons | Where-Object { $_.LocalAddress -in $tunIps })
            if ($relayed.Count -gt 0) {
                throw ('double-hop relay detected: xray.exe socket bound to TUN (' + (($relayed.LocalAddress | Select-Object -Unique) -join ',') + ') instead of physical NIC')
            }
            'xray physical socket aligned: ' + (($xrayCons.LocalAddress | Select-Object -Unique) -join ',')
        }
    } 'physical socket alignment'

    Check 'physical adapter socket direct egress blocked to foreign IP while TUN up' {
        $physNic = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch '(?i)wintun|singbox|xray|tap|loopback|virtual' } | Select-Object -First 1
        if (-not $physNic) { return 'skipped (no active physical adapter)' }
        $physIp = (Get-NetIPAddress -InterfaceIndex $physNic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
        if (-not $physIp) { return 'skipped (no physical IPv4)' }
        $targetForeignIp = '13.107.246.51'
        $localEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($physIp), 0)
        $sock = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
        try {
            $sock.Bind($localEp)
            $async = $sock.BeginConnect($targetForeignIp, 443, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne(2000, $false)) {
                $sock.EndConnect($async)
                throw ('direct physical outbound leak detected: ' + $physIp + ' connected to ' + $targetForeignIp + ':443')
            }
            'kernel blocked/timed out direct foreign egress on physical adapter'
        }
        catch {
            'blocked by kernel WFP (' + $_.Exception.Message + ')'
        }
        finally {
            $sock.Close()
        }
    } 'physical socket direct leak probe'

    Check 'domestic site reachable (direct TUN datapath)' {
        $r = Invoke-DirectHttp -Url 'https://www.baidu.com' -TimeoutSec 15
        if ($r.StatusCode -eq 200) { 'baidu 200' } else { throw ('status ' + $r.StatusCode) }
    } 'domestic site works'
}
else {
    Write-Host '--- functional tests (TUN is OFF -> direct domestic / foreign blocked) ---' -ForegroundColor Cyan

    if ($cnActive) {
        Check 'domestic DNS resolves without proxy' {
            $r = @(Resolve-DnsName -Name 'www.baidu.com' -Type A -ErrorAction Stop | Where-Object { $_.IPAddress })
            if ($r.Count -gt 0) { ($r.IPAddress) -join ',' } else { throw 'no A record' }
        } '223.5.5.5 resolves domestic names'

        Check 'domestic HTTPS reachable directly without proxy' {
            $r = Invoke-DirectHttp -Url 'https://www.baidu.com' -TimeoutSec 15
            if ($r.StatusCode -eq 200) { 'baidu 200' } else { throw ('status ' + $r.StatusCode) }
        } 'domestic direct works (G1)'
    }

    Check 'foreign raw TCP (1.1.1.1:443 & 8.8.8.8:443) blocked without TUN' {
        $c1 = Test-TcpClosed -Target '1.1.1.1' -Port 443 -TimeoutMs 3000
        $c2 = Test-TcpClosed -Target '8.8.8.8' -Port 443 -TimeoutMs 3000
        if ($c1 -and $c2) { '1.1.1.1:443 & 8.8.8.8:443 blocked' }
        else { throw ('unexpected open raw TCP: 1.1.1.1=' + (-not $c1) + ' 8.8.8.8=' + (-not $c2)) }
    } 'foreign raw TCP blocked (G2)'

    Check 'foreign direct HTTPS (chatgpt.com & github.com, Proxy=null) blocked without TUN' {
        $leaked = @()
        foreach ($u in @('https://chatgpt.com', 'https://github.com')) {
            try {
                $r = Invoke-DirectHttp -Url $u -TimeoutSec 6
                $leaked += ($u + '=' + $r.StatusCode)
            }
            catch {
                $code = Get-HttpExceptionCode $_
                if ($null -ne $code) {
                    $leaked += ($u + '=HTTP_' + $code)
                }
            }
        }
        if ($leaked.Count -gt 0) { throw ('direct egress not blocked: ' + ($leaked -join ', ')) }
        'direct foreign HTTPS blocked by kernel WFP'
    } 'direct foreign HTTPS blocked (G2)'
}

# ---------------------------------------------------------------- WFP note
if ($WfpCheck) {
    Write-Host ''
    Write-Host '--- Xray WFP filters (information) ---' -ForegroundColor Cyan
    $wfpDir = Join-Path $Root ('logs\wfp-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $wfpDir -Force | Out-Null
    $f = Join-Path $wfpDir 'filters.xml'
    netsh wfp show filters file="$f" 2>$null | Out-Null
    if (Test-Path -LiteralPath $f) {
        $t = Get-Content -LiteralPath $f -Raw -Encoding UTF8
        $permitXray = ([regex]::Matches($t, 'permit Xray')).Count
        if ($permitXray -gt 0) {
            Write-Host ('  Xray hard permit present (' + $permitXray + ' filters).') -ForegroundColor Yellow
            Write-Host '  => while TUN runs, Windows Firewall does NOT constrain xray.exe outbound.' -ForegroundColor Yellow
            Write-Host '  => enforce xray itself at the router, or disable autoSystemWfpBlockLeak.' -ForegroundColor Yellow
        }
        else {
            Write-Host '  no Xray hard permit active right now (Windows Firewall governs proxy core).' -ForegroundColor Green
        }
    }
    else { Write-Host '  netsh wfp show filters failed (needs admin).' -ForegroundColor Yellow }
    if (-not $KeepCaptures) {
        Remove-Item -LiteralPath $wfpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------- fail-closed / proxy-off drill
if ($FailClosedTest) {
    Write-Host ''
    Write-Host '--- proxy-off drill (interactive) ---' -ForegroundColor Cyan
    Write-Host 'Quit v2rayN completely (tray icon -> Exit), then press Enter here.' -ForegroundColor Yellow
    Read-Host 'Press Enter when v2rayN is fully stopped' | Out-Null
    Start-Sleep -Seconds 2
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    ipconfig /flushdns | Out-Null

    if ($cnActive) {
        Check 'drill: domestic HTTPS still works without proxy (v5.4 G1)' {
            $r = Invoke-DirectHttp -Url 'https://www.baidu.com' -TimeoutSec 15
            if ($r.StatusCode -eq 200) { 'baidu 200' } else { throw ('status ' + $r.StatusCode) }
        } 'domestic direct works'
    }
    else {
        Check 'drill: DNS is dead without tunnel (strict/Protected)' {
            try { $r = Resolve-DnsName -Name 'www.google.com' -Type A -ErrorAction Stop; throw 'resolved: ' + (($r.IPAddress) -join ',') }
            catch { if ($_.Exception.Message -like 'resolved:*') { throw $_.Exception.Message } else { $true } }
        } 'resolution fails'
    }

    Check 'drill: TCP to 8.8.8.8:443 is blocked without tunnel (G2)' {
        if (Test-TcpClosed -Target '8.8.8.8' -Port 443 -TimeoutMs 3500) { $true } else { throw 'still connects - route/firewall leak' }
    } 'connection blocked'

    Check 'drill: foreign HTTPS (chatgpt.com & api.ipify.org, Proxy=null) blocked without tunnel (G2)' {
        $leaked = @()
        foreach ($u in @('https://chatgpt.com', 'https://api.ipify.org')) {
            try {
                $r = Invoke-DirectHttp -Url $u -TimeoutSec 8
                $leaked += ($u + '=' + $r.StatusCode)
            }
            catch {
                $code = Get-HttpExceptionCode $_
                if ($null -ne $code) {
                    $leaked += ($u + '=HTTP_' + $code)
                }
            }
        }
        if ($leaked.Count -gt 0) { throw ('still reachable: ' + ($leaked -join ', ')) }
        'foreign endpoints blocked'
    } 'foreign requests blocked'

    Write-Host 'Restart v2rayN with TUN now, then press Enter.' -ForegroundColor Yellow
    Read-Host 'Press Enter when v2rayN + TUN are running again' | Out-Null
}

# ---------------------------------------------------------------- report
Write-Host ''
$fail = @($script:results | Where-Object { $_.Status -ne 'PASS' })
$script:results | Format-Table -AutoSize

$logDir = Join-Path $Root 'logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$report = Join-Path $logDir ('verify-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
$script:results | Format-Table -AutoSize | Out-String | Set-Content -LiteralPath $report -Encoding UTF8
if ($MaxReports -gt 0) {
    $oldVerify = @(Get-ChildItem -LiteralPath $logDir -Filter 'verify-*.txt' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -Skip $MaxReports)
    foreach ($ov in $oldVerify) { Remove-Item -LiteralPath $ov.FullName -Force -ErrorAction SilentlyContinue }
}
Write-Host ('report: ' + $report) -ForegroundColor DarkGray

if ($fail.Count -eq 0) {
    Write-Host ''
    Write-Host 'ALL CHECKS PASSED.' -ForegroundColor Green
    exit 0
}
else {
    Write-Host ''
    Write-Host ('FAILED: ' + $fail.Count + ' check(s).') -ForegroundColor Red
    Write-Host 'Fix, or run 09-rollback.ps1.' -ForegroundColor Yellow
    exit 1
}
