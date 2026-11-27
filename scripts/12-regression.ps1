<#
.SYNOPSIS
    AI-Net-Guard v5.9.7 - automated regression suite (policy-aware, TUN-on/off & multi-core aware, zero capture bloat).

.DESCRIPTION
    Verifies the v5.4 static guard end-to-end. Read-only, except for a temporary
    WFP dump, pktmon capture, and corrupt geo file - all automatically removed
    when their checks pass (pass -KeepCaptures to retain raw XML/ETL files).

      1. static state: default Block, CN rule >=1000 prefixes, companion rules
         ACTIVE (registry Active=TRUE), zero rogue outbound Allow rules,
         DNS=223.5.5.5, IPv6 binding off, IPv4 prefix precedence > IPv6,
         LLMNR & SMHNR disabled
      2. task health & zero-resident background footprint
      3. functional (Proxy=null direct kernel datapath): adapts automatically
         to TUN-UP (domestic + foreign + egress) or TUN-OFF (domestic + blocked)
      4. WFP: asserts Xray dynamic WFP filters or alternate-core TUN rule
      5. DNS capture: dynamically detects physical & TUN IPv4s and proves zero
         port-53 escape on physical NIC
      6. Core direct-egress detection (supports both Xray and sing-box schemas)
      7. geoip failure & CIDR-collapse drill

    Report: <Root>\logs\regression-<ts>.txt (auto-pruned to newest MaxReports)
#>

[CmdletBinding()]
param(
    [string]$Root = $(if ($PSScriptRoot) { if ((Split-Path -Leaf $PSScriptRoot) -ieq 'scripts') { Split-Path -Parent $PSScriptRoot } else { $PSScriptRoot } } else { 'C:\AI-Net-Guard' }),
    [string]$V2rayNRoot = '',
    [string]$TunName = 'xray_tun',
    [string]$DnsServer = '223.5.5.5',
    [int]$CaptureSeconds = 10,
    [int]$DirectWatchSeconds = 12,
    [switch]$KeepCaptures,
    [int]$MaxReports = 10
)

$ErrorActionPreference = 'Continue'
$libCommonReg = ''
foreach ($cand in @((Join-Path $PSScriptRoot 'lib-guard-common.ps1'), (Join-Path (Join-Path $Root 'scripts') 'lib-guard-common.ps1'), (Join-Path $Root 'lib-guard-common.ps1'))) {
    if ($cand -and (Test-Path -LiteralPath $cand)) { $libCommonReg = $cand; break }
}
if ($libCommonReg) { . $libCommonReg }

$policyFile = Join-Path $Root 'backup\guard-policy.json'
$guardPolicyDefaults = [ordered]@{
    Version              = '5.5'
    Preset               = 'Recommended'
    DnsServer            = $DnsServer
    V2rayNRoot           = ''
    AllowCnDirect        = $true
    AllowLan             = $true
    AllowNcsi            = $true
    QuarantineRogueAllow = $true
    LockPhysicalDns      = $true
    DisableSmhnr         = $true
    DisableLlmnrNetbios  = $true
    StrictNrptDoh        = $false
    BlockWebRtcLeak      = $true
    DisablePhysicalIpv6  = $true
    PreferIpv4Prefix     = $true
    ZeroResidentMonitor  = $true
    AutoNodeSync         = $true
    AutoHealStaleProxy   = $true
    DomesticNtp          = $true
    HardenInstallAcl     = $true
}
if (Get-Command Read-GuardPolicyStrict -ErrorAction SilentlyContinue) {
    $guardPolicy = Read-GuardPolicyStrict -PolicyPath $policyFile -Defaults $guardPolicyDefaults -LastGoodPath (Join-Path $Root 'backup\guard-policy.last-good.json') -NoSaveLastGood
}
else {
    $guardPolicy = [pscustomobject]$guardPolicyDefaults
}
if (-not $PSBoundParameters.ContainsKey('V2rayNRoot') -and $guardPolicy.V2rayNRoot -and (Test-Path -LiteralPath $guardPolicy.V2rayNRoot)) {
    $V2rayNRoot = $guardPolicy.V2rayNRoot
}
if (-not $PSBoundParameters.ContainsKey('DnsServer')) {
    if ($guardPolicy.StrictNrptDoh) { $DnsServer = '1.1.1.1' }
    elseif ($guardPolicy.DnsServer) { $DnsServer = $guardPolicy.DnsServer }
}

if (-not $V2rayNRoot) {
    if ($env:V2RAYN_ROOT -and (Test-Path -LiteralPath $env:V2RAYN_ROOT)) { $V2rayNRoot = $env:V2RAYN_ROOT }
    else {
        # Keep this list in sync with 07-mode.ps1 and the default -V2rayNRoot of
        # 18-route-stun-guard.ps1. Without the -desktop paths, a missing or archived
        # guard-policy.json points the B1 check at a config.json that does not exist,
        # which quietly degrades the guard check into a SKIP even though v2rayN is up.
        foreach ($cand in @('D:\v2rayN-windows-64-desktop\v2rayN-windows-64', 'D:\v2rayN-windows-64-desktop', 'C:\v2rayN-windows-64-desktop\v2rayN-windows-64', 'C:\v2rayN-windows-64', 'D:\v2rayN-windows-64', 'C:\v2rayN', 'D:\v2rayN', (Join-Path $env:LOCALAPPDATA 'v2rayN'), 'C:\Program Files\v2rayN')) {
            if ($cand -and ((Test-Path -LiteralPath (Join-Path $cand 'v2rayN.exe')) -or (Test-Path -LiteralPath (Join-Path $cand 'binConfigs')))) { $V2rayNRoot = $cand; break }
        }
        if (-not $V2rayNRoot) { try { $vp = [System.Diagnostics.Process]::GetProcessesByName('v2rayN'); if ($vp.Length -gt 0 -and $vp[0].MainModule.FileName) { $V2rayNRoot = Split-Path -Parent $vp[0].MainModule.FileName } } catch { } }
        if (-not $V2rayNRoot) { $V2rayNRoot = 'C:\v2rayN-windows-64' }
    }
}
trap {
    if ($script:log) {
        $script:fail++
        Add-Content -LiteralPath $script:log -Value ('  [ERROR] uncaught: ' + $_.Exception.Message) -Encoding UTF8
    }
    continue
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'ERROR: run elevated.' -ForegroundColor Red
    exit 1
}

$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$logDir = Join-Path $Root 'logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$script:log = Join-Path $logDir ('regression-' + $ts + '.txt')
# ------------------------------------------------------------------ shared STUN guard analysis
# B1 lives in the core routing table, not in the firewall, so the physical-NIC STUN
# probes below cannot see it at all. Ask the same question 18 and 07 ask by
# dot-sourcing the shared lib at script scope (its $script: variables and its
# functions must stay in the same scope). A missing lib is a hard error for the
# B1 check, not a silent skip.
$libStun = ''
if ($PSScriptRoot) { $libStun = Join-Path $PSScriptRoot 'lib-stun-guard.ps1' }
if (-not $libStun -or -not (Test-Path -LiteralPath $libStun)) {
    $libStun = Join-Path (Join-Path $Root 'scripts') 'lib-stun-guard.ps1'
}
$stunLibMissing = -not (Test-Path -LiteralPath $libStun)
if (-not $stunLibMissing) {
    . $libStun
}

$script:pass = 0
$script:fail = 0
$script:skip = 0
$knownTunNames = @($TunName, 'xray_tun', 'singbox_tun', 'mihomo_tun', 'Meta', 'Mihomo') | Select-Object -Unique

function W($t) {
    Write-Host $t
    $t | Add-Content -LiteralPath $script:log -Encoding UTF8
}

function Check($name, [scriptblock]$body) {
    try {
        $r = & $body
        if ($r -is [bool] -and -not $r) { throw 'assertion returned false' }
        # A body may opt out by returning a string starting with 'SKIP'. That is NEITHER
        # a pass nor a failure: the check did not run. Counting it as PASS used to let the
        # suite (and the GUI's FAIL=0 banner) claim a clean bill of health for a guard
        # that was never inspected. B1 uses this when v2rayN is down and no core routing
        # table exists yet - a legal fail-closed state, but not a verified one.
        if ($r -is [string] -and $r.StartsWith('SKIP')) {
            $script:skip++
            $line = ('  [SKIP] ' + $name + ' : ' + $r.Substring(4).TrimStart(' ', '-'))
            Write-Host $line -ForegroundColor DarkGray
            $line | Add-Content -LiteralPath $script:log -Encoding UTF8
            return
        }
        $script:pass++
        $detail = ''
        if ($null -ne $r -and $r -isnot [bool]) { $detail = [string]$r }
        $line = ('  [PASS] ' + $name + $(if ($detail) { ' : ' + $detail } else { '' }))
        Write-Host $line -ForegroundColor Green
        $line | Add-Content -LiteralPath $script:log -Encoding UTF8
    }
    catch {
        $script:fail++
        $line = ('  [FAIL] ' + $name + ' : ' + $_.Exception.Message)
        Write-Host $line -ForegroundColor Red
        $line | Add-Content -LiteralPath $script:log -Encoding UTF8
    }
}

function Test-IsTunNic($ni) {
    if (-not $ni) { return $false }
    $hasIp = $ni.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv4) -or
             $ni.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv6)
    if (-not $hasIp) { return $false }
    if ($knownTunNames -contains $ni.Name) { return $true }
    if ($ni.Description -match '(?i)Wintun|sing-tun|Mihomo') { return $true }
    return $false
}

function Get-InterfaceIpv4Map {
    $tunIps = @()
    $physIps = @()
    $tunNames = @()
    foreach ($ni in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($ni.OperationalStatus -ne 'Up') { continue }
        if ($ni.Description -match 'Loopback' -or $ni.NetworkInterfaceType -eq 'Loopback') { continue }
        if (-not ($ni.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv4) -or
                  $ni.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv6))) { continue }
        $v4s = @($ni.GetIPProperties().UnicastAddresses |
            Where-Object { $_.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
            ForEach-Object { $_.Address.IPAddressToString })
        if (Test-IsTunNic $ni) {
            $tunIps += $v4s
            $tunNames += $ni.Name
        }
        else {
            $physIps += $v4s
        }
    }
    [pscustomobject]@{
        TunNames = @($tunNames | Select-Object -Unique)
        TunIps   = @($tunIps | Select-Object -Unique)
        PhysIps  = @($physIps | Select-Object -Unique)
    }
}

function Invoke-DirectHttp {
    param([string]$Url, [int]$TimeoutSec = 12)
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

function Get-ConfiguredNodeInfo {
    $cfgPath = Join-Path $V2rayNRoot 'binConfigs\config.json'
    if (-not (Test-Path -LiteralPath $cfgPath)) { return [pscustomobject]@{ CoreType = 'xray'; Address = ''; Ips = @() } }
    $cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $coreType = 'xray'
    $node = ''
    $xOut = $cfg.outbounds | Where-Object { $_.protocol -in @('vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'wireguard', 'socks', 'http') } | Select-Object -First 1
    if ($xOut) {
        $node = [string]$xOut.settings.address
        if (-not $node -and $xOut.settings.vnext) { $node = [string]$xOut.settings.vnext[0].address }
        if (-not $node -and $xOut.settings.servers) { $node = [string]$xOut.settings.servers[0].address }
    }
    else {
        $sOut = $cfg.outbounds | Where-Object { $_.type -in @('hysteria2', 'hysteria', 'tuic', 'vless', 'vmess', 'trojan', 'shadowsocks', 'wireguard', 'anytls', 'socks', 'http') } | Select-Object -First 1
        if ($sOut) {
            $coreType = 'sing-box'
            $node = [string]$sOut.server
            if (-not $node -and $sOut.peers) { $node = [string]$sOut.peers[0].server }
        }
    }
    $ips = @()
    if ($node -match '^\d{1,3}(\.\d{1,3}){3}$') {
        $ips = @($node)
    }
    elseif ($node) {
        try {
            $doh = (Invoke-DirectHttp -Url ('https://223.5.5.5/resolve?name=' + [uri]::EscapeDataString($node) + '&type=A') -TimeoutSec 4).Content | ConvertFrom-Json
            $ips = @($doh.Answer | Where-Object { $_.type -eq 1 -and $_.data -match '^\d{1,3}(\.\d{1,3}){3}$' } | ForEach-Object { [string]$_.data })
        }
        catch { }
        if ($ips.Count -eq 0) {
            $ips = @(Resolve-DnsName -Name $node -Type A -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
        }
    }
    [pscustomobject]@{
        CoreType = $coreType
        Address  = $node
        Ips      = @($ips | Where-Object { $_ } | Select-Object -Unique)
    }
}

W ('=== AI-Net-Guard v5.9.7 regression ' + (Get-Date -Format 'o') + ' ===')
function Get-ActiveIpPhysicalNics {
    @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {
        $_.OperationalStatus -eq 'Up' -and
        -not (Test-IsTunNic $_) -and
        $_.NetworkInterfaceType -ne 'Loopback' -and
        $_.Description -notmatch 'Loopback|WAN Miniport' -and
        ($_.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv4) -or
         $_.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv6))
    })
}
$ipMap = Get-InterfaceIpv4Map
$tunUp = ($ipMap.TunNames.Count -gt 0)
$nodeInfo = Get-ConfiguredNodeInfo
$nodeAddr = $nodeInfo.Address
W ('TUN up: ' + $tunUp + $(if ($tunUp) { ' (' + ($ipMap.TunNames -join ',') + ')' } else { '' }) + '  TUN IPv4: [' + ($ipMap.TunIps -join ',') + ']  Physical IPv4: [' + ($ipMap.PhysIps -join ',') + ']  Node: ' + $nodeAddr + $(if ($nodeInfo.Ips.Count -gt 0 -and $nodeAddr -notmatch '^\d+\.') { ' (' + ($nodeInfo.Ips -join ',') + ')' } else { '' }) + ' [' + $nodeInfo.CoreType + ']')

# ---------------------------------------------------------------- 1. static state
W ''
W '--- 1. static state ---'
Check 'default outbound = Block (all profiles)' {
    $bad = @(Get-NetFirewallProfile | Where-Object { $_.DefaultOutboundAction -ne 'Block' -or -not $_.Enabled })
    if ($bad.Count -gt 0) { throw (($bad | ForEach-Object { $_.Name }) -join ',') }
    $true
}

Check 'CN allow rule matches policy' {
    $r = Get-NetFirewallRule -Name 'AI-Guard-Allow-CN' -ErrorAction SilentlyContinue
    if (-not $guardPolicy.AllowCnDirect) {
        if ($r -and $r.Enabled -eq 'True') { throw 'expected disabled in strict global lock policy, but Enabled=True' }
        'disabled as configured (strict global lock)'
    }
    else {
        if (-not $r) { throw 'missing AI-Guard-Allow-CN' }
        if ($r.Enabled -ne 'True') { throw 'disabled' }
        $n = @(($r | Get-NetFirewallAddressFilter).RemoteAddress).Count
        if ($n -lt 1000) { throw ('prefixes=' + $n) }
        ('prefixes=' + $n)
    }
}

Check 'required companion rules present AND Active=TRUE' {
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
    $props = (Get-ItemProperty -Path $key -ErrorAction Stop).PSObject.Properties
    $states = @{}
    $rogues = @()
    $exceptions = @()
    $exFile = Join-Path $Root 'backup\allowed-outbound-rules.json'
    if (Test-Path -LiteralPath $exFile) {
        try { $exceptions = @(Get-Content -LiteralPath $exFile -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { $exceptions = @() }
    }
    foreach ($pr in $props) {
        if ($pr.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
        $v = [string]$pr.Value
        $act = ($v -match '(^|\|)Active=TRUE(\||$)')
        $dn = ''
        if ($v -match '(^|\|)Name=([^|]+)') { $dn = $matches[2] }
        if (-not $states.ContainsKey($pr.Name) -or $act) { $states[$pr.Name] = $act }
        if ($dn -and (-not $states.ContainsKey($dn) -or $act)) { $states[$dn] = $act }
        $isAi = ($pr.Name -like 'AI-Guard-*') -or ($dn -and ($dn -like 'AI-Guard-*'))
        if (-not $isAi -and $act -and ($v -match '(^|\|)Dir=Out(\||$)') -and ($v -match '(^|\|)Action=Allow(\||$)')) {
            $exempt = ($exceptions.Count -gt 0) -and (($exceptions -contains $pr.Name) -or ($dn -and ($exceptions -contains $dn)))
            if (-not $exempt) { $rogues += $(if ($dn) { $dn } else { $pr.Name }) }
        }
    }
    $script:regStates = $states
    $script:regRogues = $rogues
    $need = @('AI-Guard-Allow-Node-TCP', 'AI-Guard-Allow-DoH-Ali', 'AI-Guard-Allow-DHCP')
    if ($guardPolicy.AllowLan) { $need += 'AI-Guard-Allow-LAN' }
    $bad = @()
    $tunRuleOk = ($states.ContainsKey('AI-Guard-Allow-TUN') -and $states['AI-Guard-Allow-TUN']) -or ($states.ContainsKey('AI-Guard-Allow-TUN-Alt') -and $states['AI-Guard-Allow-TUN-Alt'])
    if (-not $tunRuleOk) { $bad += 'AI-Guard-Allow-TUN=missing' }
    foreach ($n in $need) {
        if (-not $states.ContainsKey($n)) { $bad += ($n + '=missing') }
        elseif (-not $states[$n]) { $bad += ($n + '=disabled') }
    }
    if (-not $guardPolicy.AllowLan -and $states.ContainsKey('AI-Guard-Allow-LAN') -and $states['AI-Guard-Allow-LAN']) {
        $bad += 'AI-Guard-Allow-LAN=enabled(expected disabled by policy)'
    }
    if ($bad.Count -gt 0) { throw ($bad -join '; ') }
    ('all ' + $need.Count + ' active')
}

Check 'outbound ALLOW drift quarantine matches policy' {
    if (-not $guardPolicy.QuarantineRogueAllow) {
        ('quarantine disabled by policy (active external rules=' + $script:regRogues.Count + ')')
    }
    else {
        if ($script:regRogues.Count -gt 0) {
            throw ('found ' + $script:regRogues.Count + ': ' + (($script:regRogues | Select-Object -First 5) -join '; '))
        }
        '0 rogue rules'
    }
}

Check ('physical adapter DNS policy (' + $(if ($guardPolicy.LockPhysicalDns) { $DnsServer } else { 'unlocked/DHCP' }) + ')') {
    if (-not $guardPolicy.LockPhysicalDns -and -not $guardPolicy.StrictNrptDoh) {
        'unlocked as configured by policy'
    }
    else {
        $bad = @()
        foreach ($a in (Get-ActiveIpPhysicalNics)) {
            if (-not $a.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv4)) { continue }
            $s = @((Get-DnsClientServerAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
            if (($s -join ',') -ne $DnsServer) { $bad += ($a.Name + '=' + ($s -join ',')) }
        }
        if ($bad.Count -gt 0) { throw ($bad -join '; ') }
        $cDoh = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome' -ErrorAction SilentlyContinue).DnsOverHttpsMode
        $eDoh = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -ErrorAction SilentlyContinue).DnsOverHttpsMode
        if ($cDoh -ne 'off' -or $eDoh -ne 'off') {
            throw ('Chromium DnsOverHttpsMode mismatch: Chrome=' + $cDoh + ' Edge=' + $eDoh)
        }
        'ok (Chrome+Edge DoH=off)'
    }
}

Check 'physical adapter IPv6 policy' {
    if (-not $guardPolicy.DisablePhysicalIpv6) {
        'IPv6 allowed by user policy'
    }
    else {
        $names = @(Get-ActiveIpPhysicalNics | ForEach-Object { $_.Name })
        if ($names.Count -eq 0) { throw 'no active physical adapter' }
        foreach ($n in $names) {
            $b = Get-NetAdapterBinding -Name $n -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue
            if ($b -and $b.Enabled) { throw ('IPv6 enabled on ' + $n) }
        }
        'ok'
    }
}

Check 'IPv4/IPv6 prefix precedence policy' {
    if (-not $guardPolicy.PreferIpv4Prefix) {
        'default prefix policy kept by user policy'
    }
    else {
        $v4 = Get-NetPrefixPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Prefix -eq '::ffff:0:0/96' } | Select-Object -First 1
        $v6 = Get-NetPrefixPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Prefix -eq '::/0' } | Select-Object -First 1
        if ($v4 -and $v6 -and $v4.Precedence -le $v6.Precedence) {
            throw ('::ffff:0:0/96 (' + $v4.Precedence + ') <= ::/0 (' + $v6.Precedence + ')')
        }
        ('::ffff:0:0/96=' + $v4.Precedence + ' > ::/0=' + $v6.Precedence)
    }
}

Check 'LLMNR, mDNS & Smart Multi-Homed DNS (SMHNR) policy' {
    $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
    $svc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -ErrorAction SilentlyContinue
    $parts = @()
    if ($guardPolicy.DisableLlmnrNetbios) {
        if (-not $pol -or $pol.EnableMulticast -ne 0) { throw ('EnableMulticast=' + $(if ($pol) { $pol.EnableMulticast } else { 'null' })) }
        if (-not $svc -or $svc.EnableMDNS -ne 0) { throw ('EnableMDNS=' + $(if ($svc) { $svc.EnableMDNS } else { 'null' })) }
        $parts += 'LLMNR=off'
        $parts += 'mDNS=off'
    }
    else { $parts += 'LLMNR=allowed(policy), mDNS=allowed(policy)' }

    if ($guardPolicy.DisableSmhnr) {
        $v54Migrated = Test-Path -LiteralPath (Join-Path $Root 'backup\v54-migrated.flag')
        if ($pol -and $pol.DisableSmartNameResolution -eq 1) {
            $parts += 'SMHNR=off'
        }
        elseif (-not $v54Migrated) {
            $parts += 'SMHNR=queued'
        }
        else {
            throw ('DisableSmartNameResolution=' + $(if ($pol) { $pol.DisableSmartNameResolution } else { 'null' }))
        }
    }
    else { $parts += 'SMHNR=allowed(policy)' }
    ($parts -join ', ')
}

Check 'WebRTC STUN/TURN leak-shield policy' {
    $u = Get-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-UDP' -ErrorAction SilentlyContinue
    $t = Get-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-TCP' -ErrorAction SilentlyContinue
    $lu = Get-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-LocalIP-UDP' -ErrorAction SilentlyContinue
    $lt = Get-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-LocalIP-TCP' -ErrorAction SilentlyContinue
    $c = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome' -ErrorAction SilentlyContinue).WebRtcIPHandlingPolicy
    $e = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -ErrorAction SilentlyContinue).WebRtcIPHandlingPolicy
    if ($guardPolicy.BlockWebRtcLeak) {
        if (-not $u -or $u.Enabled -ne 'True' -or -not $t -or $t.Enabled -ne 'True' -or -not $lu -or $lu.Enabled -ne 'True' -or -not $lt -or $lt.Enabled -ne 'True') {
            throw 'WebRTC firewall rules missing or disabled'
        }
        if ($c -ne 'disable_non_proxied_udp' -or $e -ne 'disable_non_proxied_udp') {
            throw ('Chromium WebRtcIPHandlingPolicy mismatch: Chrome=' + $c + ' Edge=' + $e)
        }
        'FW(NIC+LocalIP UDP/TCP)=ON, Chrome+Edge=disable_non_proxied_udp'
    }
    else {
        'WebRTC leak-shield disabled by user policy'
    }
}

Check 'B1 STUN route guard present in core routing table' {
    if ($stunLibMissing) { throw ('lib-stun-guard.ps1 not found: ' + $libStun) }
    $cfg = Join-Path $V2rayNRoot 'binConfigs\config.json'
    if (-not (Test-Path -LiteralPath $cfg)) {
        # v2rayN down is a legal fail-closed state: the WFP rules still hold and there
        # is no core routing table to inspect. Report it, do not fail the whole suite.
        return 'SKIP - core config not generated; B1 not checkable while v2rayN is down'
    }
    $a = Get-StunGuardAnalysis -ConfigPath $cfg -Expected @(Get-StunGuardPorts)
    if ($a.State -ne 'present') {
        throw ('B1 guard ' + $a.State + ' (rule #' + $a.Index + ') - close v2rayN, then run scripts\18-route-stun-guard.ps1 -Apply')
    }
    if ($a.Shadow -gt 0) {
        throw ('B1 guard SHADOWED by ' + $a.Shadow + ' preceding rule(s): ' + (@($a.ShadowRules) -join '; '))
    }
    # A caveat is a known limitation, not a failure: 07-mode.ps1 shows it as a note and
    # verify-leak-test.ps1 reports PASSED WITH CAVEAT. Keep the same verdict here.
    $ruleSpan = if (($a.PSObject.Properties.Name -contains 'RuleCount') -and $a.RuleCount -eq 1) {
        'rule #' + $a.Index
    }
    else {
        'rules #' + $a.Index + '/' + ($a.Index + 1)
    }
    $out = 'loaded (' + $ruleSpan + ', udp+tcp, ' + (@(Get-StunGuardPorts)).Count + ' ports)'
    if ($a.Caveat -gt 0) { $out += ' - caveat: ' + $a.Caveat + ' origin-scoped rule(s) ahead may bypass it' }
    $out
}

Check 'explicit physical-NIC foreign block policy (IPv4 + IPv6)' {
    $v4Act = $script:regStates.ContainsKey('AI-Guard-Block-Foreign-Physical') -and $script:regStates['AI-Guard-Block-Foreign-Physical']
    if (-not $v4Act) { throw 'AI-Guard-Block-Foreign-Physical missing or disabled' }
    $v6Act = $script:regStates.ContainsKey('AI-Guard-Block-Foreign-Physical-IPv6') -and $script:regStates['AI-Guard-Block-Foreign-Physical-IPv6']
    if ($guardPolicy.DisablePhysicalIpv6) {
        if (-not $v6Act) { throw 'AI-Guard-Block-Foreign-Physical-IPv6 missing or disabled' }
        'IPv4=active, IPv6(2000::/3)=active'
    }
    else {
        if ($v6Act) { throw 'AI-Guard-Block-Foreign-Physical-IPv6 active while DisablePhysicalIpv6=false' }
        'IPv4=active, IPv6=disabled(policy)'
    }
}

Check 'ActiveStore WFP enforcement & address-filter readback' {
    $activeIdx = @{}
    foreach ($ar in @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)) {
        if (-not $ar) { continue }
        $an = [string]$ar.Name
        $ad = [string]$ar.DisplayName
        if ($an -and (-not $activeIdx.ContainsKey($an) -or $ar.Enabled -eq 'True')) { $activeIdx[$an] = $ar }
        if ($ad -and (-not $activeIdx.ContainsKey($ad) -or $ar.Enabled -eq 'True')) { $activeIdx[$ad] = $ar }
    }
    $fpRule = if ($activeIdx.ContainsKey('AI-Guard-Block-Foreign-Physical')) { $activeIdx['AI-Guard-Block-Foreign-Physical'] } else { $null }
    if (-not $fpRule -or $fpRule.Enabled -ne 'True' -or $fpRule.Action -ne 'Block') {
        throw 'AI-Guard-Block-Foreign-Physical not active/Block in ActiveStore'
    }
    $fpRanges = @(($fpRule | Get-NetFirewallAddressFilter -ErrorAction Stop).RemoteAddress)
    if ($fpRanges.Count -lt 100) {
        throw ('AI-Guard-Block-Foreign-Physical ActiveStore truncated: ranges=' + $fpRanges.Count)
    }

    $v6Msg = 'disabled(policy)'
    if ($guardPolicy.DisablePhysicalIpv6) {
        $fp6Rule = if ($activeIdx.ContainsKey('AI-Guard-Block-Foreign-Physical-IPv6')) { $activeIdx['AI-Guard-Block-Foreign-Physical-IPv6'] } else { $null }
        if (-not $fp6Rule -or $fp6Rule.Enabled -ne 'True' -or $fp6Rule.Action -ne 'Block') {
            throw 'AI-Guard-Block-Foreign-Physical-IPv6 not active/Block in ActiveStore'
        }
        $fp6Ranges = @(($fp6Rule | Get-NetFirewallAddressFilter -ErrorAction Stop).RemoteAddress)
        if ($fp6Ranges -notcontains '2000::/3') {
            throw ('AI-Guard-Block-Foreign-Physical-IPv6 ActiveStore missing 2000::/3 (' + ($fp6Ranges -join ',') + ')')
        }
        $v6Msg = '2000::/3'
    }

    $cnMsg = 'disabled(policy)'
    if ($guardPolicy.AllowCnDirect) {
        $cnActiveRule = if ($activeIdx.ContainsKey('AI-Guard-Allow-CN')) { $activeIdx['AI-Guard-Allow-CN'] } else { $null }
        if (-not $cnActiveRule -or $cnActiveRule.Enabled -ne 'True' -or $cnActiveRule.Action -ne 'Allow') {
            throw 'AI-Guard-Allow-CN not active/Allow in ActiveStore'
        }
        $cnActiveCnt = @(($cnActiveRule | Get-NetFirewallAddressFilter -ErrorAction Stop).RemoteAddress).Count
        if ($cnActiveCnt -lt 1000) {
            throw ('AI-Guard-Allow-CN ActiveStore count too low: ' + $cnActiveCnt)
        }
        $cnMsg = [string]$cnActiveCnt
    }

    $tunMsg = 'tun-down'
    if ($tunUp) {
        $tunActiveRule = if ($activeIdx.ContainsKey('AI-Guard-Allow-TUN')) { $activeIdx['AI-Guard-Allow-TUN'] } elseif ($activeIdx.ContainsKey('AI-Guard-Allow-TUN-Alt')) { $activeIdx['AI-Guard-Allow-TUN-Alt'] } else { $null }
        if (-not $tunActiveRule -or $tunActiveRule.Enabled -ne 'True' -or $tunActiveRule.Action -ne 'Allow') {
            throw 'AI-Guard-Allow-TUN not active/Allow in ActiveStore'
        }
        $tunMsg = 'ok'
    }

    ('Foreign-v4=' + $fpRanges.Count + ' ranges, Foreign-v6=' + $v6Msg + ', CN=' + $cnMsg + ', TUN=' + $tunMsg)
}

Check 'physical-IP-on-TUN block policy' {
    if (-not $tunUp) { return 'SKIP - TUN is down' }
    if (-not ($script:regStates.ContainsKey('AI-Guard-Block-PhysicalIP-On-TUN') -and $script:regStates['AI-Guard-Block-PhysicalIP-On-TUN'])) {
        throw 'AI-Guard-Block-PhysicalIP-On-TUN missing or disabled while TUN is up'
    }
    'active'
}

Check 'no orphaned PersistentStore /32 node host routes' {
    $p32 = @(Get-NetRoute -PolicyStore PersistentStore -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DestinationPrefix -like '*/32' -and
            $_.RouteMetric -eq 1 -and
            $_.InterfaceAlias -notmatch '(?i)tun|wintun|sing|xray|meta|mihomo|loopback'
        })
    $orphans = @()
    foreach ($pr in $p32) {
        $rip = ($pr.DestinationPrefix -split '/')[0]
        if (-not $rip -or ($rip -notmatch '^\d{1,3}(\.\d{1,3}){3}$')) { continue }
        if ($rip -match '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)') { continue }
        $oct0 = [int]($rip.Split('.')[0])
        if ($oct0 -ge 224) { continue }
        $orphans += $pr.DestinationPrefix
    }
    if ($orphans.Count -gt 0) {
        throw ($orphans.Count.ToString() + ' orphaned PersistentStore /32 route(s), e.g. ' + $orphans[0] + ' (run 10-sync-node-rule.ps1 -PruneStaleNodeRoutes)')
    }
    '0 persistent /32 routes'
}

Check 'install directory ACL policy' {
    if (-not $guardPolicy.HardenInstallAcl) {
        'ACL lock disabled by user policy'
    }
    else {
        if (-not (Get-Command Get-GuardInstallAclIssues -ErrorAction SilentlyContinue)) {
            throw 'lib-guard-common.ps1 missing - cannot run recursive ACL check'
        }
        $issues = @(Get-GuardInstallAclIssues -Path $Root)
        if ($issues.Count -gt 0) { throw ([string]$issues.Count + ' issue(s), e.g. ' + $issues[0] + ' (run .\13-harden-acl.ps1)') }
        'recursive ACL + ReparsePoint clean (owner=Administrators, Users=RX)'
    }
}

# ---------------------------------------------------------------- 2. tasks & background footprint
W ''
W '--- 2. task health & background footprint ---'
Check 'monitor + fallback tasks policy (AI-Guard-Mode-*)' {
    $ev = Get-ScheduledTask -TaskName 'AI-Guard-Mode-Event' -ErrorAction SilentlyContinue
    $w = Get-ScheduledTask -TaskName 'AI-Guard-Mode-Watcher' -ErrorAction SilentlyContinue
    $f = Get-ScheduledTask -TaskName 'AI-Guard-Mode-Fallback' -ErrorAction SilentlyContinue
    if (-not $guardPolicy.ZeroResidentMonitor) {
        if ($ev -or $w -or $f) { throw 'expected no AI-Guard-Mode-* tasks when ZeroResidentMonitor=false' }
        'unregistered as configured by policy'
    }
    else {
        if ((-not $ev -and -not $w) -or (-not $f)) { throw 'missing monitor or fallback task (run 07-mode.ps1 -InstallTasks)' }
        if ($ev) {
            ('AI-Guard-Mode-Event(' + $ev.State + '), AI-Guard-Mode-Fallback(' + $f.State + ')')
        }
        else {
            ('AI-Guard-Mode-Watcher(' + $w.State + '), AI-Guard-Mode-Fallback(' + $f.State + ')')
        }
    }
}

Check 'background footprint (zero-resident event mode vs legacy daemon)' {
    $ev = Get-ScheduledTask -TaskName 'AI-Guard-Mode-Event' -ErrorAction SilentlyContinue
    $wd = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -and $_.CommandLine -match 'watchdog\.ps1' })
    if (-not $guardPolicy.ZeroResidentMonitor) {
        if ($wd.Count -gt 0) { throw ('unexpected resident watchdog pid=' + (($wd | ForEach-Object { $_.ProcessId }) -join ',')) }
        '0 resident scripts (background monitor disabled by policy)'
    }
    elseif ($ev) {
        if ($wd.Count -gt 0) { throw ('orphaned resident watchdog pid=' + (($wd | ForEach-Object { $_.ProcessId }) -join ',')) }
        '0 resident scripts (0 MB idle RAM, event + sleep-resume triggered)'
    }
    else { 'opt-in resident watchdog running (pid=' + (($wd | ForEach-Object { $_.ProcessId }) -join ',') + ')' }
}

# ---------------------------------------------------------------- 3. functional
W ''
W '--- 3. functional (Proxy=null direct kernel datapath) ---'
function Find-WfpBlockOrigin {
    param([string]$DestinationIP, [datetime]$Since)
    if (-not $DestinationIP) { return $null }
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5157; StartTime = $Since } `
            -MaxEvents 100 -ErrorAction Stop
    }
    catch {
        return $null
    }
    foreach ($e in $events) {
        try { $xmlDoc = [xml]$e.ToXml() } catch { continue }
        $ns = New-Object System.Xml.XmlNamespaceManager($xmlDoc.NameTable)
        $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
        $dest = $xmlDoc.SelectSingleNode('//e:EventData/e:Data[@Name="DestAddress"]', $ns)
        if (-not $dest -or $dest.'#text' -ne $DestinationIP) { continue }
        $origin = $xmlDoc.SelectSingleNode('//e:EventData/e:Data[@Name="FilterOrigin"]', $ns)
        if ($origin -and $origin.'#text') { return [string]$origin.'#text' }
        return 'Security-5157'
    }
    return $null
}

function Test-UrlStatus($url) {
    try { return [string](Invoke-DirectHttp -Url $url -TimeoutSec 12).StatusCode }
    catch {
        # PowerShell wraps .NET GetResponse() exceptions in MethodInvocationException;
        # unwrap InnerException chain to reach the underlying System.Net.WebException.
        $ex = $_.Exception
        while ($ex -and -not ($ex -is [System.Net.WebException])) { $ex = $ex.InnerException }
        if ($ex -and $ex.Response) {
            $c = [int]$ex.Response.StatusCode
            try { $ex.Response.Close() } catch { }
            return ('HTTP ' + $c)
        }
        return 'BLOCKED'
    }
}

if (-not $guardPolicy.AllowCnDirect -and -not $tunUp) {
    foreach ($u in @('https://www.baidu.com', 'https://www.qq.com')) {
        Check ('domestic blocked in strict global lock when TUN off ' + $u) {
            $st = Test-UrlStatus $u
            if ($st -ne 'BLOCKED') { throw ('expected BLOCKED, got ' + $st) }
            'BLOCKED'
        }
    }
}
elseif ($guardPolicy.AllowCnDirect) {
    foreach ($u in @('https://www.baidu.com', 'https://www.qq.com')) {
        Check ('domestic ' + $u) { $st = Test-UrlStatus $u; if ($st -ne '200') { throw $st }; $st }
    }
}

if ($tunUp) {
    foreach ($u in @('https://github.com', 'https://chatgpt.com')) {
        Check ('foreign via TUN ' + $u) { $st = Test-UrlStatus $u; if ($st -notin @('200', 'HTTP 403')) { throw $st }; $st }
    }
    Check 'egress = proxy node' {
        $ip = (Invoke-DirectHttp -Url 'https://api.ipify.org' -TimeoutSec 15).Content.Trim()
        if ($nodeInfo.Ips.Count -gt 0 -and ($nodeInfo.Ips -notcontains $ip) -and ($ip -ne $nodeAddr)) {
            throw ('egress=' + $ip + ' expected=' + ($nodeInfo.Ips -join ','))
        }
        $ip
    }

    Check 'physical adapter socket direct egress blocked to foreign IP while TUN up' {
        $physNic = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch '(?i)wintun|sing-tun|mihomo|singbox|xray|tap|loopback|virtual' -and $_.Name -notmatch '(?i)tun|loopback|xray|singbox|mihomo' } | Select-Object -First 1
        if (-not $physNic) { return 'SKIP - no active physical adapter' }
        $physIp = (Get-NetIPAddress -InterfaceIndex $physNic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
        if (-not $physIp) { return 'SKIP - no physical IPv4' }
        $targetForeignIp = '13.107.246.51'
        $probeSince = (Get-Date).AddSeconds(-2)
        $localEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($physIp), 0)
        $sock = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
        $leakedTcp = $false
        $msgTcp = 'kernel blocked/timed out direct foreign egress on physical adapter'
        try {
            $sock.Bind($localEp)
            $async = $sock.BeginConnect($targetForeignIp, 443, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne(2000, $false)) {
                $sock.EndConnect($async)
                $leakedTcp = $true
            }
        }
        catch {
            $msgTcp = 'blocked by kernel WFP (' + $_.Exception.Message + ')'
        }
        finally {
            $sock.Close()
        }
        if ($leakedTcp) { throw ('direct physical outbound leak detected: ' + $physIp + ' connected to ' + $targetForeignIp + ':443') }
        $origin5157 = Find-WfpBlockOrigin -DestinationIP $targetForeignIp -Since $probeSince
        if ($origin5157) { $msgTcp += '; WFP 5157 FilterOrigin=' + $origin5157 }
        $msgTcp
    }

    if ($guardPolicy.BlockWebRtcLeak) {
        Check 'physical adapter raw WebRTC STUN UDP (19302) blocked' {
            $physNic = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch '(?i)wintun|sing-tun|mihomo|singbox|xray|tap|loopback|virtual' -and $_.Name -notmatch '(?i)tun|loopback' } | Select-Object -First 1
            if (-not $physNic) { return 'SKIP - no active physical adapter' }
            $physIp = (Get-NetIPAddress -InterfaceIndex $physNic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
            if (-not $physIp) { return 'SKIP - no physical IPv4' }
            $stunReqObj = if (-not $stunLibMissing) { New-StunBindingRequest } else { [pscustomobject]@{ Packet = [byte[]]@(0x00,0x01,0x00,0x00,0x21,0x12,0xA4,0x42,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC); TransactionId = [byte[]]@(0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC) } }
            $stunTargetIp = '74.125.250.129'
            $probeSince = (Get-Date).AddSeconds(-2)
            $localEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($physIp), 0)
            $udp = New-Object System.Net.Sockets.UdpClient($localEp)
            $udp.Client.ReceiveTimeout = 2000
            $leakedStun = $false
            $leakedInfo = ''
            $msgStun = 'STUN UDP blocked/timed out'
            try {
                [void]$udp.Send($stunReqObj.Packet, $stunReqObj.Packet.Length, $stunTargetIp, 19302)
                $rem = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $resp = $udp.Receive([ref]$rem)
                if ($resp -and $resp.Length -gt 0) {
                    $leakedStun = $true
                    $mapped = if (-not $stunLibMissing) { ConvertFrom-StunResponse -Packet $resp -TransactionId $stunReqObj.TransactionId } else { $null }
                    $leakedInfo = if ($mapped) { 'mapped=' + $mapped } else { 'non-STUN/mismatched reply ' + $resp.Length + 'B' }
                }
            }
            catch {
                $msgStun = 'blocked/timed out on ' + $physIp + ' (' + $_.Exception.Message + ')'
            }
            finally {
                $udp.Close()
            }
            if ($leakedStun) { throw ('WebRTC STUN UDP leak detected on physical NIC ' + $physIp + ' -> ' + $stunTargetIp + ':19302 (' + $leakedInfo + ')') }
            $origin5157 = Find-WfpBlockOrigin -DestinationIP $stunTargetIp -Since $probeSince
            if ($origin5157) { $msgStun += '; WFP 5157 FilterOrigin=' + $origin5157 }
            $msgStun
        }
    }
}
else {
    foreach ($u in @('https://github.com', 'https://chatgpt.com')) {
        Check ('foreign blocked directly when TUN off ' + $u) {
            $st = Test-UrlStatus $u
            if ($st -ne 'BLOCKED') { throw ('expected BLOCKED, got ' + $st) }
            'BLOCKED'
        }
    }
}

if ($guardPolicy.AllowCnDirect -or $tunUp) {
    Check 'domestic DNS resolves quickly' {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = @(Resolve-DnsName -Name 'www.baidu.com' -Type A -ErrorAction Stop | Where-Object { $_.IPAddress })
        $sw.Stop()
        if ($r.Count -eq 0) { throw 'no answer' }
        ((([int]$sw.Elapsed.TotalMilliseconds).ToString()) + ' ms')
    }
}

# ---------------------------------------------------------------- 4. WFP (auto-cleans 8.7 MB XML dump on PASS)
W ''
W '--- 4. WFP ---'
$failBeforeWfp = $script:fail
$wfpDir = Join-Path $logDir ('wfp-reg-' + $ts)
New-Item -ItemType Directory -Path $wfpDir -Force | Out-Null
$wfpFile = Join-Path $wfpDir 'filters.xml'
netsh wfp show filters file="$wfpFile" 2>$null | Out-Null
if (Test-Path -LiteralPath $wfpFile) {
    $wf = Get-Content -LiteralPath $wfpFile -Raw -Encoding UTF8
    $pCnt = ([regex]::Matches($wf, 'permit Xray')).Count
    $bCnt = ([regex]::Matches($wf, 'block (?:the )?DNS|block (?:tcp|udp)/(?:53|853)')).Count
    if ($tunUp) {
        if ($nodeInfo.CoreType -eq 'xray' -and ($ipMap.TunNames -contains 'xray_tun')) {
            Check 'permit Xray present while TUN up' { if ($pCnt -le 0) { throw 'count=0' }; ('count=' + $pCnt) }
            Check 'block DNS present while TUN up' { if ($bCnt -le 0) { throw 'count=0' }; ('count=' + $bCnt) }
        }
        else {
            Check ('alternate core (' + $nodeInfo.CoreType + ') TUN firewall rule active') {
                $hasTunUp = ($ipMap.TunNames.Count -gt 0)
                $tunRuleActive = ($script:regStates.ContainsKey('AI-Guard-Allow-TUN') -and $script:regStates['AI-Guard-Allow-TUN']) -or ($script:regStates.ContainsKey('AI-Guard-Allow-TUN-Alt') -and $script:regStates['AI-Guard-Allow-TUN-Alt'])
                $okAlt = $hasTunUp -and $tunRuleActive
                if (-not $okAlt) { throw 'missing active TUN rule for alternate core' }
                ('active for ' + ($ipMap.TunNames -join ','))
            }
        }
    }
    else {
        Check 'Xray dynamic WFP filters absent while TUN off' { if ($pCnt -ne 0) { throw ('count=' + $pCnt) }; 'count=0' }
    }
}
if (($script:fail -eq $failBeforeWfp) -and (-not $KeepCaptures)) {
    Remove-Item -LiteralPath $wfpDir -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------- 5. DNS capture (auto-cleans ETL/TXT on PASS)
if ($tunUp -and $ipMap.TunIps.Count -gt 0 -and $ipMap.PhysIps.Count -gt 0) {
    W ''
    W ('--- 5. DNS capture (' + $CaptureSeconds + ' s, dynamic NIC IPs) ---')
    $failBeforeDns = $script:fail
    $capDir = Join-Path $logDir ('dns-reg-' + $ts)
    New-Item -ItemType Directory -Path $capDir -Force | Out-Null
    $etl = Join-Path $capDir 'dns.etl'
    $capTxt = Join-Path $capDir 'dns.txt'
    pktmon filter remove 2>$null | Out-Null
    pktmon filter add -p 53 2>$null | Out-Null
    pktmon start --capture --pkt-size 96 -f "$etl" 2>$null | Out-Null
    Start-Sleep -Seconds 1
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    foreach ($d in @('www.baidu.com', 'www.zhihu.com', 'www.bilibili.com', 'www.jd.com')) {
        try { [void](Resolve-DnsName -Name $d -Type A -QuickTimeout -ErrorAction SilentlyContinue) } catch { }
        Start-Sleep -Milliseconds 500
    }
    Start-Sleep -Seconds $CaptureSeconds
    pktmon stop 2>$null | Out-Null
    pktmon filter remove 2>$null | Out-Null

    if (Test-Path -LiteralPath $etl) {
        pktmon etl2txt "$etl" -o "$capTxt" 2>$null | Out-Null
        if (Test-Path -LiteralPath $capTxt) {
            $lines = @(Get-Content -LiteralPath $capTxt -ErrorAction SilentlyContinue)
            $tunRegex = '(' + (($ipMap.TunIps | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
            $physRegex = '(' + (($ipMap.PhysIps | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
            # Pure ASCII unicode escapes for Chinese Windows pktmon drop labels (ShanChu / DiuQi)
            $dropRegex = '(?i)(Drop|\u5220\u9664|\u4E22\u5F03)'

            $tunCount = 0
            $physAttempts = 0
            $physDropped = 0
            $physSent = 0
            $curDrop = $false
            foreach ($line in $lines) {
                if ($line -match '\[Microsoft-Windows-PktMon\].*?\bPktGroupId\b') {
                    $curDrop = ($line -match $dropRegex)
                }
                elseif ($line -match '^\s*(ip|ipv6):\s+(\S+)\s+>\s+(\S+):') {
                    $src = $matches[2]
                    $dst = $matches[3]
                    $isDns = ($src -match '(\.53\b|:53\b)') -or ($dst -match '(\.53\b|:53\b)')
                    if ($isDns) {
                        if (($src -match $tunRegex) -or ($dst -match $tunRegex)) { $tunCount++ }
                        if (($src -match $physRegex) -or ($dst -match $physRegex)) {
                            $physAttempts++
                            if ($curDrop) { $physDropped++ } else { $physSent++ }
                        }
                    }
                }
            }




            Check 'port-53 traffic routed into TUN' {
                if ($tunCount -le 0) { throw '0 packets seen on TUN IP' }
                ('tun_pkts=' + $tunCount)
            }
            Check 'no port-53 plaintext packets escaped physical NIC' {
                if ($physSent -gt 0) { throw ('escaped=' + $physSent + ' of ' + $physAttempts) }
                ('phys_attempts=' + $physAttempts + ', dropped=' + $physDropped + ', escaped=0')
            }
        }
    }
    if (($script:fail -eq $failBeforeDns) -and (-not $KeepCaptures)) {
        Remove-Item -LiteralPath $capDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
else {
    W ''
    W '--- 5. DNS capture skipped (TUN is off or single-IP state) ---'
}

# ---------------------------------------------------------------- 6. proxy core direct egress
W ''
W '--- 6. Proxy core direct egress (whitelist routing) ---'
$coreProc = @(Get-Process -Name @('xray', 'sing-box', 'mihomo', 'mihomo-windows-amd64-v1') -ErrorAction SilentlyContinue) | Select-Object -First 1
if (-not $guardPolicy.AllowCnDirect) {
    W '  skipped (CN direct whitelist disabled by strict global lock policy)'
}
elseif ($coreProc -and $tunUp) {
    $corePid = $coreProc.Id
    $job = Start-Job {
        if ([int][Net.ServicePointManager]::SecurityProtocol -ne 0) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
        1..5 | ForEach-Object {
            try {
                $rq = [System.Net.HttpWebRequest]::Create('https://www.baidu.com')
                $rq.Proxy = $null
                $rq.Timeout = 8000
                $rs = $rq.GetResponse()
                $rs.Close()
            }
            catch { }
        }
    }
    $seen = @{}
    $deadline = (Get-Date).AddSeconds($DirectWatchSeconds)
    while ((Get-Date) -lt $deadline) {
        foreach ($c in @(Get-NetTCPConnection -OwningProcess $corePid -State Established -ErrorAction SilentlyContinue)) {
            $ra = [string]$c.RemoteAddress
            if (-not $ra) { continue }
            if ($ra -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254)') { continue }
            if ($ra -eq $nodeAddr -or ($nodeInfo.Ips -contains $ra) -or $ra -in @('223.5.5.5', '223.6.6.6')) { continue }
            $seen[$ra + ':' + $c.RemotePort] = $true
        }
        Start-Sleep -Milliseconds 700
    }
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    Check ($coreProc.ProcessName + ' direct CN connections observed (whitelist routing)') {
        if ($seen.Count -eq 0) { throw 'none observed in window' }
        (($seen.Keys | Sort-Object) -join ', ')
    }
}
else {
    W '  skipped (proxy core not running or TUN off)'
}

# ---------------------------------------------------------------- 7. geoip drill
W ''
W '--- 7. geoip failure drill ---'
$cnFile = Join-Path $Root 'cn-ipv4.txt'
$cnFileExists = Test-Path -LiteralPath $cnFile
$before = if ($cnFileExists) { @(Get-Content -LiteralPath $cnFile | Where-Object { $_ -and -not $_.StartsWith('#') }).Count } else { 0 }
$badGeo = Join-Path $Root 'backup\corrupt-test.dat'
$tmpOut = Join-Path $Root 'backup\corrupt-test-cn.txt'
New-Item -ItemType Directory -Path (Split-Path $badGeo) -Force | Out-Null
[System.IO.File]::WriteAllBytes($badGeo, [byte[]](1..300 | ForEach-Object { $_ % 251 }))
Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue
$code = 0
try {
    & (if (Test-Path (Join-Path (Join-Path $Root 'scripts') '11-geo-cn.ps1')) { Join-Path (Join-Path $Root 'scripts') '11-geo-cn.ps1' } else { Join-Path $Root '11-geo-cn.ps1' }) -Root $Root -GeoFile $badGeo -OutFile $tmpOut -Force -Quiet 2>$null | Out-Null
    $code = $LASTEXITCODE
}
catch { $code = 99 }
$after = if (Test-Path -LiteralPath $cnFile) { @(Get-Content -LiteralPath $cnFile | Where-Object { $_ -and -not $_.StartsWith('#') }).Count } else { 0 }
Check 'corrupt geoip rejected without altering CN allowlist' {
    if (-not $cnFileExists) { throw ('cn-ipv4.txt missing at ' + $cnFile) }
    if ($before -lt 1000) { throw ('baseline cn-ipv4.txt too small: ' + $before) }
    if ($code -eq 0) { throw 'parser accepted corrupt data' }
    if ($before -ne $after) { throw ('list size changed: ' + $before + ' -> ' + $after) }
    if (Test-Path -LiteralPath $tmpOut) { throw 'temp output was written' }
    ('exit=' + $code + ', prefixes=' + $after)
}
Remove-Item -LiteralPath $badGeo -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------- log & capture hygiene
if (-not $KeepCaptures) {
    $cutoff = (Get-Date).AddHours(-24)
    foreach ($oldCap in @(Get-ChildItem -LiteralPath $logDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(wfp-reg-|dns-reg-|wfp-\d)' -and $_.LastWriteTime -lt $cutoff })) {
        Remove-Item -LiteralPath $oldCap.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
}
if ($MaxReports -gt 0) {
    $oldReps = @(Get-ChildItem -LiteralPath $logDir -Filter 'regression-*.txt' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -Skip $MaxReports)
    foreach ($or in $oldReps) { Remove-Item -LiteralPath $or.FullName -Force -ErrorAction SilentlyContinue }
}

# ---------------------------------------------------------------- summary
W ''
W ('=== RESULT: PASS=' + $script:pass + ' FAIL=' + $script:fail + $(if ($script:skip -gt 0) { ' SKIP=' + $script:skip } else { '' }) + ' ===')
Write-Host ('regression report: ' + $script:log) -ForegroundColor Cyan
exit $(if ($script:fail -gt 0) { 1 } else { 0 })
