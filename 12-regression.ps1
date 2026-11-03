<#
.SYNOPSIS
    AI-Net-Guard v5.6 - automated regression suite (policy-aware, TUN-on/off & multi-core aware, zero capture bloat).

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
    [string]$Root = $(if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\AI-Net-Guard' }),
    [string]$V2rayNRoot = '',
    [string]$TunName = 'xray_tun',
    [string]$DnsServer = '223.5.5.5',
    [int]$CaptureSeconds = 10,
    [int]$DirectWatchSeconds = 12,
    [switch]$KeepCaptures,
    [int]$MaxReports = 10
)

$ErrorActionPreference = 'Continue'
$policyFile = Join-Path $Root 'backup\guard-policy.json'
$guardPolicy = [ordered]@{
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
    DisablePhysicalIpv6  = $true
    PreferIpv4Prefix     = $true
    ZeroResidentMonitor  = $true
    AutoNodeSync         = $true
    AutoHealStaleProxy   = $true
    DomesticNtp          = $true
    HardenInstallAcl     = $true
}
if (Test-Path -LiteralPath $policyFile) {
    try {
        $rawPol = Get-Content -LiteralPath $policyFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($rawPol) {
            foreach ($k in @('AllowCnDirect', 'AllowLan', 'AllowNcsi', 'QuarantineRogueAllow', 'LockPhysicalDns',
                    'DisableSmhnr', 'DisableLlmnrNetbios', 'StrictNrptDoh', 'DisablePhysicalIpv6', 'PreferIpv4Prefix',
                    'ZeroResidentMonitor', 'AutoNodeSync', 'AutoHealStaleProxy', 'DomesticNtp', 'HardenInstallAcl')) {
                if ($rawPol.PSObject.Properties.Name -contains $k -and $null -ne $rawPol.$k) {
                    $guardPolicy[$k] = [bool]$rawPol.$k
                }
            }
            foreach ($sk in @('Version', 'Preset', 'DnsServer', 'V2rayNRoot')) {
                if ($rawPol.PSObject.Properties.Name -contains $sk -and $rawPol.$sk) {
                    $guardPolicy[$sk] = [string]$rawPol.$sk
                }
            }
        }
    }
    catch { }
}
$guardPolicy = [pscustomobject]$guardPolicy
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
        foreach ($cand in @('C:\v2rayN-windows-64', 'D:\v2rayN-windows-64', 'C:\v2rayN', 'D:\v2rayN', (Join-Path $env:LOCALAPPDATA 'v2rayN'), 'C:\Program Files\v2rayN')) {
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
$script:pass = 0
$script:fail = 0
$knownTunNames = @($TunName, 'xray_tun', 'singbox_tun', 'mihomo_tun', 'Meta', 'Mihomo') | Select-Object -Unique

function W($t) {
    Write-Host $t
    $t | Add-Content -LiteralPath $script:log -Encoding UTF8
}

function Check($name, [scriptblock]$body) {
    try {
        $r = & $body
        if ($r -is [bool] -and -not $r) { throw 'assertion returned false' }
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

W ('=== AI-Net-Guard v5.6 regression ' + (Get-Date -Format 'o') + ' ===')
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
        'ok'
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

Check 'LLMNR & Smart Multi-Homed DNS (SMHNR) policy' {
    $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
    $parts = @()
    if ($guardPolicy.DisableLlmnrNetbios) {
        if (-not $pol -or $pol.EnableMulticast -ne 0) { throw ('EnableMulticast=' + $(if ($pol) { $pol.EnableMulticast } else { 'null' })) }
        $parts += 'LLMNR=off'
    }
    else { $parts += 'LLMNR=allowed(policy)' }

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

Check 'install directory ACL policy' {
    if (-not $guardPolicy.HardenInstallAcl) {
        'ACL lock disabled by user policy'
    }
    else {
        $trusted = @('S-1-5-32-544', 'S-1-5-18', 'S-1-3-0', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
        $writeMask = [int64]0x500D0156
        $issues = @()
        $targets = @(Get-Item -LiteralPath $Root -Force) + @(Get-ChildItem -LiteralPath $Root -Force -File -ErrorAction SilentlyContinue)
        foreach ($sub in @('backup', 'logs')) {
            $sp = Join-Path $Root $sub
            if (Test-Path -LiteralPath $sp) { $targets += @(Get-Item -LiteralPath $sp -Force) }
        }
        foreach ($t in $targets) {
            $sections = [System.Security.AccessControl.AccessControlSections]'Owner, Access'
            $acl = if ($t.PSIsContainer) { New-Object System.Security.AccessControl.DirectorySecurity($t.FullName, $sections) }
                   else { New-Object System.Security.AccessControl.FileSecurity($t.FullName, $sections) }
            $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            if ($trusted -notcontains $owner) { $issues += ($t.Name + ': owner=' + $owner) }
            foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                if ($ace.AccessControlType -ne 'Allow' -or ($trusted -contains $ace.IdentityReference.Value)) { continue }
                if (([int64]$ace.FileSystemRights -band $writeMask) -ne 0) { $issues += ($t.Name + ': ' + $ace.IdentityReference.Value + ' has ' + $ace.FileSystemRights) }
            }
        }
        if ($issues.Count -gt 0) { throw ([string]$issues.Count + ' issue(s), e.g. ' + $issues[0] + ' (run .\13-harden-acl.ps1)') }
        ('owner=Administrators, Users=RX, ' + $targets.Count + ' objects checked')
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
    $bCnt = ([regex]::Matches($wf, 'block DNS')).Count
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
$before = @(Get-Content -LiteralPath $cnFile | Where-Object { $_ -and -not $_.StartsWith('#') }).Count
$badGeo = Join-Path $Root 'backup\corrupt-test.dat'
$tmpOut = Join-Path $Root 'backup\corrupt-test-cn.txt'
New-Item -ItemType Directory -Path (Split-Path $badGeo) -Force | Out-Null
[System.IO.File]::WriteAllBytes($badGeo, [byte[]](1..300 | ForEach-Object { $_ % 251 }))
Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue
$code = 0
try {
    & (Join-Path $Root '11-geo-cn.ps1') -Root $Root -GeoFile $badGeo -OutFile $tmpOut -Force -Quiet 2>$null | Out-Null
    $code = $LASTEXITCODE
}
catch { $code = 99 }
$after = @(Get-Content -LiteralPath $cnFile | Where-Object { $_ -and -not $_.StartsWith('#') }).Count
Check 'corrupt geoip rejected without altering CN allowlist' {
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
W ('=== RESULT: PASS=' + $script:pass + ' FAIL=' + $script:fail + ' ===')
Write-Host ('regression report: ' + $script:log) -ForegroundColor Cyan
exit $(if ($script:fail -gt 0) { 1 } else { 0 })
