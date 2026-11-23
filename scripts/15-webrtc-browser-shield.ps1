<#
.SYNOPSIS
    AI-Net-Guard - WebRTC browser shield (port-independent, program-scoped).

.DESCRIPTION
    The stock port-list shield (AI-Guard-Block-WebRTC-{UDP,TCP}) only covers
    3478/3479/5349/5350/19302-19309.  Browsers can reach STUN/TURN on 443 or any
    other port, and those requests are allowed out of the physical NIC whenever
    the destination is a mainland-China IP (AI-Guard-Allow-CN) - that is the last
    path by which a real ISP address can still reach a STUN server.

    This script closes it at the source: for each browser executable it creates
    an outbound BLOCK rule scoped to
        protocol  = UDP          (everything WebRTC ICE can leak through)
        interface = physical NICs only
        program   = chrome.exe / msedge.exe (one rule each)
        port      = ANY          (port-independent, covers 443/8080/ephemeral)

    Why program-scoped instead of a blanket UDP block: a blanket block would also
    kill DHCP (67/68), plaintext DNS (53), NTP (123) and the proxy node's own UDP
    transport, because Windows Firewall gives BLOCK precedence over ALLOW at equal
    weight.  Scoping to the browser obtains the same protection with zero risk to
    the tunnel itself, and when the TUN is up the browser never egresses the
    physical NIC anyway (its traffic enters xray_tun) - so normal browsing is
    untouched.

    It also repairs the two drift bugs in the stock shield:
      * AI-Guard-Block-WebRTC-{UDP,TCP}   interface list re-synced to all live physical NICs
      * AI-Guard-Block-WebRTC-LocalIP-*   LocalAddress widened from the single leased address
        (the stock rules stored whatever IP existed at apply time, e.g. 192.168.1.165, and went
        dead after a DHCP renumber) to the physical NIC subnet, so an in-LAN lease change no
        longer voids the block.  /32 is kept whenever the subnet would also cover a TUN address,
        because that would black-hole proxied WebRTC instead of unproxied leaks.

    Third gap, measured on 2026-11-22 with a live ICE probe: blocking the browser process is
    not enough when a TUN is up.  The browser hands the STUN packet to the tunnel, the tunnel
    core re-sends it from the physical NIC, and the rule that names chrome.exe never sees it.
    A CN-resident STUN server (stun.miwifi.com, stun.chat.bilibili.com) matched geoip:cn ->
    direct and came back with the real ISP address (183.188.38.12), while Google/Cloudflare
    STUN servers returned the proxy exit (20.89.232.246).  That is exactly the "sometimes it
    leaks, sometimes it does not" pattern: it depends on which STUN server the test page hits.

    Follow-up measurement, same day, independent STUN client (no browser involved): the
    Program-scoped BLOCK rules this script creates do NOT stop it either.  With all eight
    AI-Guard-Block-WebRTC-* rules Active=TRUE and the exact core path, port list and interface
    GUIDs in place, a raw UDP STUN request still came back with the real ISP address.  Windows
    Firewall gives an explicit BLOCK precedence over every ALLOW rule, so the losing comparison
    is not rule specificity: the TUN provider terminates ALE_AUTH_CONNECT for the core's own
    re-send with a PERMIT, and the firewall's block filters are never evaluated at all.  These
    rules stay as defence in depth (they do stop a core that egresses without a TUN), but the
    layer that actually closes this leak is scripts/18-route-stun-guard.ps1, which drops the
    STUN/TURN port set inside the core's routing table.

.PARAMETER Apply     Create/update the rules (default action).
.PARAMETER Verify    Read-only report of the current shield state.
.PARAMETER Remove    Delete the browser-shield rules and restore the stock interface/IP lists.
.PARAMETER DryRun    Show what would change without touching the firewall.
.PARAMETER Quiet     Suppress per-item chatter (used by 02-killswitch / 07-mode auto-heal).

.NOTES
    Creating or changing firewall rules requires an elevated PowerShell.
    Exit codes: 0 ok, 1 error, 5 not elevated.
#>

[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Verify,
    [switch]$Remove,
    [switch]$DryRun,
    [switch]$Quiet,
    [string]$Root = $(if ($PSScriptRoot) { (Split-Path -Parent $PSScriptRoot) } else { 'C:\AI-Net-Guard' })
)

$ErrorActionPreference = 'Stop'

function Say($m, $c = 'Gray') { if (-not $Quiet) { Write-Host $m -ForegroundColor $c } }

# The STUN/TURN port set is defined once, in lib-stun-guard.ps1 (see the header there).
# This script repairs rules created by 02/07/14 from that same list, so reading its own
# copy here is how a "repair" can quietly rewrite a rule back to a stale port list. A
# missing lib is a hard stop: an empty list would create a rule that blocks every port.
$libStun = Join-Path $PSScriptRoot 'lib-stun-guard.ps1'
if (-not (Test-Path -LiteralPath $libStun)) { $libStun = Join-Path (Join-Path $Root 'scripts') 'lib-stun-guard.ps1' }
if (-not (Test-Path -LiteralPath $libStun)) {
    Write-Host ('[!] lib-stun-guard.ps1 not found: ' + $libStun) -ForegroundColor Red
    Write-Host '    refusing to touch the STUN/TURN rules without the shared port list.' -ForegroundColor Red
    exit 1
}
. $libStun

# ------------------------------------------------------------ NetSecurity cache
# Measured on this host: Get-NetFirewallRule costs ~1.23 s per call whether or not
# -Name narrows it, and each Get-NetFirewall*Filter costs another ~0.3 s. Discovery
# alone probed six rule names, so a single -Apply run burned ~12 s before touching
# anything. The index below enumerates once and serves every later lookup from memory;
# any write invalidates it, because repairing from a stale object re-applies drift.
$script:RuleIndex = $null
$script:RuleFilterCache = @{}

function Reset-RuleCache {
    $script:RuleIndex = $null
    $script:RuleFilterCache = @{}
}

function Get-RuleIndex {
    if ($null -ne $script:RuleIndex) { return $script:RuleIndex }
    $idx = @{}
    try {
        foreach ($r in @(Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
            if (-not $r) { continue }
            $n = [string]$r.Name
            if ($n -and -not $idx.ContainsKey($n)) { $idx[$n] = $r }
            $d = [string]$r.DisplayName
            if ($d -and -not $idx.ContainsKey($d)) { $idx[$d] = $r }
        }
    }
    catch { }
    $script:RuleIndex = $idx
    return $idx
}

function Get-GuardRule([string]$Key) {
    if (-not $Key) { return $null }
    $idx = Get-RuleIndex
    if ($idx.ContainsKey($Key)) { return $idx[$Key] }
    return $null
}

function Get-GuardRuleFilter([string]$Key, [string]$Kind) {
    $ck = $Kind + '|' + $Key
    if ($script:RuleFilterCache.ContainsKey($ck)) { return $script:RuleFilterCache[$ck] }
    $val = $null
    $r = Get-GuardRule $Key
    if ($r) {
        try {
            switch ($Kind) {
                'Interface' { $val = @(($r | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue).InterfaceAlias) }
                'Address' { $val = @(($r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue).LocalAddress) }
                'Application' { $val = ($r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program }
                'Port' { $val = @(($r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue).RemotePort) }
            }
        }
        catch { $val = $null }
    }
    $script:RuleFilterCache[$ck] = $val
    return $val
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------------------------------------------------------- discovery
$knownTun = @('xray_tun', 'singbox_tun', 'mihomo_tun', 'Meta', 'Mihomo', 'wintun')

$physical = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -ne 'Not Present' -and
        $_.InterfaceDescription -notmatch '(?i)Wintun|sing-tun|Mihomo|TAP-Windows|Loopback' -and
        $_.Name -notmatch '(?i)loopback' -and
        ($knownTun -notcontains $_.Name)
    })

if ($physical.Count -eq 0) {
    Say 'no physical NIC found - nothing to scope' 'Yellow'
    exit 0
}
$physNames = @($physical | Select-Object -ExpandProperty Name | Select-Object -Unique)

# One enumeration of the IPv4 table feeds the lease list, the TUN addresses and the subnet
# scope below. Get-NetIPAddress costs ~0.45 s per call, and the script used to issue three.
$allV4 = @()
try { $allV4 = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue) } catch { }

$physIps = @()
try {
    $physIps = @($allV4 |
        Where-Object { $_.IPAddress -and ($physNames -contains $_.InterfaceAlias) -and $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        Select-Object -ExpandProperty IPAddress -Unique)
}
catch { }

# ---------------------------------------------------------------- subnet helpers
# A rule that stores the concrete DHCP lease dies the moment the router renumbers it: the rule
# stays Enabled=True but points at an address this host no longer owns, so it blocks nothing.
# Widening to the NIC's own subnet survives an in-LAN renumber; /32 is kept when the subnet
# would also cover a TUN address (blocking there would kill proxied WebRTC, not leaks).
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

function Get-IPv4PrefixFromMask([string]$Mask) {
    $bits = 0
    foreach ($x in ([System.Net.IPAddress]::Parse($Mask)).GetAddressBytes()) {
        for ($i = 7; $i -ge 0; $i--) { if ((([int]$x -shr $i) -band 1) -eq 1) { $bits++ } }
    }
    return $bits
}

function Get-IPv4NetworkText([string]$Ip, [byte[]]$Mask) {
    $ipb = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
    $n = New-Object 'byte[]' 4
    for ($i = 0; $i -lt 4; $i++) { $n[$i] = [byte]($ipb[$i] -band $Mask[$i]) }
    return (([string]$n[0]) + '.' + ([string]$n[1]) + '.' + ([string]$n[2]) + '.' + ([string]$n[3]))
}

function ConvertTo-IPv4CidrSet([string[]]$Values) {
    # normalise any mix of '1.2.3.4', '1.2.3.0/24', '1.2.3.0/255.255.255.0' into '1.2.3.0/24'
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($v in $Values) {
        if (-not $v) { continue }
        foreach ($tok in ([string]$v -split ',')) {
            $t = $tok.Trim()
            if (-not $t -or $t -eq 'Any' -or $t -match ':') { continue }
            $parts = $t -split '/'
            $ip = $parts[0].Trim()
            if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { continue }
            $plen = 32
            if ($parts.Count -ge 2) {
                $mx = $parts[1].Trim()
                if ($mx -match '^\d+$') { $plen = [int]$mx } else { $plen = Get-IPv4PrefixFromMask $mx }
            }
            if ($plen -lt 0 -or $plen -gt 32) { $plen = 32 }
            $mask = Get-IPv4MaskBytes $plen
            $cidr = (Get-IPv4NetworkText $ip $mask) + '/' + ([string]$plen)
            if (-not $out.Contains($cidr)) { $out.Add($cidr) }
        }
    }
    return $out.ToArray()   # plain return (no leading comma) so callers can wrap with @()
}

$physCidrs = @()
$tunIps = @()
try {
    $tunIps = @($allV4 |
        Where-Object { $_.IPAddress -and ($knownTun -contains $_.InterfaceAlias) } |
        Select-Object -ExpandProperty IPAddress -Unique)
}
catch { }
try {
    foreach ($pa in @($allV4 |
            Where-Object { $_.IPAddress -and ($physNames -contains $_.InterfaceAlias) -and $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' })) {
        $ip = [string]$pa.IPAddress
        $plen = 32
        try { $plen = [int]$pa.PrefixLength } catch { $plen = 32 }
        if ($plen -le 0 -or $plen -gt 32) { $plen = 32 }
        $mask = Get-IPv4MaskBytes $plen
        $net = Get-IPv4NetworkText $ip $mask
        $overlap = $false
        if ($plen -lt 32) {
            foreach ($ti in $tunIps) {
                if ((Get-IPv4NetworkText $ti $mask) -eq $net) { $overlap = $true; break }
            }
        }
        $cidr = if ($plen -ge 32 -or $overlap) { ($ip + '/32') } else { ($net + '/' + ([string]$plen)) }
        if ($physCidrs -notcontains $cidr) { $physCidrs += $cidr }
    }
}
catch { }

# browser executables we actually guard (only when the file exists)
$candidates = [ordered]@{
    'Chrome' = (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe')
    'Edge'   = (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe')
}
$extra = @(
    (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'),
    (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe')
)
foreach ($p in $extra) {
    if (-not $p) { continue }
    if ((Test-Path -LiteralPath $p) -and -not ($candidates.Values -contains $p)) {
        $tag = if ($p -match 'msedge') { 'Edge' } else { 'Chrome' }
        $candidates[$tag + '-alt'] = $p
    }
}

$targets = @()
foreach ($k in $candidates.Keys) {
    $exe = $candidates[$k]
    if (Test-Path -LiteralPath $exe) { $targets += [pscustomobject]@{ Tag = $k; Exe = $exe } }
}

# proxy cores: the process that actually egresses the physical NIC while a TUN is up.
# Prefer the live process path; when the core is stopped, derive the bin root from the
# running v2rayN GUI so the rules still get created before the tunnel comes back.
$coreExe = New-Object System.Collections.Generic.List[string]
foreach ($n in @('xray', 'sing-box', 'mihomo', 'mihomo-windows-amd64-v1')) {
    foreach ($p in @(Get-Process -Name $n -ErrorAction SilentlyContinue)) {
        try { if ($p.Path) { if (-not $coreExe.Contains($p.Path)) { $coreExe.Add($p.Path) } } } catch { }
    }
}
if ($coreExe.Count -eq 0) {
    # An unelevated shell cannot read the path of a core running at a higher integrity,
    # but the guard's own Allow rules already store it. Reuse them before guessing dirs.
    foreach ($rn in @('AI-Guard-Allow-Node-TCP', 'AI-Guard-Allow-Core-Xray-TCP', 'AI-Guard-Allow-Core-Xray-UDP',
            'AI-Guard-Allow-Core-SingBox-TCP', 'AI-Guard-Allow-Core-mihomo-TCP', 'AI-Guard-Allow-Core-mihomo-windows-amd64-v1-TCP')) {
        $rr = Get-GuardRule $rn
        if (-not $rr) { continue }
        $prog = [string](Get-GuardRuleFilter $rn 'Application')
        if (-not $prog -or $prog -eq 'Any') { continue }
        if ($prog -notmatch '(?i)(xray|sing-box|mihomo).*\.exe$') { continue }
        if ((Test-Path -LiteralPath $prog) -and -not $coreExe.Contains($prog)) { $coreExe.Add($prog) }
    }
}
if ($coreExe.Count -eq 0) {
    $binRoots = New-Object System.Collections.Generic.List[string]
    foreach ($pn in @('v2rayN', 'v2rayN-Core')) {
        foreach ($p in @(Get-Process -Name $pn -ErrorAction SilentlyContinue)) {
            try { if ($p.Path) { $binRoots.Add((Join-Path (Split-Path $p.Path -Parent) 'bin')) } } catch { }
        }
    }
    $binRoots.Add((Join-Path $env:APPDATA 'v2rayN\bin'))
    foreach ($br in $binRoots) {
        if (-not (Test-Path -LiteralPath $br)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $br -Recurse -Include 'xray.exe', 'sing-box.exe', 'mihomo.exe', 'mihomo-windows-amd64-v1.exe' -File -ErrorAction SilentlyContinue)) {
            if (-not $coreExe.Contains($f.FullName)) { $coreExe.Add($f.FullName) }
        }
    }
}
$cores = @()
foreach ($e in $coreExe) {
    $tag = [System.IO.Path]::GetFileNameWithoutExtension($e)
    $cores += [pscustomobject]@{ Tag = $tag; Exe = $e }
}

# STUN / TURN well-known ports, from lib-stun-guard.ps1 (the single definition).
# 19302-19309 covers the Google STUN pool; Windows Firewall has no port-range object here.
$stunPorts = @(Get-StunGuardPortStrings)

Say ' '
Say ('physical NICs : ' + ($physNames -join ', ')) 'Cyan'
Say ('physical IPv4 : ' + $(if ($physIps.Count) { $physIps -join ', ' } else { '(none)' })) 'Cyan'
Say ('LocalIP scope : ' + $(if ($physCidrs.Count) { $physCidrs -join ', ' } else { '(none)' })) 'Cyan'
Say ('browsers      : ' + $(if ($targets.Count) { ($targets | ForEach-Object { $_.Tag }) -join ', ' } else { '(none found)' })) 'Cyan'
Say ('proxy cores   : ' + $(if ($cores.Count) { ($cores | ForEach-Object { $_.Tag }) -join ', ' } else { '(none found - core STUN block will NOT be created)' })) $(if ($cores.Count) { 'Cyan' } else { 'Red' })

# ---------------------------------------------------------------- helpers
function Get-RuleInterfaceList([string]$Name) {
    if (-not (Get-GuardRule $Name)) { return $null }
    @(Get-GuardRuleFilter $Name 'Interface' | Where-Object { $_ -and $_ -ne 'Any' -and $_ -ne '0' })
}

function Get-RuleLocalAddressList([string]$Name) {
    if (-not (Get-GuardRule $Name)) { return $null }
    @(Get-GuardRuleFilter $Name 'Address' | Where-Object { $_ -and $_ -ne 'Any' })
}

$stockIfRules = @('AI-Guard-Block-WebRTC-UDP', 'AI-Guard-Block-WebRTC-TCP')
$stockIpRules = @('AI-Guard-Block-WebRTC-LocalIP-UDP', 'AI-Guard-Block-WebRTC-LocalIP-TCP')
$shieldRules = @($targets | ForEach-Object { 'AI-Guard-Block-WebRTC-' + $_.Tag + '-PhysUDP' })
foreach ($c in $cores) {
    foreach ($proto in @('UDP', 'TCP')) {
        $shieldRules += ('AI-Guard-Block-WebRTC-' + $c.Tag + '-CoreSTUN-' + $proto)
    }
}

# ---------------------------------------------------------------- verify
if ($Verify) {
    Say ' '
    Say '=== browser shield state ===' 'Cyan'
    foreach ($n in $shieldRules) {
        $r = Get-GuardRule $n
        if (-not $r) { Say ('  {0,-46} MISSING' -f $n) 'Red'; continue }
        $ifs = @(Get-RuleInterfaceList $n)
        $ifText = $ifs -join ','
        $ap = [string](Get-GuardRuleFilter $n 'Application')
        # language independent check: the rule must target at least one live physical NIC
        # (adapter aliases differ per OS language, e.g. WLAN / Ethernet / a localized name)
        $ifOk = (@($physNames | Where-Object { $ifs -contains $_ }).Count -gt 0)
        $ok = ($r.Enabled -eq 'True') -and ($r.Action -eq 'Block') -and $ifOk
        Say ('  {0,-46} {1} enabled={2} if={3} prog={4}' -f $n, $(if ($ok) { 'OK  ' } else { 'DRIFT' }), $r.Enabled, $ifText, (Split-Path -Leaf $ap)) $(if ($ok) { 'Green' } else { 'Yellow' })
    }
    if ($cores.Count -eq 0) {
        Say '  [warn] no proxy core detected - TUN-mode STUN egress stays open' 'Red'
    }
    else {
        foreach ($c in $cores) {
            foreach ($proto in @('UDP', 'TCP')) {
                $cn = 'AI-Guard-Block-WebRTC-' + $c.Tag + '-CoreSTUN-' + $proto
                if (-not (Get-GuardRule $cn)) { continue }
                $cports = @(Get-GuardRuleFilter $cn 'Port')
                $missingPorts = @($stunPorts | Where-Object { $cports -notcontains $_ })
                if ($missingPorts.Count -gt 0) {
                    Say ('  {0,-46} port drift (missing {1})' -f $cn, ($missingPorts -join ',')) 'Yellow'
                }
            }
        }
    }
    Say ' '
    Say '=== stock shield drift ===' 'Cyan'
    foreach ($n in $stockIfRules) {
        $cur = Get-RuleInterfaceList $n
        if ($null -eq $cur) { Say ('  {0,-46} MISSING' -f $n) 'Red'; continue }
        $missing = @($physNames | Where-Object { $cur -notcontains $_ })
        Say ('  {0,-46} if={1} {2}' -f $n, ($cur -join ','), $(if ($missing.Count) { 'DRIFT (missing ' + ($missing -join ',') + ')' } else { 'OK' })) $(if ($missing.Count) { 'Yellow' } else { 'Green' })
    }
    foreach ($n in $stockIpRules) {
        $cur = Get-RuleLocalAddressList $n
        if ($null -eq $cur) { Say ('  {0,-46} MISSING' -f $n) 'Red'; continue }
        $curSet = @(@(ConvertTo-IPv4CidrSet $cur) | Sort-Object -Unique)
        $expSet = @(@($physCidrs) | Sort-Object -Unique)
        $same = (($curSet -join ';') -eq ($expSet -join ';'))
        Say ('  {0,-46} la={1} {2}' -f $n, ($cur -join ','), $(if ($same) { 'OK' } else { 'DRIFT (expected ' + ($expSet -join ',') + ')' })) $(if ($same) { 'Green' } else { 'Yellow' })
    }
    Say ' '
    exit 0
}

# ---------------------------------------------------------------- remove
if ($Remove) {
    if (-not $isAdmin) { Say 'ERROR: needs an elevated PowerShell.' 'Red'; exit 5 }
    $removed = 0
    foreach ($n in $shieldRules) {
        if (-not (Get-GuardRule $n)) { continue }
        Remove-NetFirewallRule -Name $n -ErrorAction SilentlyContinue
        Say ('  removed ' + $n) 'Yellow'
        $removed++
    }
    # core rules are built from the live process list, so sweep by pattern as well - a core
    # that is not running right now must not leave a stray block behind.  The sweep reads
    # the cached index instead of re-enumerating (that cost 1.4 s on its own).
    $coreRuleNames = @()
    foreach ($rr in @((Get-RuleIndex).Values)) {
        if (-not $rr) { continue }
        $nm = [string]$rr.Name
        if ($nm -notmatch '^AI-Guard-Block-WebRTC-(.+)-CoreSTUN-(?:UDP|TCP)$') { continue }
        if ($coreRuleNames -contains $nm) { continue }
        $coreRuleNames += $nm
        Remove-NetFirewallRule -Name $nm -ErrorAction SilentlyContinue
        Say ('  removed ' + $nm) 'Yellow'
        $removed++
    }
    if ($removed -gt 0) { Reset-RuleCache }
    # put the two stock LocalAddress rules back on their original exact-IP (/32) behaviour
    if ($physIps.Count -gt 0) {
        foreach ($n in $stockIpRules) {
            if (Get-GuardRule $n) {
                Set-NetFirewallRule -Name $n -LocalAddress $physIps -Enabled True -ErrorAction SilentlyContinue
                Reset-RuleCache
                Say ('  restored {0} LocalAddress -> {1}' -f $n, ($physIps -join ',')) 'Yellow'
            }
        }
    }
    Say 'browser shield removed (stock rules restored, port-list shield untouched).' 'Green'
    exit 0
}

# ---------------------------------------------------------------- apply
if (-not $isAdmin -and -not $DryRun) {
    Say 'ERROR: creating firewall rules requires an elevated PowerShell.' 'Red'
    Say '        Re-run this script with -Apply from an admin shell, or run 14-apply-policy.ps1 -Apply.' 'Yellow'
    exit 5
}

$changed = 0

# 1) browser-scoped, port-independent UDP block on physical NICs
foreach ($t in $targets) {
    $name = 'AI-Guard-Block-WebRTC-' + $t.Tag + '-PhysUDP'
    $exists = Get-GuardRule $name
    if ($DryRun) {
        Say ('  [dry] {0} -> {1}' -f $name, $t.Exe) 'DarkGray'
        continue
    }
    if ($exists) {
        $cur = @(Get-RuleInterfaceList $name)
        $missing = @($physNames | Where-Object { $cur -notcontains $_ })
        if ($missing.Count -gt 0 -or $exists.Enabled -ne 'True' -or $exists.Action -ne 'Block') {
            Set-NetFirewallRule -Name $name -InterfaceAlias $physNames -Enabled True -Action Block -ErrorAction Stop
            Reset-RuleCache
            Say ('  updated {0} (if: {1})' -f $name, ($physNames -join ',')) 'Green'
            $changed++
        }
        else {
            Say ('  ok      {0}' -f $name) 'DarkGray'
        }
    }
    else {
        New-NetFirewallRule -Name $name -DisplayName $name -Direction Outbound -Action Block `
            -Protocol UDP -Program $t.Exe -InterfaceAlias $physNames -Profile Any -Enabled True `
            -Group 'AI-Net-Guard' `
            -Description ('Block all UDP from ' + $t.Tag + ' on physical NICs (port-independent WebRTC/STUN/TURN leak shield).') | Out-Null
        Reset-RuleCache
        Say ('  created {0} -> {1}' -f $name, $t.Exe) 'Green'
        $changed++
    }
}

# 2) repair the stock rules' interface / address drift
foreach ($n in $stockIfRules) {
    $cur = Get-RuleInterfaceList $n
    if ($null -eq $cur) { continue }
    $missing = @($physNames | Where-Object { $cur -notcontains $_ })
    if ($missing.Count -gt 0) {
        if ($DryRun) { Say ('  [dry] {0} add interfaces: {1}' -f $n, ($missing -join ',')) 'DarkGray' }
        else { Set-NetFirewallRule -Name $n -InterfaceAlias $physNames -ErrorAction Stop; Reset-RuleCache; Say ('  updated {0} (if: {1})' -f $n, ($physNames -join ',')) 'Green'; $changed++ }
    }
}

# The two LocalAddress rules carry the physical-NIC scope that survives a DHCP renumber.
# Compare as sets (not "is the new IP missing"), so a lease left over from an old subnet is
# pruned instead of lingering forever on a rule that looks healthy.
$webrtcPorts = @(Get-StunGuardPortStrings)
foreach ($n in $stockIpRules) {
    if ($physCidrs.Count -eq 0) { Say ('  skip    {0} (no physical IPv4)' -f $n) 'Yellow'; continue }
    $cur = Get-RuleLocalAddressList $n
    $curSet = @(@(ConvertTo-IPv4CidrSet $cur) | Sort-Object -Unique)
    $expSet = @(@($physCidrs) | Sort-Object -Unique)
    $proto = if ($n -match 'UDP$') { 'UDP' } else { 'TCP' }
    if ($null -ne $cur -and (($curSet -join ';') -eq ($expSet -join ';'))) { Say ('  ok      {0} (la: {1})' -f $n, ($expSet -join ',')) 'DarkGray'; continue }
    if ($DryRun) { Say ('  [dry] {0} set LocalAddress: {1}' -f $n, ($expSet -join ',')) 'DarkGray'; continue }
    if ($null -eq $cur) {
        New-NetFirewallRule -Name $n -DisplayName $n -Direction Outbound -Action Block -Protocol $proto `
            -LocalAddress $expSet -RemotePort $webrtcPorts -Profile Any -Enabled True -Group 'AI-Net-Guard' `
            -Description ('Block WebRTC STUN/TURN ' + $proto + ' bound to physical NIC subnets even when TUN metric 0 captures ALE routing.') | Out-Null
        Reset-RuleCache
        Say ('  created {0} (la: {1})' -f $n, ($expSet -join ',')) 'Green'
    }
    else {
        Set-NetFirewallRule -Name $n -LocalAddress $expSet -Enabled True -ErrorAction Stop
        Reset-RuleCache
        Say ('  updated {0} (la: {1})' -f $n, ($expSet -join ',')) 'Green'
    }
    $changed++
}

# 3) proxy-core STUN/TURN block on the physical NICs.  Browser-scoped rules never see this
#    traffic: with a TUN up the browser sends the STUN packet into the tunnel and the core
#    re-sends it out of the physical NIC.  AI-Guard-Allow-CN (explicit CN address list, any
#    program, any port) outranks the program-less AI-Guard-Block-WebRTC-UDP, so a CN STUN
#    server still answers with the real ISP address.  A Program-scoped block is the more
#    specific filter and wins that comparison.
foreach ($c in $cores) {
    foreach ($proto in @('UDP', 'TCP')) {
        $name = 'AI-Guard-Block-WebRTC-' + $c.Tag + '-CoreSTUN-' + $proto
        $exists = Get-GuardRule $name
        if ($DryRun) {
            Say ('  [dry] {0} -> {1} : {2}' -f $name, $c.Exe, ($stunPorts -join ',')) 'DarkGray'
            continue
        }
        $needFix = $true
        if ($exists) {
            $curIf = @(Get-RuleInterfaceList $name)
            $curPorts = @(Get-GuardRuleFilter $name 'Port')
            $missingIf = @($physNames | Where-Object { $curIf -notcontains $_ })
            $missingPt = @($stunPorts | Where-Object { $curPorts -notcontains $_ })
            if ($missingIf.Count -eq 0 -and $missingPt.Count -eq 0 -and $exists.Enabled -eq 'True' -and $exists.Action -eq 'Block') {
                $needFix = $false
            }
        }
        if (-not $needFix) { Say ('  ok      {0}' -f $name) 'DarkGray'; continue }
        if ($exists) { Remove-NetFirewallRule -Name $name -ErrorAction SilentlyContinue }
        New-NetFirewallRule -Name $name -DisplayName $name -Direction Outbound -Action Block `
            -Protocol $proto -Program $c.Exe -RemotePort $stunPorts -InterfaceAlias $physNames `
            -Profile Any -Enabled True -Group 'AI-Net-Guard' `
            -Description ('Block STUN/TURN ' + $proto + ' from the tunnel core on physical NICs (a CN-resident STUN server reached through geoip:cn -> direct would otherwise return the real ISP address).') | Out-Null
        Reset-RuleCache
        $verb = if ($exists) { 'updated' } else { 'created' }
        Say ('  {0} {1} -> {2}' -f $verb, $name, $c.Exe) 'Green'
        $changed++
    }
}
if ($cores.Count -eq 0) {
    Say '  [warn] no proxy core found - core STUN block skipped (TUN-mode leak path stays open)' 'Red'
}

Say ' '
if ($DryRun) { Say 'dry run complete - nothing changed.' 'Yellow'; exit 0 }
if ($changed -eq 0) { Say 'browser shield already in sync (0 changes).' 'Green' }
else { Say ('browser shield applied ({0} change(s)).' -f $changed) 'Green' }
exit 0
