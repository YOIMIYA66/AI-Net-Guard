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

$physIps = @()
try {
    $physIps = @(Get-NetIPAddress -InterfaceAlias $physNames -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -and $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
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
    $tunIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -and ($knownTun -contains $_.InterfaceAlias) } |
        Select-Object -ExpandProperty IPAddress -Unique)
}
catch { }
try {
    foreach ($pa in @(Get-NetIPAddress -InterfaceAlias $physNames -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -and $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' })) {
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

Say ' '
Say ('physical NICs : ' + ($physNames -join ', ')) 'Cyan'
Say ('physical IPv4 : ' + $(if ($physIps.Count) { $physIps -join ', ' } else { '(none)' })) 'Cyan'
Say ('LocalIP scope : ' + $(if ($physCidrs.Count) { $physCidrs -join ', ' } else { '(none)' })) 'Cyan'
Say ('browsers      : ' + $(if ($targets.Count) { ($targets | ForEach-Object { $_.Tag }) -join ', ' } else { '(none found)' })) 'Cyan'

# ---------------------------------------------------------------- helpers
function Get-RuleInterfaceList([string]$Name) {
    $r = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
    if (-not $r) { return $null }
    @(($r | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue).InterfaceAlias |
        Where-Object { $_ -and $_ -ne 'Any' -and $_ -ne '0' })
}

function Get-RuleLocalAddressList([string]$Name) {
    $r = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
    if (-not $r) { return $null }
    @(($r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue).LocalAddress |
        Where-Object { $_ -and $_ -ne 'Any' })
}

$stockIfRules = @('AI-Guard-Block-WebRTC-UDP', 'AI-Guard-Block-WebRTC-TCP')
$stockIpRules = @('AI-Guard-Block-WebRTC-LocalIP-UDP', 'AI-Guard-Block-WebRTC-LocalIP-TCP')
$shieldRules = @($targets | ForEach-Object { 'AI-Guard-Block-WebRTC-' + $_.Tag + '-PhysUDP' })

# ---------------------------------------------------------------- verify
if ($Verify) {
    Say ' '
    Say '=== browser shield state ===' 'Cyan'
    foreach ($n in $shieldRules) {
        $r = Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue
        if (-not $r) { Say ('  {0,-46} MISSING' -f $n) 'Red'; continue }
        $ifs = @(Get-RuleInterfaceList $n)
        $ifText = $ifs -join ','
        $ap = ($r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program
        # language independent check: the rule must target at least one live physical NIC
        # (adapter aliases differ per OS language, e.g. WLAN / Ethernet / a localized name)
        $ifOk = (@($physNames | Where-Object { $ifs -contains $_ }).Count -gt 0)
        $ok = ($r.Enabled -eq 'True') -and ($r.Action -eq 'Block') -and $ifOk
        Say ('  {0,-46} {1} enabled={2} if={3} prog={4}' -f $n, $(if ($ok) { 'OK  ' } else { 'DRIFT' }), $r.Enabled, $ifText, (Split-Path -Leaf $ap)) $(if ($ok) { 'Green' } else { 'Yellow' })
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
    foreach ($n in $shieldRules) {
        if (Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue) {
            Remove-NetFirewallRule -Name $n -ErrorAction SilentlyContinue
            Say ('  removed ' + $n) 'Yellow'
        }
    }
    # put the two stock LocalAddress rules back on their original exact-IP (/32) behaviour
    if ($physIps.Count -gt 0) {
        foreach ($n in $stockIpRules) {
            if (Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue) {
                Set-NetFirewallRule -Name $n -LocalAddress $physIps -Enabled True -ErrorAction SilentlyContinue
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
    $exists = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
    if ($DryRun) {
        Say ('  [dry] {0} -> {1}' -f $name, $t.Exe) 'DarkGray'
        continue
    }
    if ($exists) {
        $cur = Get-RuleInterfaceList $name
        $missing = @($physNames | Where-Object { $cur -notcontains $_ })
        if ($missing.Count -gt 0 -or $exists.Enabled -ne 'True' -or $exists.Action -ne 'Block') {
            Set-NetFirewallRule -Name $name -InterfaceAlias $physNames -Enabled True -Action Block -ErrorAction Stop
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
        else { Set-NetFirewallRule -Name $n -InterfaceAlias $physNames -ErrorAction Stop; Say ('  updated {0} (if: {1})' -f $n, ($physNames -join ',')) 'Green'; $changed++ }
    }
}

# The two LocalAddress rules carry the physical-NIC scope that survives a DHCP renumber.
# Compare as sets (not "is the new IP missing"), so a lease left over from an old subnet is
# pruned instead of lingering forever on a rule that looks healthy.
$webrtcPorts = @('3478', '3479', '5349', '5350', '19302', '19303', '19304', '19305', '19306', '19307', '19308', '19309')
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
        Say ('  created {0} (la: {1})' -f $n, ($expSet -join ',')) 'Green'
    }
    else {
        Set-NetFirewallRule -Name $n -LocalAddress $expSet -Enabled True -ErrorAction Stop
        Say ('  updated {0} (la: {1})' -f $n, ($expSet -join ',')) 'Green'
    }
    $changed++
}

Say ' '
if ($DryRun) { Say 'dry run complete - nothing changed.' 'Yellow'; exit 0 }
if ($changed -eq 0) { Say 'browser shield already in sync (0 changes).' 'Green' }
else { Say ('browser shield applied ({0} change(s)).' -f $changed) 'Green' }
exit 0
