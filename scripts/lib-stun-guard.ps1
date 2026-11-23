# AI-Net-Guard - shared STUN/TURN guard validation (pure ASCII)
#
# One implementation, dot-sourced by both 18-route-stun-guard.ps1 and
# verify-leak-test.ps1. Two copies of this logic is how the two scripts end up telling
# different stories about the same file: 18 said "SHADOWED" while the acceptance test
# said "PASS", and the operator has no way to tell which one to believe.
#
# Two questions are answered here, and they are different questions:
#
#   1. Is a rule shaped like a B1 guard rule at all?  (Test-StunPortBlockRule)
#      B1 means PORT ONLY, EVERY HOST. A rule that also carries domain / ip / process /
#      inboundTag still blocks something, but it blocks a subset, so it is NOT the guard
#      and must not be reported as one.
#
#   2. Can a rule placed BEFORE the guard pair swallow the STUN traffic? (Get-StunRuleVerdict)
#      "Has a constraining field" is not the answer. A rule scoped to inboundTag=["tun"]
#      matches exactly the traffic the guard is supposed to drop. Each rule is therefore
#      evaluated against the actual shape of a STUN probe: an IP destination, one of the
#      twelve ports, over udp or tcp, arriving through the TUN inbound.

# ---------------------------------------------------------------- the port set
#
# THE list. Twelve ports, four protocols worth of ways to leak, one definition.
#
# It used to be copy-pasted into seven places: 02-killswitch, 07-mode (twice),
# 14-apply-policy, 15-webrtc-browser-shield (twice), 18-route-stun-guard and
# verify-leak-test. Every copy is a place where "the guard covers twelve ports" quietly
# stops being true: add a port to the firewall rule and not to the routing rule and the
# host blocks 13 ports at WFP while the core drops 12, with both halves reporting healthy.
# The acceptance test would then report the mismatch as a config problem instead of a code
# one.
#
# Consumers dot-source this file and call one of the three getters below. There is no
# fallback literal: a script that cannot find this file must refuse to run, because a rule
# built from an empty port list blocks nothing while still showing Enabled=True.
$script:StunGuardPorts = @(
    3478, 3479,                                                  # STUN / TURN
    5349, 5350,                                                  # TURN over TLS / TCP
    19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309       # Google STUN pool
)

function Get-StunGuardPorts {
    # int[] - what the analysis in this file compares against. Returned unrolled (the
    # pipeline re-collects it), so @(Get-StunGuardPorts) and a bare assignment both give
    # the same 12-element array.
    return $script:StunGuardPorts
}

function Get-StunGuardPortStrings {
    # string[] - New-NetFirewallRule -RemotePort accepts this form directly, and 02/07/14/15
    # have passed strings to it since the first version, so the type is kept identical.
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($p in $script:StunGuardPorts) { $out.Add([string]$p) }
    return $out.ToArray()
}

function Get-StunGuardPortSpec {
    # '3478,3479,...' - the wire form 18 writes into the routing rule and shows on screen.
    return ($script:StunGuardPorts -join ',')
}

# Keys that narrow a rule so it no longer matches every host/port. 'type' is added by
# v2rayN when it generates config.json and carries no matching semantics of its own.
$script:StunNarrowingKeys = @(
    'domain', 'ip', 'process', 'inboundTag', 'protocol',
    'sourcePort', 'user', 'source', 'localIP', 'localPort', 'attrs'
)

function Get-StunPortSet {
    param([string]$Spec)
    $set = New-Object 'System.Collections.Generic.HashSet[int]'
    if (-not $Spec) { return , $set }
    foreach ($tok in ($Spec -split ',')) {
        $t = $tok.Trim()
        if (-not $t) { continue }
        if ($t -match '^(\d+)\s*-\s*(\d+)$') {
            $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
            if ($hi -lt $lo) { $swap = $lo; $lo = $hi; $hi = $swap }
            for ($x = $lo; $x -le $hi; $x++) { [void]$set.Add($x) }
        }
        elseif ($t -match '^\d+$') { [void]$set.Add([int]$t) }
    }
    return , $set
}

function Test-StunPortBlockRule {
    param($Rule, [string]$Network, [int[]]$Expected)
    if (-not $Rule) { return $false }
    if ([string]$Rule.outboundTag -ne 'block') { return $false }
    if ([string]$Rule.network -ne $Network) { return $false }
    if ($Rule.PSObject.Properties.Name -contains 'enabled' -and $Rule.enabled -ne $true) { return $false }
    # A rule with any narrowing key is not B1, however many ports it lists.
    foreach ($k in $script:StunNarrowingKeys) {
        if ($Rule.PSObject.Properties.Name -contains $k) { return $false }
    }
    $got = Get-StunPortSet ([string]$Rule.port)
    if ($got.Count -ne $Expected.Count) { return $false }
    foreach ($p in $Expected) { if (-not $got.Contains($p)) { return $false } }
    return $true
}

function Get-TunInboundTags {
    # STUN probes leave through the TUN inbound, so a rule scoped to any other inbound
    # cannot match them. This is the only inboundTag verdict that can be proven, and it
    # depends on reading the actual tag names rather than assuming "tun-in".
    param($Config)
    $tags = New-Object System.Collections.ArrayList
    foreach ($inb in @($Config.inbounds)) {
        if (-not $inb) { continue }
        if ([string]$inb.protocol -eq 'tun' -and $inb.tag) { [void]$tags.Add([string]$inb.tag) }
    }
    return , @($tags)
}

function Get-StunRuleVerdict {
    # Returns Kind = excluded | restricted | matches, plus a human reason.
    #   excluded   - cannot match a STUN probe under any circumstances (proven)
    #   restricted - matches only a subset (one process, one inbound, one source net);
    #                reported as a caveat, never silently dropped
    #   matches    - can match an arbitrary STUN probe, so it can hide the guard pair
    param($Rule, [string[]]$TunTags, [int[]]$Expected)

    $res = [pscustomobject]@{ Kind = 'matches'; Why = 'no constraining field - matches every destination' }

    # A STUN probe targets an IP literal: the client resolves the hostname itself and sends
    # the datagram to that address, so the core never sees a domain here and a domain rule
    # cannot fire. This holds regardless of domainStrategy - nothing turns an IP back into
    # a domain.
    if ($Rule.PSObject.Properties.Name -contains 'domain') {
        $res.Kind = 'excluded'
        $res.Why = 'domain rule - the destination is an IP literal, so it cannot match'
        return $res
    }

    # Port is a required match in Xray: a rule listing other ports cannot fire on ours.
    if ($Rule.PSObject.Properties.Name -contains 'port') {
        $got = Get-StunPortSet ([string]$Rule.port)
        $hit = @($Expected | Where-Object { $got.Contains($_) })
        if ($hit.Count -eq 0) {
            $res.Kind = 'excluded'
            $res.Why = 'port list excludes every STUN/TURN port'
            return $res
        }
    }

    if ($Rule.PSObject.Properties.Name -contains 'network') {
        $nets = @(([string]$Rule.network) -split ',' | ForEach-Object { $_.Trim() })
        if (-not ($nets -contains 'udp') -and -not ($nets -contains 'tcp')) {
            $res.Kind = 'excluded'
            $res.Why = 'network excludes udp and tcp'
            return $res
        }
    }

    # inboundTag: only provable when the tag list does not contain the TUN inbound.
    if ($Rule.PSObject.Properties.Name -contains 'inboundTag') {
        $tags = @($Rule.inboundTag | ForEach-Object { [string]$_ })
        $common = @($tags | Where-Object { $TunTags -contains $_ })
        if ($common.Count -eq 0) {
            $res.Kind = 'excluded'
            $res.Why = 'inboundTag ' + ($tags -join '|') + ' is not the TUN inbound (' + ($TunTags -join '|') + ')'
            return $res
        }
        if ($Expected.Count -gt 0) {
            $res.Kind = 'matches'
            $res.Why = 'inboundTag includes the TUN inbound, so it matches STUN traffic'
            return $res
        }
    }

    # ip cannot be disproven cheaply: geoip:cn really does contain the mainland STUN hosts,
    # so a preceding direct rule pinned to it would swallow them.
    if ($Rule.PSObject.Properties.Name -contains 'ip') {
        $res.Kind = 'matches'
        $res.Why = 'ip rule may contain the STUN destinations'
        return $res
    }

    # Process / user / source narrowing: the rule fires only for some origins. It cannot
    # swallow STUN from an arbitrary application, but it is also not harmless - traffic
    # from that origin bypasses the guard, so it is surfaced rather than filtered out.
    foreach ($k in @('process', 'user', 'source', 'sourcePort', 'localIP', 'localPort')) {
        if ($Rule.PSObject.Properties.Name -contains $k) {
            $res.Kind = 'restricted'
            $res.Why = 'scoped by ' + $k + ' (' + ((@($Rule.$k) | ForEach-Object { [string]$_ }) -join '|') + ')'
            return $res
        }
    }

    return $res
}

function Get-StunGuardAnalysis {
    # Locate the guard pair in the config the core actually loaded and decide whether
    # anything ahead of it can hide it.
    param([string]$ConfigPath, [int[]]$Expected)

    $res = [pscustomobject]@{
        State = 'no-config'; Index = -1; Preceding = 0; Shadow = 0; Caveat = 0
        ShadowRules = @(); CaveatRules = @(); Detail = ''; Config = ''; TunTags = @()
    }
    if (-not $ConfigPath -or -not (Test-Path -LiteralPath $ConfigPath)) { return $res }
    $res.Config = $ConfigPath
    try { $cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { $res.State = 'unparsable'; $res.Detail = $_.Exception.Message; return $res }

    $res.TunTags = Get-TunInboundTags $cfg
    $rules = @($cfg.routing.rules | Where-Object { $_ })

    # The pair must be ADJACENT and in this order: udp then tcp, each carrying the complete
    # port set. Xray routing is first-match, so "somewhere in the table" is not enough.
    $pairAt = -1
    for ($i = 0; $i -lt $rules.Count - 1; $i++) {
        if ((Test-StunPortBlockRule $rules[$i] 'udp' $Expected) -and
            (Test-StunPortBlockRule $rules[$i + 1] 'tcp' $Expected)) { $pairAt = $i; break }
    }

    if ($pairAt -lt 0) {
        # Diagnose a half-written table instead of reporting "absent" for both cases.
        for ($i = 0; $i -lt $rules.Count; $i++) {
            $r = $rules[$i]
            if ([string]$r.outboundTag -ne 'block') { continue }
            if (([string]$r.port) -notmatch '(^|,)3478(,|$)') { continue }
            $got = Get-StunPortSet ([string]$r.port)
            $missing = @($Expected | Where-Object { -not $got.Contains($_) })
            $res.State = 'partial'
            $res.Index = $i
            $res.Detail = 'rule #' + $i + ' net=' + $r.network + ' carries ' + $got.Count + '/' + $Expected.Count + ' ports'
            if ($missing.Count -gt 0) { $res.Detail += ', missing ' + (($missing | Select-Object -First 6) -join ',') }
            foreach ($k in $script:StunNarrowingKeys) {
                if ($r.PSObject.Properties.Name -contains $k) { $res.Detail += ', also narrowed by ' + $k }
            }
            return $res
        }
        $res.State = 'absent'
        return $res
    }

    $res.State = 'present'
    $res.Index = $pairAt
    if ($pairAt -gt 0) {
        $before = @(0..($pairAt - 1) | ForEach-Object { $rules[$_] } |
            Where-Object { [string]$_.outboundTag -ne 'block' })
        $res.Preceding = $before.Count
        foreach ($r in $before) {
            $v = Get-StunRuleVerdict $r $res.TunTags $Expected
            if ($v.Kind -eq 'matches') {
                $res.Shadow++
                $res.ShadowRules += ('out=' + ([string]$r.outboundTag) + ' : ' + $v.Why)
            }
            elseif ($v.Kind -eq 'restricted') {
                $res.Caveat++
                $res.CaveatRules += ('out=' + ([string]$r.outboundTag) + ' : ' + $v.Why)
            }
        }
    }
    return $res
}
