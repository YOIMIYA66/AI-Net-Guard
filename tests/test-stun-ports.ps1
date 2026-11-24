<#
.SYNOPSIS
    AI-Net-Guard regression gate: the STUN/TURN port set has exactly one definition.

.DESCRIPTION
    The twelve-port STUN/TURN list used to be copy-pasted into seven places:
    02-killswitch, 07-mode (twice), 14-apply-policy, 15-webrtc-browser-shield (twice),
    18-route-stun-guard and verify-leak-test. Each copy is a chance for the firewall
    rule and the routing rule to drift apart while both report healthy, and the drift
    is invisible: the acceptance test would blame the config, not the code.

    The list now lives ONLY in scripts\lib-stun-guard.ps1, and every consumer reads it
    from there. This test makes sure it stays that way:

      1. the lib defines exactly the twelve canonical ports;
      2. all three getters (int[], string[], '3478,3479,...') agree;
      3. no executable (non-comment) line in any other script under scripts\ contains
         the first two ports back to back - the signature of a local copy;
      4. every consumer that calls a lib getter also dot-sources the lib;
      5. rollback clears the B1 verdict cache;
      6. a rule narrowed by inboundTag AND process is reported as 'restricted' (a scoped
         caveat), never as a full 'matches' shadow;
      7. the B1 verdict cache is UTF-8 without BOM on BOTH read and write;
      8. the uninstaller tells the operator to restore the core routing table;
      9. the regression suite actually checks B1 and the GUI no longer hard-codes a
         check count that goes stale the moment a new check is added;
     10. a skipped regression check is counted as SKIP, never as a PASS;
     11. a protocol-scoped preceding rule is a caveat, never a false SHADOWED;
     12. an ip rule narrowed by process / protocol is a caveat, while ip alone is still
         a full shadow (the ip branch must not return before the narrowing loop);
     13. an attrs-scoped rule agrees with StunNarrowingKeys and is a caveat;
     14. the GUI captures SKIP=n, shows a warning tone for skipped checks, and never
         claims an absolute zero-leak clean bill of health;
     15. sing-box route.rules schema B1 detection (udp+tcp pair, combined rule, ip_cidr shadow, inbound/process narrowing);
     16. /32 host route persistence prevention (ActiveStore only, no configTest*.json scanning, node-routes.meta rollback cleanup, UTF-8 no-BOM rollback log);
     17. IPv6 physical-NIC explicit block (AI-Guard-Block-Foreign-Physical-IPv6 with 2000::/3, authorized in 07-mode);
     18. 14-apply-policy.ps1 has no misplaced DiagTrack block and removes/disables 15-webrtc-browser-shield rules when BlockWebRtcLeak is off;
     19. 07-mode.ps1 -Status distinguishes non-elevated ReadOnlyStatusMode for SYSTEM tasks.

    Exit code 0 when every assertion passes, 1 otherwise. Run by gui\build.ps1 so a
    local copy can never reach a release.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tests\test-stun-ports.ps1

.NOTES
    Pure ASCII. No network, no firewall, no filesystem writes.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

. (Join-Path $repo 'scripts\lib-stun-guard.ps1')
. (Join-Path $repo 'scripts\lib-guard-common.ps1')

$script:fail = 0
function Assert-True([string]$Name, [bool]$Ok, [string]$Why = '') {
    if ($Ok) {
        Write-Host ('  [PASS] ' + $Name) -ForegroundColor Green
    }
    else {
        $detail = if ($Why) { ' - ' + $Why } else { '' }
        Write-Host ('  [FAIL] ' + $Name + $detail) -ForegroundColor Red
        $script:fail++
    }
}

Write-Host '=== STUN/TURN port-set regression gate ===' -ForegroundColor Cyan

# ---------------------------------------------------------------- 1. the canonical set
$expected = @(3478, 3479, 5349, 5350, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309)
$got = @(Get-StunGuardPorts)
Assert-True 'lib defines exactly the twelve canonical ports' `
    (($got.Count -eq 12) -and (@($got | Where-Object { $expected -contains $_ }).Count -eq 12)) `
    ('got ' + ($got -join ','))

# ---------------------------------------------------------------- 2. the getters agree
$spec = Get-StunGuardPortSpec
Assert-True 'port-spec getter round-trips to the same twelve ports' `
    (@($spec.Split(',') | Where-Object { $_ }).Count -eq 12 -and $spec -eq ($expected -join ',')) `
    ('spec is "' + $spec + '"')
$strs = @(Get-StunGuardPortStrings)
Assert-True 'string getter is the string form of the same set' `
    (($strs.Count -eq 12) -and (($strs -join ',') -eq ($expected -join ','))) `
    ('got ' + ($strs -join ','))

# ---------------------------------------------------------------- 3. no local copy survives
# The first two ports adjacent is the fingerprint of a copy: nobody builds a STUN rule
# from 3478 alone. Comment lines are excluded, prose is allowed to mention the ports.
$badCopies = @()
foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $repo 'scripts') -Filter '*.ps1' -File)) {
    if ($f.Name -eq 'lib-stun-guard.ps1') { continue }
    foreach ($ln in @(Get-Content -LiteralPath $f.FullName)) {
        $t = $ln.TrimStart()
        if ($t.StartsWith('#')) { continue }
        if ($ln -match "3478['`" ]*[,\s]\s*['`" ]*3479") {
            $badCopies += ($f.Name + ' : ' + $t)
            break
        }
    }
}
Assert-True 'no other script keeps a local copy of the port list' ($badCopies.Count -eq 0) ($badCopies -join ' | ')

# ---------------------------------------------------------------- 4. consumers load the lib FIRST
# Existence is not enough: a dot-source at the bottom of a file still satisfies a regex,
# while every getter call above it would run against an empty function table. Compare
# line numbers so the gate actually enforces the ordering it claims to enforce.
$consumers = @(
    '02-killswitch.ps1', '07-mode.ps1', '12-regression.ps1', '14-apply-policy.ps1',
    '15-webrtc-browser-shield.ps1', '18-route-stun-guard.ps1', 'verify-leak-test.ps1'
)
foreach ($c in $consumers) {
    $p = Join-Path (Join-Path $repo 'scripts') $c
    if (-not (Test-Path -LiteralPath $p)) {
        Assert-True ($c + ' exists') $false 'file not found'
        continue
    }
    $lines = @(Get-Content -LiteralPath $p)
    $srcLine = -1
    $getLine = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $t = $lines[$i].TrimStart()
        if ($t.StartsWith('#')) { continue }
        if ($srcLine -lt 0 -and $t -match '^\.\s+\$lib(Stun|Path)\b') { $srcLine = $i }
        if ($getLine -lt 0 -and $t -match 'Get-StunGuard(PortStrings|Ports|PortSpec|Analysis)') { $getLine = $i }
    }
    Assert-True ($c + ' dot-sources the lib before its first getter call') `
        ($srcLine -ge 0 -and $getLine -ge 0 -and $srcLine -lt $getLine) `
        ('dot-source line ' + ($srcLine + 1) + ', first getter line ' + ($getLine + 1))
}

# ---------------------------------------------------------------- 5. new runtime metadata is rollback-safe
# 07-mode writes backup\b1-guard.meta as a verdict cache. A metadata file the rollback
# script does not delete survives an uninstall and can later be read back as a stale
# 'present' verdict, so the cleanup list belongs in this gate.
$rollback = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'scripts') '09-rollback.ps1') -Raw
Assert-True '09-rollback.ps1 clears the B1 verdict cache' ($rollback -match "'b1-guard\.meta'")

# ---------------------------------------------------------------- 6. origin-scoped rules are caveats, not shadows
# An inboundTag matching the TUN inbound only proves the rule was NOT excluded. The old
# early 'return matches' skipped the process/user/source checks below and turned a rule
# scoped to a single process into a false SHADOWED alarm. Lock all three shapes.
$tunTags = @('tun-in', 'tun')
$scoped = [pscustomobject]@{ inboundTag = @('tun-in'); process = @('curl.exe') }
$v1 = Get-StunRuleVerdict $scoped $tunTags $expected
Assert-True 'inboundTag + process rule is restricted, not a full shadow' `
    ($v1.Kind -eq 'restricted') ('got ' + $v1.Kind + ' : ' + $v1.Why)
$plain = [pscustomobject]@{ inboundTag = @('tun-in') }
$v2 = Get-StunRuleVerdict $plain $tunTags $expected
Assert-True 'inboundTag-only rule still matches STUN traffic' `
    ($v2.Kind -eq 'matches') ('got ' + $v2.Kind + ' : ' + $v2.Why)
$otherIn = [pscustomobject]@{ inboundTag = @('socks-in') }
$v3 = Get-StunRuleVerdict $otherIn $tunTags $expected
Assert-True 'non-TUN inboundTag rule is excluded' `
    ($v3.Kind -eq 'excluded') ('got ' + $v3.Kind)

# ---------------------------------------------------------------- 7. B1 verdict cache codec
# -Encoding ASCII flattened localised Detail to '?'. Set-Content -Encoding UTF8 on PS 5.1
# writes a BOM that breaks the StartsWith(stamp) fast path forever, so the only safe form
# is the explicit no-BOM API paired with a UTF-8 read (same as lib-foreign-block.ps1).
$mode = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'scripts') '07-mode.ps1') -Raw
$writeOk = $mode -match 'WriteAllText\(\$b1Meta, \$line, \(New-Object System\.Text\.UTF8Encoding\(\$false\)\)\)'
$readOk = $mode -match 'ReadAllText\(\$b1Meta, \[System\.Text\.Encoding\]::UTF8\)'
$noAscii = $mode -notmatch 'Set-Content -LiteralPath \$b1Meta'
Assert-True '07-mode B1 cache is UTF-8 without BOM on read and write' `
    ($writeOk -and $readOk -and $noAscii) `
    ('write=' + $writeOk + ' read=' + $readOk + ' noAsciiWrite=' + $noAscii)

# ---------------------------------------------------------------- 8. uninstaller closes the loop
# It cannot rewrite guiNDB.db safely (v2rayN may be up), but it must not claim a fully
# clean uninstall while the B1 rules are still live in the core routing table.
Assert-True '09-rollback.ps1 points at 18 -Restore for the core routing table' `
    ($rollback -match '18-route-stun-guard\.ps1 -Restore')

# ---------------------------------------------------------------- 9. B1 is visible in the GUI regression path
$reg = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'scripts') '12-regression.ps1') -Raw
Assert-True '12-regression.ps1 checks B1 through the shared analysis' `
    (($reg -match "Check 'B1 STUN route guard") -and ($reg -match 'Get-StunGuardAnalysis'))
# Read as UTF-8 so checks against CJK UI strings compare real characters instead of
# mojibake: PowerShell 5.1 defaults to the ANSI code page for BOM-less files.
$gui = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'gui') 'MainWindow.xaml.cs') -Raw -Encoding UTF8
$xaml = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'gui') 'MainWindow.xaml') -Raw
$loc = Get-Content -LiteralPath (Join-Path (Join-Path (Join-Path $repo 'gui') 'Services') 'LocalizationService.cs') -Raw
$rd = Get-Content -LiteralPath (Join-Path $repo 'README.md') -Raw
$rde = Get-Content -LiteralPath (Join-Path $repo 'README_EN.md') -Raw
# The check count is dynamic (loop-generated checks), so no UI string may hard-code it.
# Cover EVERY surface that once displayed '24': code-behind, XAML, both locale
# dictionaries and both READMEs. A stale number can creep back through any one of them.
$noCount = '24/24|24-check|All 24 |Full Regression \(24\)|24\s*\u9879'
Assert-True 'GUI and docs no longer hard-code a regression check count' `
    (($gui -notmatch $noCount) -and ($xaml -notmatch $noCount) -and ($loc -notmatch $noCount) -and ($rd -notmatch $noCount) -and ($rde -notmatch $noCount))

# ---------------------------------------------------------------- 10. a SKIP is not a PASS
# 12-regression.ps1 used to count every string-returning Check as a PASS, so a B1 check
# that returned 'SKIP - core config not generated' still produced a green [PASS] line and
# a FAIL=0 banner. It must now keep a separate SKIP counter and print [SKIP] instead.
Assert-True '12-regression.ps1 counts SKIP separately instead of as a PASS' `
    (($reg -match '\$script:skip\+\+') -and ($reg -match "StartsWith\('SKIP'\)") -and ($reg -match '\[SKIP\]')) `
    'SKIP counter / opt-out branch / grey [SKIP] line must all be present'

# ---------------------------------------------------------------- 11. protocol is a caveat, not a shadow
# Xray routing rules may carry a sniffing-result 'protocol' field. A STUN datagram is not
# http/tls/bittorrent, but sniffing outcomes cannot be proven from config.json, so such a
# rule must be surfaced as 'restricted' rather than reported as a full SHADOWED.
$proto = [pscustomobject]@{ inboundTag = @('tun-in'); protocol = @('bittorrent') }
$v4 = Get-StunRuleVerdict $proto $tunTags $expected
Assert-True 'protocol-scoped rule is restricted, not a full shadow' `
    ($v4.Kind -eq 'restricted') ('got ' + $v4.Kind + ' : ' + $v4.Why)

# ---------------------------------------------------------------- 12. ip + narrowing is still a caveat
# The ip branch used to 'return matches' BEFORE the narrowing loop, so a preceding rule
# pinned to both geoip:cn and one process was reported as a full SHADOWED. ip alone must
# stay a full shadow; ip + process / ip + protocol must become a scoped caveat.
$ipOnly  = [pscustomobject]@{ ip = @('geoip:cn') }
$ipProc  = [pscustomobject]@{ ip = @('geoip:cn'); process = @('curl.exe') }
$ipProto = [pscustomobject]@{ ip = @('geoip:cn'); protocol = @('bittorrent') }
$v5 = Get-StunRuleVerdict $ipOnly  $tunTags $expected
$v6 = Get-StunRuleVerdict $ipProc  $tunTags $expected
$v7 = Get-StunRuleVerdict $ipProto $tunTags $expected
Assert-True 'ip alone is a shadow, but ip + narrowing field is a caveat' `
    (($v5.Kind -eq 'matches') -and ($v6.Kind -eq 'restricted') -and ($v7.Kind -eq 'restricted')) `
    ('got ip=' + $v5.Kind + ' ip+process=' + $v6.Kind + ' ip+protocol=' + $v7.Kind)

# ---------------------------------------------------------------- 13. attrs is a narrowing key
# StunNarrowingKeys already lists 'attrs', so a rule carrying it can never be a B1 guard
# rule. The verdict must agree: an attrs-scoped preceding rule is a caveat, not a shadow.
$attrsRule = [pscustomobject]@{ attrs = @{ ':method' = 'GET' } }
$v8 = Get-StunRuleVerdict $attrsRule $tunTags $expected
Assert-True 'attrs-scoped rule is restricted, consistent with StunNarrowingKeys' `
    ($v8.Kind -eq 'restricted') ('got ' + $v8.Kind + ' : ' + $v8.Why)

# ---------------------------------------------------------------- 14. GUI honours SKIP, avoids absolute claims
# 12-regression.ps1 may exit 0 with skipped checks. The GUI used to treat exit 0 as an
# unconditional "all checks passed / zero leak" success. It must capture SKIP=n, use a
# warning tone when checks were skipped, and drop the absolute zero-leak wording that
# contradicts the PASSED WITH CAVEAT acceptance verdict.
$absZeroLeak = -join ([char[]]@(0x96F6, 0x6CC4, 0x6F0F, 0x5065, 0x5EB7))
Assert-True 'GUI captures SKIP and no longer claims an absolute zero-leak result' `
    (($gui.Contains('SKIP=(\d+)')) -and ($gui.Contains('[SKIP]')) -and `
     ($gui.Contains('StatusTone.Warning')) -and ($gui.Contains('Incomplete verification')) -and `
     (-not $gui.Contains('Regression PASS (FAIL=0)')) -and (-not $gui.Contains($absZeroLeak))) `
    'SKIP capture, warning tone and no absolute zero-leak wording are all required'

# ---------------------------------------------------------------- 15. sing-box B1 analysis
$sbCfgPair = [pscustomobject]@{
    inbounds = @([pscustomobject]@{ tag = 'tun-in'; type = 'tun' })
    route    = [pscustomobject]@{
        rules = @(
            [pscustomobject]@{ action = 'sniff' },
            [pscustomobject]@{ domain_suffix = @('example.com'); outbound = 'direct' },
            [pscustomobject]@{ ip_cidr = @('1.2.3.4/32'); process_name = @('curl.exe'); outbound = 'direct' },
            [pscustomobject]@{ action = 'reject'; network = @('udp'); port = @(3478, 3479, 5349, 5350); port_range = @('19302:19309') },
            [pscustomobject]@{ action = 'reject'; network = @('tcp'); port = @(3478, 3479, 5349, 5350); port_range = @('19302:19309') }
        )
    }
}
$aSb1 = Get-StunGuardAnalysisFromObject -Cfg $sbCfgPair -Expected $expected
Assert-True 'sing-box udp+tcp reject pair with sniff/domain/ip+process gives present, shadow=0, caveat=1' `
    (($aSb1.State -eq 'present') -and ($aSb1.Index -eq 3) -and ($aSb1.Shadow -eq 0) -and ($aSb1.Caveat -eq 1)) `
    ('got state=' + $aSb1.State + ' idx=' + $aSb1.Index + ' shadow=' + $aSb1.Shadow + ' caveat=' + $aSb1.Caveat)

$sbCfgSingle = [pscustomobject]@{
    inbounds = @([pscustomobject]@{ tag = 'tun-in'; type = 'tun' })
    route    = [pscustomobject]@{
        rules = @(
            [pscustomobject]@{ action = 'reject'; port = @(3478, 3479, 5349, 5350); port_range = @('19302:19309') }
        )
    }
}
$aSb2 = Get-StunGuardAnalysisFromObject -Cfg $sbCfgSingle -Expected $expected
Assert-True 'sing-box single combined reject rule gives present and shadow=0' `
    (($aSb2.State -eq 'present') -and ($aSb2.Index -eq 0) -and ($aSb2.Shadow -eq 0)) `
    ('got state=' + $aSb2.State + ' shadow=' + $aSb2.Shadow)

$sbCfgShadow = [pscustomobject]@{
    inbounds = @([pscustomobject]@{ tag = 'tun-in'; type = 'tun' })
    route    = [pscustomobject]@{
        rules = @(
            [pscustomobject]@{ ip_cidr = @('192.0.2.0/24'); outbound = 'direct' },
            [pscustomobject]@{ action = 'reject'; port = @(3478, 3479, 5349, 5350); port_range = @('19302:19309') }
        )
    }
}
$aSb3 = Get-StunGuardAnalysisFromObject -Cfg $sbCfgShadow -Expected $expected
Assert-True 'sing-box ip_cidr-only preceding rule flags shadow=1' `
    (($aSb3.State -eq 'present') -and ($aSb3.Shadow -eq 1)) `
    ('got state=' + $aSb3.State + ' shadow=' + $aSb3.Shadow)

$vSbExcl = Get-SingBoxStunRuleVerdict ([pscustomobject]@{ inbound = @('socks-in') }) $tunTags $expected
$vSbRestr = Get-SingBoxStunRuleVerdict ([pscustomobject]@{ inbound = @('tun-in'); process_name = @('curl.exe') }) $tunTags $expected
Assert-True 'sing-box non-TUN inbound is excluded and TUN inbound + process_name is restricted' `
    (($vSbExcl.Kind -eq 'excluded') -and ($vSbRestr.Kind -eq 'restricted')) `
    ('got excl=' + $vSbExcl.Kind + ' restr=' + $vSbRestr.Kind)

# ---------------------------------------------------------------- 16. route pollution & rollback fixes
$syncNode = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'scripts') '10-sync-node-rule.ps1') -Raw
Assert-True '07-mode and 10-sync-node-rule use ActiveStore only and never scan configTest*.json' `
    (($mode -match '-PolicyStore\s+ActiveStore') -and ($syncNode -match '-PolicyStore\s+ActiveStore') -and `
     ($mode -notmatch "Get-ChildItem[^\r\n]*configTest") -and ($syncNode -notmatch "Get-ChildItem[^\r\n]*configTest")) `
    'ActiveStore flag required on New-NetRoute and no configTest*.json scanning allowed'

Assert-True '09-rollback cleans node-routes.meta and writes log as UTF-8 without BOM' `
    (($rollback -match "'node-routes\.meta'") -and ($rollback -match 'AppendAllText\(\$Log,.*UTF8Encoding\(\$false\)') -and `
     ($rollback -notmatch 'Add-Content -LiteralPath \$Log.*-Encoding ASCII')) `
    'node-routes.meta cleanup and UTF8Encoding($false) log writer required'

# ---------------------------------------------------------------- 17. IPv6 physical block
$libForeign = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'scripts') 'lib-foreign-block.ps1') -Raw
Assert-True 'lib-foreign-block enforces AI-Guard-Block-Foreign-Physical-IPv6 (2000::/3) and 07-mode authorizes it' `
    (($libForeign -match 'AI-Guard-Block-Foreign-Physical-IPv6') -and ($libForeign -match '2000::/3') -and `
     ($mode -match 'Foreign-Physical-IPv6')) `
    'IPv6 physical block rule and 07-mode authorization regex must be present'

# ---------------------------------------------------------------- 18. 14-apply-policy fixes
$applyPol = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'scripts') '14-apply-policy.ps1') -Raw
Assert-True '14-apply-policy removes misplaced DiagTrack block and removes/disables 15-webrtc-browser-shield on OFF' `
    (($applyPol -notmatch 'DiagTrack') -and ($applyPol -match '15-webrtc-browser-shield\.ps1') -and `
     ($applyPol -match '-Remove -Quiet')) `
    'no DiagTrack in 14-apply-policy and WebRTC browser shield must be removed when disabled'

# ---------------------------------------------------------------- 19. 07-mode non-elevated task status
Assert-True '07-mode Show-Status reports inconclusive for SYSTEM tasks when non-elevated' `
    (($mode -match '\$script:ReadOnlyStatusMode') -and ($mode -match 'inconclusive \(non-elevated session cannot enumerate SYSTEM tasks')) `
    'ReadOnlyStatusMode guard required before reporting monitor tasks : none registered'

# ---------------------------------------------------------------- 20. v5.8.8 post-review fixes
$vSbHijack = Get-SingBoxStunRuleVerdict ([pscustomobject]@{ protocol = @('dns'); action = 'hijack-dns' }) $tunTags $expected
$sbCfgLogical = [pscustomobject]@{
    inbounds = @([pscustomobject]@{ tag = 'tun-in'; type = 'tun' })
    route    = [pscustomobject]@{
        rules = @(
            [pscustomobject]@{ type = 'logical'; mode = 'or'; rules = @([pscustomobject]@{ protocol = @('dns') }, [pscustomobject]@{ port = @(53) }); action = 'hijack-dns' },
            [pscustomobject]@{ action = 'reject'; port = @(3478, 3479, 5349, 5350); port_range = @('19302:19309') }
        )
    }
}
$aSbLog = Get-StunGuardAnalysisFromObject -Cfg $sbCfgLogical -Expected $expected
$vSbLogAndExcl = Get-SingBoxStunRuleVerdict ([pscustomobject]@{ type = 'logical'; mode = 'and'; rules = @([pscustomobject]@{ ip_cidr = @('1.1.1.1/32') }, [pscustomobject]@{ port = @(53) }); outbound = 'direct' }) $tunTags $expected
$vSbLogOrMatch = Get-SingBoxStunRuleVerdict ([pscustomobject]@{ type = 'logical'; mode = 'or'; rules = @([pscustomobject]@{ domain = @('example.com') }, [pscustomobject]@{ ip_cidr = @('1.1.1.0/24') }); outbound = 'direct' }) $tunTags $expected
Assert-True 'sing-box hijack-dns and logical rules are classified without false SHADOWED and track RuleCount' `
    (($vSbHijack.Kind -eq 'excluded') -and ($aSbLog.State -eq 'present') -and ($aSbLog.Shadow -eq 0) -and ($aSbLog.Caveat -eq 0) -and ($aSbLog.RuleCount -eq 1) -and ($aSb1.RuleCount -eq 2) -and ($vSbLogAndExcl.Kind -eq 'excluded') -and ($vSbLogOrMatch.Kind -eq 'matches')) `
    ('got hijack=' + $vSbHijack.Kind + ' logShadow=' + $aSbLog.Shadow + ' logRuleCount=' + $aSbLog.RuleCount + ' andExcl=' + $vSbLogAndExcl.Kind + ' orMatch=' + $vSbLogOrMatch.Kind)

Assert-True '07-mode Get-ActiveTunNamesFast & Get-ActivePhysicalNicsFast avoid nested return-comma and call Sync-NodeActiveHostRoutes' `
    (($mode -match 'function Get-ActiveTunNamesFast[\s\S]*?return \$names\.ToArray\(\)') -and `
     ($mode -match 'function Get-ActivePhysicalNicsFast[\s\S]*?return \$list\.ToArray\(\)') -and `
     ($mode -match 'Sync-NodeActiveHostRoutes -NodeIps \$wantIps') -and `
     ($mode -match 'Sync-NodeActiveHostRoutes -NodeIps \$ips') -and `
     ($mode -match 'b1Meta, \$line' -and $mode -match "Detail -replace '\[\\\|\\r\\n\]'")) `
    'flat returns, fast-path /32 route recovery, and pre-cache Detail normalization required'

Assert-True 'IPv6 physical block respects DisablePhysicalIpv6 across lib-foreign-block, 07-mode, 02-killswitch, 10-sync-node-rule, 14-apply-policy' `
    (($libForeign -match '\[bool\]\$BlockPhysicalIpv6 = \$true') -and `
     ($mode -match '\$wantV6Block = \[bool\]\$guardPolicy\.DisablePhysicalIpv6') -and `
     ($syncNode -match 'DisablePhysicalIpv6') -and `
     ($syncNode -match '-BlockPhysicalIpv6') -and `
     ($applyPol -match '-SkipIpv6Block')) `
    'BlockPhysicalIpv6 gating required across all 5 consumers'

Assert-True '09-rollback clears foreign-block.meta and 12-regression enforces SKIP casing and new static checks' `
    (($rollback -match "'foreign-block\.meta'") -and `
     ($reg -notmatch "return 'skipped") -and `
     ($reg -match 'AI-Guard-Block-Foreign-Physical-IPv6') -and `
     ($reg -match 'AI-Guard-Block-PhysicalIP-On-TUN') -and `
     ($reg -match 'PersistentStore')) `
    'rollback cleanup, uppercase SKIP, and static regression checks required'

# ---------------------------------------------------------------- 21. v5.8.8 STUN RFC 5389 parser, WFP 5157 & ActiveStore readback
$req = New-StunBindingRequest
$tx = $req.TransactionId
$ck = [byte[]]@(0x21, 0x12, 0xA4, 0x42)

# Build valid IPv4 XOR-MAPPED-ADDRESS (203.0.113.42)
$rawV4 = [byte[]]@(203, 0, 113, 42)
$pktV4 = New-Object 'byte[]' 32
$pktV4[0] = 0x01; $pktV4[1] = 0x01; $pktV4[3] = 12
[System.Array]::Copy($ck, 0, $pktV4, 4, 4)
[System.Array]::Copy($tx, 0, $pktV4, 8, 12)
$pktV4[20] = 0x00; $pktV4[21] = 0x20; $pktV4[22] = 0x00; $pktV4[23] = 8
$pktV4[25] = 0x01; $pktV4[26] = 0x11; $pktV4[27] = 0x22
for ($i = 0; $i -lt 4; $i++) { $pktV4[28 + $i] = [byte]($rawV4[$i] -bxor $ck[$i]) }
$decV4 = ConvertFrom-StunResponse -Packet $pktV4 -TransactionId $tx

# Build valid IPv6 XOR-MAPPED-ADDRESS (2001:db8::1)
$rawV6 = ([System.Net.IPAddress]::Parse('2001:db8::1')).GetAddressBytes()
$pktV6 = New-Object 'byte[]' 44
$pktV6[0] = 0x01; $pktV6[1] = 0x01; $pktV6[3] = 24
[System.Array]::Copy($ck, 0, $pktV6, 4, 4)
[System.Array]::Copy($tx, 0, $pktV6, 8, 12)
$pktV6[20] = 0x00; $pktV6[21] = 0x20; $pktV6[22] = 0x00; $pktV6[23] = 20
$pktV6[25] = 0x02; $pktV6[26] = 0x11; $pktV6[27] = 0x22
for ($i = 0; $i -lt 16; $i++) {
    $maskB = if ($i -lt 4) { $ck[$i] } else { $tx[$i - 4] }
    $pktV6[28 + $i] = [byte]($rawV6[$i] -bxor $maskB)
}
$decV6 = ConvertFrom-StunResponse -Packet $pktV6 -TransactionId $tx

# Build valid IPv4 MAPPED-ADDRESS (198.51.100.7)
$pktMap = New-Object 'byte[]' 32
$pktMap[0] = 0x01; $pktMap[1] = 0x01; $pktMap[3] = 12
[System.Array]::Copy($ck, 0, $pktMap, 4, 4)
[System.Array]::Copy($tx, 0, $pktMap, 8, 12)
$pktMap[20] = 0x00; $pktMap[21] = 0x01; $pktMap[22] = 0x00; $pktMap[23] = 8
$pktMap[25] = 0x01; $pktMap[28] = 198; $pktMap[29] = 51; $pktMap[30] = 100; $pktMap[31] = 7
$decMap = ConvertFrom-StunResponse -Packet $pktMap -TransactionId $tx

# Mismatched TransactionId, bad Cookie, bad type
$badTx = [byte[]]@(0..11)
$badTx[0] = [byte]($tx[0] -bxor 0xFF)
$decBadTx = ConvertFrom-StunResponse -Packet $pktV4 -TransactionId $badTx
$pktBadCookie = [byte[]]$pktV4.Clone(); $pktBadCookie[4] = 0x00
$decBadCookie = ConvertFrom-StunResponse -Packet $pktBadCookie -TransactionId $tx
$decShort = ConvertFrom-StunResponse -Packet ($pktV4[0..19]) -TransactionId $tx

Assert-True 'strict STUN parser decodes IPv4/IPv6 XOR and rejects mismatched TxID/cookie/truncation' `
    (($req.Packet.Length -eq 20) -and ($decV4 -eq '203.0.113.42') -and ($decV6 -eq '2001:db8::1') -and `
     ($decMap -eq '198.51.100.7') -and ($null -eq $decBadTx) -and ($null -eq $decBadCookie) -and ($null -eq $decShort)) `
    ('v4=' + $decV4 + ' v6=' + $decV6 + ' map=' + $decMap + ' badTx=' + $decBadTx)

$vlt = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'scripts') 'verify-leak-test.ps1') -Raw
Assert-True 'verify-leak-test and 12-regression use strict STUN, WFP 5157 attribution, and ActiveStore readback' `
    (($vlt -match 'New-StunBindingRequest') -and ($vlt -match 'ConvertFrom-StunResponse') -and `
     ($reg -match 'New-StunBindingRequest') -and ($reg -match 'ConvertFrom-StunResponse') -and `
     ($reg -match 'Find-WfpBlockOrigin') -and ($reg -match 'Id = 5157') -and `
     ($reg -match '-PolicyStore ActiveStore')) `
    'strict STUN helpers, Event 5157 origin lookup, and ActiveStore readback required'

# ---------------------------------------------------------------- 22. v5.9.0 security hardening (ACL, Rollback, ExitCode, Fail-Closed Policy, Lock, CIDR, Tasks, GUI)
$tmpSecDir = Join-Path ([System.IO.Path]::GetTempPath()) ('ai-guard-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpSecDir -Force | Out-Null
try {
    $defs = [ordered]@{ AllowCnDirect = $true; AllowLan = $true; StrictNrptDoh = $false; HardenInstallAcl = $true; Preset = 'Recommended' }
    $pFile = Join-Path $tmpSecDir 'guard-policy.json'
    $lgFile = Join-Path $tmpSecDir 'guard-policy.last-good.json'

    # Valid policy reads ok and does NOT prematurely write last-good before apply succeeds
    [System.IO.File]::WriteAllText($pFile, '{"AllowCnDirect":false,"AllowLan":true,"Preset":"StrictLock"}', (New-Object System.Text.UTF8Encoding($false)))
    $pOk = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile
    $okPass = ($pOk.PolicyHealth -eq 'ok') -and (-not $pOk.AllowCnDirect) -and (-not (Test-Path -LiteralPath $lgFile))

    # Explicit Save-GuardPolicyLastGood persists last-good atomically
    Save-GuardPolicyLastGood -PolicyPath $pFile -LastGoodPath $lgFile
    $lgSaved = Test-Path -LiteralPath $lgFile

    # String "false" must NOT coerce to $true - should recover last-good
    [System.IO.File]::WriteAllText($pFile, '{"AllowCnDirect":"false"}', (New-Object System.Text.UTF8Encoding($false)))
    $pRec = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile
    $recPass = ($pRec.PolicyHealth -eq 'recovered-last-good') -and (-not $pRec.AllowCnDirect)

    # Empty {} and explicit null boolean must be rejected (recover last-good / fail closed when last-good corrupt)
    [System.IO.File]::WriteAllText($pFile, '{}', (New-Object System.Text.UTF8Encoding($false)))
    $pEmptyRec = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile
    [System.IO.File]::WriteAllText($lgFile, '{also-broken', (New-Object System.Text.UTF8Encoding($false)))
    $pEmptyFc = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile
    [System.IO.File]::WriteAllText($pFile, '{"AllowCnDirect":null}', (New-Object System.Text.UTF8Encoding($false)))
    $pNullFc = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile
    $strictFieldPass = ($pEmptyRec.PolicyHealth -eq 'recovered-last-good') -and ($pEmptyFc.PolicyHealth -eq 'corrupt-fail-closed') -and ($pNullFc.PolicyHealth -eq 'corrupt-fail-closed') -and (-not $pNullFc.AllowCnDirect)

    # Missing primary on deployed host without last-good -> Fail-Closed; missing with valid last-good -> recovered
    Remove-Item -LiteralPath $pFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $lgFile -Force -ErrorAction SilentlyContinue
    $pMissingDeployed = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile -IsDeployed
    $pMissingFresh = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile
    [System.IO.File]::WriteAllText($lgFile, '{"AllowCnDirect":false,"AllowLan":true,"Preset":"StrictLock"}', (New-Object System.Text.UTF8Encoding($false)))
    $pMissingLg = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile -IsDeployed
    $missingPolicyPass = ($pMissingDeployed.PolicyHealth -eq 'corrupt-fail-closed') -and (-not $pMissingDeployed.AllowCnDirect) -and (-not $pMissingDeployed.AllowLan) -and ($pMissingFresh.PolicyHealth -eq 'default') -and ($pMissingLg.PolicyHealth -eq 'recovered-last-good') -and (-not $pMissingLg.AllowCnDirect)

    Assert-True 'Read-GuardPolicyStrict rejects string/null/empty fields, decouples last-good save, and fails closed when missing on deployed host' `
        ($okPass -and $lgSaved -and $recPass -and $strictFieldPass -and $missingPolicyPass) `
        ('ok=' + $okPass + ' lgSaved=' + $lgSaved + ' rec=' + $recPass + ' strict=' + $strictFieldPass + ' missing=' + $missingPolicyPass)

    # ACL audit rejects user-writable non-drive-root parent folder
    $subInstall = Join-Path $tmpSecDir 'install-sub'
    New-Item -ItemType Directory -Path $subInstall -Force | Out-Null
    $aclParentIssues = @(Get-GuardInstallAclIssues -Path $subInstall)
    Assert-True 'Get-GuardInstallAclIssues flags user-writable non-drive-root parent directory' `
        (@($aclParentIssues | Where-Object { $_ -like 'parent(*):*' }).Count -gt 0) `
        ('issues=' + ($aclParentIssues -join '; '))
}
finally {
    Remove-Item -LiteralPath $tmpSecDir -Recurse -Force -ErrorAction SilentlyContinue
}

$cnSample = @('# comment', '0.0.0.0/0', '1.0.0.0/1', '999.1.1.1/24', '192.168.1.0/24', '127.0.0.0/8', '172.16.0.0/12', '224.0.0.0/4', '1.0.1.5/24', '1.0.1.0/24')
$cnValidated = @(Get-ValidatedCnPrefixes -Lines $cnSample -MinCount 1)
Assert-True 'Get-ValidatedCnPrefixes rejects /0../7, invalid IPs, private/multicast, and normalizes/dedups CIDRs' `
    (($cnValidated.Count -eq 1) -and ($cnValidated[0] -eq '1.0.1.0/24')) `
    ('got count=' + $cnValidated.Count + ' items=' + ($cnValidated -join ','))

# Lock tests: reject Local\, ignore stale owner PID token, enforce Global reentrancy + real 2-process Mutex contention
$localRejected = $false
try {
    $null = Enter-GuardWriteLock -TimeoutMs 100 -LockName 'Local\AI-Net-Guard-UnitTest-Forbidden'
}
catch {
    $localRejected = ($_.Exception.Message -match 'Local lock namespace')
}

$testGlobalLock = 'Global\AI-Net-Guard-UnitTest-' + [guid]::NewGuid().ToString('N')
$env:AI_GUARD_LOCK_TOKEN = '999999|' + $testGlobalLock + '|stale'
$lock1 = Enter-GuardWriteLock -TimeoutMs 5000 -LockName $testGlobalLock
$staleIgnored = ($lock1.Owned -and (-not $lock1.Inherited))
$lockNested = Enter-GuardWriteLock -TimeoutMs 5000 -LockName $testGlobalLock
$tokSet = [bool]$env:AI_GUARD_LOCK_TOKEN
$nestedInherits = [bool]($lock1.Owned -and $lockNested.Inherited -and (-not $lockNested.Owned))
Exit-GuardWriteLock $lockNested
$tokStillSet = [bool]$env:AI_GUARD_LOCK_TOKEN
Exit-GuardWriteLock $lock1
$tokCleared = -not [bool]$env:AI_GUARD_LOCK_TOKEN
Assert-True 'Enter-GuardWriteLock rejects Local namespace, ignores stale tokens, and enforces Global reentrancy' `
    ($localRejected -and $staleIgnored -and $tokSet -and $nestedInherits -and $tokStillSet -and $tokCleared) `
    ('localRej=' + $localRejected + ' staleIgn=' + $staleIgnored + ' nested=' + $nestedInherits + ' cleared=' + $tokCleared)

# Real 2-process Global Mutex contention check
$procTestLock = 'Global\AI-Net-Guard-ProcContention-' + [guid]::NewGuid().ToString('N')
$readyFlag = Join-Path ([System.IO.Path]::GetTempPath()) ('ai-guard-lock-ready-' + [guid]::NewGuid().ToString('N') + '.tmp')
$libCommonPath = Join-Path (Join-Path $repo 'scripts') 'lib-guard-common.ps1'
$childCode = @"
. '$($libCommonPath.Replace("'", "''"))'
`$h = Enter-GuardWriteLock -TimeoutMs 5000 -LockName '$procTestLock'
[System.IO.File]::WriteAllText('$($readyFlag.Replace("'", "''"))', 'held')
Start-Sleep -Milliseconds 2000
Exit-GuardWriteLock `$h
"@
$childB64 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($childCode))
$psiLock = New-Object System.Diagnostics.ProcessStartInfo
$psiLock.FileName = 'powershell.exe'
$psiLock.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $childB64
$psiLock.UseShellExecute = $false
$psiLock.CreateNoWindow = $true
$childProc = [System.Diagnostics.Process]::Start($psiLock)
$timedOutWhileHeld = $false
$acquiredAfterRelease = $false
$contendErr = ''
$readySeen = $false
try {
    $waitUntil = (Get-Date).AddSeconds(10)
    while ((-not (Test-Path -LiteralPath $readyFlag)) -and (-not $childProc.HasExited) -and ((Get-Date) -lt $waitUntil)) {
        Start-Sleep -Milliseconds 50
    }
    $readySeen = Test-Path -LiteralPath $readyFlag
    if ($readySeen) {
        try {
            $contend = Enter-GuardWriteLock -TimeoutMs 250 -LockName $procTestLock
            Exit-GuardWriteLock $contend
        }
        catch {
            $contendErr = $_.Exception.Message
            $timedOutWhileHeld = ($contendErr -match 'Timed out waiting')
        }
    }
    [void]$childProc.WaitForExit(10000)
    $after = Enter-GuardWriteLock -TimeoutMs 2000 -LockName $procTestLock
    $acquiredAfterRelease = [bool]$after.Owned
    Exit-GuardWriteLock $after
}
finally {
    if ($childProc -and (-not $childProc.HasExited)) { try { $childProc.Kill() } catch { } }
    Remove-Item -LiteralPath $readyFlag -Force -ErrorAction SilentlyContinue
}
Assert-True 'Real 2-process Global Mutex blocks concurrent process and releases cleanly on exit' `
    ($timedOutWhileHeld -and $acquiredAfterRelease) `
    ('readySeen=' + $readySeen + ' timedOut=' + $timedOutWhileHeld + ' acquiredAfter=' + $acquiredAfterRelease + ' err=' + $contendErr)

$libCommonRaw = Get-Content -LiteralPath $libCommonPath -Raw
$aclScriptRaw = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'scripts') '13-harden-acl.ps1') -Raw
$ks02Raw = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'scripts') '02-killswitch.ps1') -Raw
$mode07Raw = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'scripts') '07-mode.ps1') -Raw
$task17Raw = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'scripts') '17-autorepair-task.ps1') -Raw
$wdRaw = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'scripts') 'watchdog.ps1') -Raw
$payloadSvcRaw = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'gui\Services') 'PayloadAndRunnerService.cs') -Raw
$guardPolCsRaw = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'gui\Models') 'GuardPolicy.cs') -Raw

$aclIdx = $applyPol.IndexOf("Get-PolicyScriptPath '13-harden-acl.ps1'")
$taskIdx = $applyPol.IndexOf("'-InstallTasks'")
$applyLockIdx = $applyPol.IndexOf('Enter-GuardWriteLock')
$applyReadIdx = $applyPol.IndexOf('Read-GuardPolicyStrict')
$ksAclIdx = $ks02Raw.IndexOf('Get-GuardInstallAclIssues')
$ksRegIdx = $ks02Raw.IndexOf("Register-ScheduledTask -TaskName 'AI-Guard-Test-Rollback'")
$modeLockIdx = $mode07Raw.IndexOf('Enter-GuardWriteLock')
$modeRemIdx = $mode07Raw.IndexOf('if ($RemoveTasks)')

Assert-True '14-apply-policy locks before read, verifies ACL & rollback cancel, and saves last-good on success' `
    (($aclIdx -gt 0) -and ($taskIdx -gt $aclIdx) -and ($applyLockIdx -gt 0) -and ($applyReadIdx -gt $applyLockIdx) -and `
     ($applyPol -match 'Invoke-GuardChild') -and ($applyPol -match '\$pendingRollbackCancel') -and `
     ($applyPol -match 'Save-GuardPolicyLastGood') -and ($applyPol -match 'AI-Guard-Test-Rollback still registered') -and `
     ($libCommonRaw -match 'Get-ChildItem -LiteralPath \$scriptsDir -Recurse') -and `
     ($libCommonRaw -notmatch "Local\\AI-Net-Guard-PolicyEngine") -and `
     ($libCommonRaw -match 'ReparsePoint') -and ($aclScriptRaw -match 'Get-GuardInstallAclIssues')) `
    ('aclIdx=' + $aclIdx + ' taskIdx=' + $taskIdx + ' lockIdx=' + $applyLockIdx + ' readIdx=' + $applyReadIdx)

Assert-True '02-killswitch & 07-mode enforce ACL pre-checks, strict CN CIDR validation, early write lock, and Protected persistence' `
    (($ksAclIdx -gt 0) -and ($ksRegIdx -gt $ksAclIdx) -and ($ks02Raw -match 'Get-ValidatedCnPrefixes') -and `
     ($modeLockIdx -gt 0) -and ($modeRemIdx -gt $modeLockIdx) -and `
     ($mode07Raw -match 'protected-lock\.flag') -and ($mode07Raw -match '\[switch\]\$ClearProtectedLock') -and `
     ($mode07Raw -match 'Refusing to register SYSTEM watchdog tasks on untrusted install ACL')) `
    ('ksAcl=' + $ksAclIdx + ' ksReg=' + $ksRegIdx + ' modeLock=' + $modeLockIdx + ' modeRem=' + $modeRemIdx)

Assert-True '09-rollback accepts -Auto, preserves baseline/metadata on error, and gates outbound Allow on -ForceAllowOutbound' `
    (($rollback -match '\[switch\]\$Auto') -and ($rollback -match '\[switch\]\$ForceAllowOutbound') -and `
     ($rollback -match '\$impRc = \$LASTEXITCODE') -and ($rollback -match 'if \(\$ForceAllowOutbound\)') -and `
     ($rollback -match 'preserving guard-policy\.json') -and ($rollback -match '\$rollbackErrors\.Count -eq 0')) `
    'rollback -Auto, baseline preservation, and error gating required'

Assert-True 'GUI payload extraction & GuardPolicy save use Global Mutex, SHA-256 skip, and atomic File.Replace' `
    (($payloadSvcRaw -match 'Global\\AI-Net-Guard-PolicyEngine') -and ($payloadSvcRaw -notmatch 'Local\\') -and `
     ($payloadSvcRaw -match 'SHA256') -and ($payloadSvcRaw -match 'File\.Replace') -and `
     ($guardPolCsRaw -match 'File\.Replace')) `
    'GUI Mutex, SHA-256, and atomic File.Replace checks failed'

Assert-True '17-autorepair-task and watchdog inspect task health/exit codes strictly' `
    (($task17Raw -match '\$healthy -eq 2') -and ($task17Raw -match '267009') -and ($wdRaw -match 'if \(\$code -eq 0\)')) `
    'task health and watchdog non-zero exit handling required'

Write-Host ' '
if ($script:fail -gt 0) {
    Write-Host ('=== ' + $script:fail + ' assertion(s) FAILED ===') -ForegroundColor Red
    exit 1
}
Write-Host '=== all port-set assertions passed ===' -ForegroundColor Green
exit 0
