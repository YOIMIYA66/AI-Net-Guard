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

# ---------------------------------------------------------------- 22. v5.9.1 security hardening (ACL, Rollback, ExitCode, Fail-Closed Policy, Lock, CIDR, Tasks, GUI)
$tmpSecDir = Join-Path ([System.IO.Path]::GetTempPath()) ('ai-guard-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpSecDir -Force | Out-Null
try {
    $defs = [ordered]@{
        AllowCnDirect = $true; AllowLan = $true; AllowNcsi = $true; LockPhysicalDns = $true;
        DisablePhysicalIpv6 = $true; BlockWebRtcLeak = $true; ZeroResidentMonitor = $true;
        HardenInstallAcl = $true; StrictNrptDoh = $false; Preset = 'Recommended'
    }
    $pFile = Join-Path $tmpSecDir 'guard-policy.json'
    $lgFile = Join-Path $tmpSecDir 'guard-policy.last-good.json'
    $fullStrictJson = '{"AllowCnDirect":false,"AllowLan":true,"AllowNcsi":true,"LockPhysicalDns":true,"DisablePhysicalIpv6":true,"BlockWebRtcLeak":true,"ZeroResidentMonitor":true,"HardenInstallAcl":true,"Preset":"StrictLock"}'

    # Valid policy reads ok and does NOT prematurely write last-good before apply succeeds
    [System.IO.File]::WriteAllText($pFile, $fullStrictJson, (New-Object System.Text.UTF8Encoding($false)))
    $pOk = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile
    $okPass = ($pOk.PolicyHealth -eq 'ok') -and (-not $pOk.AllowCnDirect) -and (-not (Test-Path -LiteralPath $lgFile))

    # Explicit Save-GuardPolicyLastGood persists last-good atomically
    Save-GuardPolicyLastGood -PolicyPath $pFile -LastGoodPath $lgFile
    $lgSaved = Test-Path -LiteralPath $lgFile

    # String "false" must NOT coerce to $true - should recover last-good
    [System.IO.File]::WriteAllText($pFile, '{"AllowCnDirect":"false"}', (New-Object System.Text.UTF8Encoding($false)))
    $pRec = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile
    $recPass = ($pRec.PolicyHealth -eq 'recovered-last-good') -and (-not $pRec.AllowCnDirect)

    # Incomplete JSON (e.g. only {"Preset":"Recommended"}) on deployed host must NOT revert security bools to defaults (#09)
    [System.IO.File]::WriteAllText($pFile, '{"Preset":"Recommended"}', (New-Object System.Text.UTF8Encoding($false)))
    $pIncRec = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile -IsDeployed
    [System.IO.File]::WriteAllText($lgFile, '{"Preset":"Recommended"}', (New-Object System.Text.UTF8Encoding($false)))
    $pIncFc = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile -IsDeployed
    $incompleteDeployedPass = ($pIncRec.PolicyHealth -eq 'recovered-last-good') -and (-not $pIncRec.AllowCnDirect) -and ($pIncFc.PolicyHealth -eq 'corrupt-fail-closed') -and (-not $pIncFc.AllowCnDirect)

    # Empty {} and explicit null boolean must be rejected (recover last-good / fail closed when last-good corrupt)
    [System.IO.File]::WriteAllText($lgFile, $fullStrictJson, (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText($pFile, '{}', (New-Object System.Text.UTF8Encoding($false)))
    $pEmptyRec = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile -IsDeployed
    [System.IO.File]::WriteAllText($lgFile, '{also-broken', (New-Object System.Text.UTF8Encoding($false)))
    $pEmptyFc = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile -IsDeployed
    [System.IO.File]::WriteAllText($pFile, '{"AllowCnDirect":null}', (New-Object System.Text.UTF8Encoding($false)))
    $pNullFc = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile -IsDeployed
    $strictFieldPass = ($pEmptyRec.PolicyHealth -eq 'recovered-last-good') -and ($pEmptyFc.PolicyHealth -eq 'corrupt-fail-closed') -and ($pNullFc.PolicyHealth -eq 'corrupt-fail-closed') -and (-not $pNullFc.AllowCnDirect)

    # Missing primary on deployed host without last-good -> Fail-Closed; missing with valid last-good -> recovered
    Remove-Item -LiteralPath $pFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $lgFile -Force -ErrorAction SilentlyContinue
    $pMissingDeployed = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile -IsDeployed
    $pMissingFresh = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile
    [System.IO.File]::WriteAllText($lgFile, $fullStrictJson, (New-Object System.Text.UTF8Encoding($false)))
    $pMissingLg = Read-GuardPolicyStrict -PolicyPath $pFile -Defaults $defs -LastGoodPath $lgFile -IsDeployed
    $missingPolicyPass = ($pMissingDeployed.PolicyHealth -eq 'corrupt-fail-closed') -and (-not $pMissingDeployed.AllowCnDirect) -and (-not $pMissingDeployed.AllowLan) -and ($pMissingFresh.PolicyHealth -eq 'default') -and ($pMissingLg.PolicyHealth -eq 'recovered-last-good') -and (-not $pMissingLg.AllowCnDirect)

    Assert-True 'Read-GuardPolicyStrict rejects string/null/empty and incomplete deployed JSON, decouples last-good save, and fails closed when missing on deployed host' `
        ($okPass -and $lgSaved -and $recPass -and $incompleteDeployedPass -and $strictFieldPass -and $missingPolicyPass) `
        ('ok=' + $okPass + ' lgSaved=' + $lgSaved + ' rec=' + $recPass + ' inc=' + $incompleteDeployedPass + ' strict=' + $strictFieldPass + ' missing=' + $missingPolicyPass)

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

Assert-True '14-apply-policy locks before read, verifies ACL & rollback cancel, and commits last-good via transaction' `
    (($aclIdx -gt 0) -and ($taskIdx -gt $aclIdx) -and ($applyLockIdx -gt 0) -and ($applyReadIdx -gt $applyLockIdx) -and `
     ($applyPol -match 'Invoke-GuardChild') -and ($applyPol -match '\$pendingRollbackCancel') -and `
     ($applyPol -match 'txCommitPolicy') -and ($libCommonRaw -match 'Save-GuardPolicyLastGood') -and `
     ($applyPol -match 'AI-Guard-Test-Rollback still registered') -and `
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

$mainWinRaw = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'gui') 'MainWindow.xaml.cs') -Raw
$boot06Raw = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'scripts') '06-boot-guard.ps1') -Raw

Assert-True '07-mode keeps Ensure-Guard active under Protected lock, preserves CliBoundParams, and removes last-good bootstrap' `
    (($mode07Raw -match '\$script:CliBoundParams') -and ($mode07Raw -match '\$script:guardPolicy\.AllowCnDirect = \$false') -and `
     ($mode07Raw -notmatch 'lastGoodBootstrapPath') -and ($mode07Raw -match '\[switch\]\$false')) `
    '07-mode Protected override / CliBoundParams / last-good removal checks failed'

Assert-True 'GUI writes guard-policy.pending.json and 14-apply-policy rolls back failed policy & removes tasks before ACL unlock' `
    (($mainWinRaw -match 'guard-policy\.pending\.json') -and ($mainWinRaw -match '"-PolicyPath"') -and `
     ($applyPol -match 'Write-CanonicalPolicyAtomic') -and ($applyPol -match '\$pendingAclUnlock') -and `
     ($applyPol -match 'refused to unlock install ACL while SYSTEM tasks remain registered')) `
    'GUI pending policy & 14-apply-policy transactional rollback/task-before-ACL checks failed'

Assert-True '09-rollback defers self-tasks, aborts destructive steps on baseline failure, and protects ACL; 06/02 lock & ACL hardened' `
    (($rollback -match '\$deferredSelfTasks') -and ($rollback -match '\$abortDestructiveRollback') -and `
     ($rollback -match '\$remainingAiTasks\.Count -gt 0') -and `
     ($boot06Raw -match 'Get-GuardInstallAclIssues') -and ($ks02Raw -match 'Enter-GuardWriteLock')) `
    '09-rollback self-task/abort/ACL guard or 06-boot-guard ACL / 02-killswitch lock check failed'

# ---------------------------------------------------------------- 23. Runtime exception-path transaction, V2rayNRoot preservation & Boot Guard exit checks
$tmpTxDir = Join-Path ([System.IO.Path]::GetTempPath()) ('ai-guard-tx-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpTxDir -Force | Out-Null
try {
    $utf8NoBomTx = New-Object System.Text.UTF8Encoding($false)
    $oldJson = '{"Preset":"StrictLock","AllowCnDirect":false}'
    $newJson = '{"Preset":"Recommended","AllowCnDirect":true}'
    $canPath = Join-Path $tmpTxDir 'guard-policy.json'
    $pendPath = Join-Path $tmpTxDir 'guard-policy.pending.json'
    $lgPath = Join-Path $tmpTxDir 'guard-policy.last-good.json'

    # Case A: unhandled exception after staging restores existing canonical policy & preserves last-good
    [System.IO.File]::WriteAllText($canPath, $oldJson, $utf8NoBomTx)
    [System.IO.File]::WriteAllText($pendPath, $newJson, $utf8NoBomTx)
    [System.IO.File]::WriteAllText($lgPath, $oldJson, $utf8NoBomTx)
    $sawStagedRef = [ref]$false
    $resA = Invoke-GuardPolicyTransaction -CanonicalPolicyPath $canPath -PendingPolicyPath $pendPath -LastGoodPolicyPath $lgPath -ApplyAction {
        param($st, $stageFn, $commitFn)
        & $stageFn $newJson
        $sawStagedRef.Value = (([System.IO.File]::ReadAllText($canPath)).Trim() -eq $newJson)
        throw 'simulated mid-apply failure'
    }
    $caseAOk = $sawStagedRef.Value -and (-not $resA.PolicyCommitted) -and ($resA.ExitCode -eq 5) -and ($resA.ErrorMessage -eq 'simulated mid-apply failure') -and `
               (([System.IO.File]::ReadAllText($canPath)).Trim() -eq $oldJson) -and `
               (([System.IO.File]::ReadAllText($lgPath)).Trim() -eq $oldJson) -and `
               (-not (Test-Path -LiteralPath $pendPath))

    # Case B: unhandled exception on initial deploy deletes uncommitted canonical file & leaves no last-good
    Remove-Item -LiteralPath $canPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $lgPath -Force -ErrorAction SilentlyContinue
    [System.IO.File]::WriteAllText($pendPath, $newJson, $utf8NoBomTx)
    $resB = Invoke-GuardPolicyTransaction -CanonicalPolicyPath $canPath -PendingPolicyPath $pendPath -LastGoodPolicyPath $lgPath -ApplyAction {
        param($st, $stageFn, $commitFn)
        & $stageFn $newJson
        throw 'simulated initial deploy exception'
    }
    $caseBOk = (-not $resB.PolicyCommitted) -and ($resB.ExitCode -eq 5) -and (-not (Test-Path -LiteralPath $canPath)) -and (-not (Test-Path -LiteralPath $lgPath)) -and (-not (Test-Path -LiteralPath $pendPath))

    # Case C: Save-GuardPolicyLastGood failure keeps PolicyCommitted=$false and restores canonical policy
    [System.IO.File]::WriteAllText($canPath, $oldJson, $utf8NoBomTx)
    $blockerFile = Join-Path $tmpTxDir 'dir-blocker'
    [System.IO.File]::WriteAllText($blockerFile, 'file', $utf8NoBomTx)
    $badLgPath = Join-Path $blockerFile 'guard-policy.last-good.json'
    $resC = Invoke-GuardPolicyTransaction -CanonicalPolicyPath $canPath -PendingPolicyPath $pendPath -LastGoodPolicyPath $badLgPath -ApplyAction {
        param($st, $stageFn, $commitFn)
        & $stageFn $newJson
        & $commitFn
    }
    $caseCOk = (-not $resC.PolicyCommitted) -and ($resC.ExitCode -eq 5) -and (([System.IO.File]::ReadAllText($canPath)).Trim() -eq $oldJson)

    # Case D: clean commit updates canonical + last-good, marks PolicyCommitted=$true, removes pending
    [System.IO.File]::WriteAllText($canPath, $oldJson, $utf8NoBomTx)
    [System.IO.File]::WriteAllText($pendPath, $newJson, $utf8NoBomTx)
    $resD = Invoke-GuardPolicyTransaction -CanonicalPolicyPath $canPath -PendingPolicyPath $pendPath -LastGoodPolicyPath $lgPath -ApplyAction {
        param($st, $stageFn, $commitFn)
        & $stageFn $newJson
        & $commitFn
    }
    $caseDOk = $resD.PolicyCommitted -and ($resD.ExitCode -eq 0) -and `
               (([System.IO.File]::ReadAllText($canPath)).Trim() -eq $newJson) -and `
               (([System.IO.File]::ReadAllText($lgPath)).Trim() -eq $newJson) -and `
               (-not (Test-Path -LiteralPath $pendPath))

    Assert-True 'Invoke-GuardPolicyTransaction handles mid-apply exceptions, initial deploy failure, commit failure, and clean commit' `
        ($caseAOk -and $caseBOk -and $caseCOk -and $caseDOk) `
        ('A=' + $caseAOk + ' B=' + $caseBOk + ' C=' + $caseCOk + ' D=' + $caseDOk)

    # Case E: commit inside a [CmdletBinding()] script invoked with & (PowerShell 7 script-scope closure)
    $caseEHost = (Get-Process -Id $PID).Path
    $caseEScript = Join-Path $tmpTxDir 'case-e-cmdlet.ps1'
    $canE = Join-Path $tmpTxDir 'can-e.json'
    $lgE = Join-Path $tmpTxDir 'lg-e.json'
    $escapedLib = $libCommonPath.Replace("'", "''")
    $escapedCanE = $canE.Replace("'", "''")
    $escapedLgE = $lgE.Replace("'", "''")
    $caseEBody = @"
[CmdletBinding()]
param([string]`$Dummy = '')
. '$escapedLib'
`$resE = Invoke-GuardPolicyTransaction -CanonicalPolicyPath '$escapedCanE' -LastGoodPolicyPath '$escapedLgE' -ApplyAction {
    param(`$st, `$stageFn, `$commitFn)
    & `$stageFn '$newJson'
    & `$commitFn
}
if (-not `$resE.PolicyCommitted) {
    throw ('Case E PolicyCommitted=False: ' + `$resE.ErrorMessage)
}
"@
    [System.IO.File]::WriteAllText($caseEScript, $caseEBody, $utf8NoBomTx)
    & $caseEHost -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& '$($caseEScript.Replace("'", "''"))'"
    $caseEOk = ($LASTEXITCODE -eq 0) -and (Test-Path -LiteralPath $lgE) -and (([System.IO.File]::ReadAllText($lgE)).Trim() -eq $newJson)
    Assert-True 'Invoke-GuardPolicyTransaction commits cleanly inside [CmdletBinding()] script invoked via &' `
        $caseEOk ('exit=' + $LASTEXITCODE + ' lgExists=' + (Test-Path -LiteralPath $lgE))
}
finally {
    Remove-Item -LiteralPath $tmpTxDir -Recurse -Force -ErrorAction SilentlyContinue
}

Assert-True '14-apply-policy uses PolicyCommitted transaction; 07-mode resolves V2rayNRoot safely; 06-boot-guard propagates rollback exit code' `
    (($applyPol -match 'Invoke-GuardPolicyTransaction') -and ($applyPol -match '\$txResult\.PolicyCommitted') -and `
     ($mode07Raw -match 'function Resolve-EffectiveV2rayNRoot') -and ($mode07Raw -match '\$script:V2rayNRoot = Resolve-EffectiveV2rayNRoot') -and `
     ($boot06Raw -match '\$bootGuardExit') -and ($boot06Raw -match 'exit \$bootGuardExit')) `
    'transaction/V2rayNRoot/boot-guard exit propagation checks failed'

# ---------------------------------------------------------------- 21. PS 5.1 quarantine JSON self-healing & scripts\ default Root
$tmpQDir = Join-Path $env:TEMP ('ainguard-quarantine-test-' + $PID)
New-Item -ItemType Directory -Path $tmpQDir -Force | Out-Null
try {
    $qTmpFile = Join-Path $tmpQDir 'auto-disabled-outbound-allow.json'
    $corruptNestedJson = @'
[
  {
    "value": [
      {
        "value": [
          { "value": " ", "Count": 2 },
          { "Name": "RuleA", "DisplayName": "Microsoft Store", "QuarantinedAt": "2026-11-18T19:01:49" }
        ],
        "Count": 2
      },
      { "Name": "RuleB", "DisplayName": "WebExperience", "QuarantinedAt": "2026-11-20T10:00:00" }
    ],
    "Count": 2
  },
  { "Name": "RuleA", "DisplayName": "Microsoft Store", "QuarantinedAt": "2026-11-24T17:17:49" }
]
'@
    [System.IO.File]::WriteAllText($qTmpFile, $corruptNestedJson, (New-Object System.Text.UTF8Encoding($false)))
    $qHealed = Read-GuardQuarantineList -Path $qTmpFile
    $healedNames = @($qHealed.Items | ForEach-Object { $_.Name })
    Assert-True 'Read-GuardQuarantineList unwraps PS 5.1 nested value arrays, drops garbage, and deduplicates by Name' `
        ($qHealed.NeedsRewrite -and ($healedNames.Count -eq 2) -and ($healedNames[0] -eq 'RuleA') -and ($healedNames[1] -eq 'RuleB')) `
        ('NeedsRewrite=' + $qHealed.NeedsRewrite + ' names=' + ($healedNames -join ','))

    $roundTripOk = $true
    $roundTripMsg = ''
    foreach ($cnt in @(0, 1, 2, 3)) {
        $batch = New-Object System.Collections.Generic.List[object]
        for ($i = 1; $i -le $cnt; $i++) {
            $batch.Add([pscustomobject]@{
                Name          = ('Rule' + $i)
                DisplayName   = ('Display ' + $i)
                QuarantinedAt = '2026-11-24T19:30:00Z'
            })
        }
        Write-GuardQuarantineList -Path $qTmpFile -Items ([object[]]$batch.ToArray())
        $writtenRaw = [System.IO.File]::ReadAllText($qTmpFile, [System.Text.Encoding]::UTF8)
        $reRead = Read-GuardQuarantineList -Path $qTmpFile
        $isArrayText = $writtenRaw.TrimStart().StartsWith('[')
        $hasWrapper = ($writtenRaw -match '"value"\s*:') -or ($writtenRaw -match '"Count"\s*:')
        if ((-not $isArrayText) -or $hasWrapper -or $reRead.NeedsRewrite -or (@($reRead.Items).Count -ne $cnt)) {
            $roundTripOk = $false
            $roundTripMsg = ('cnt=' + $cnt + ' array=' + $isArrayText + ' wrapper=' + $hasWrapper + ' needsRewrite=' + $reRead.NeedsRewrite + ' got=' + @($reRead.Items).Count)
            break
        }
    }
    Assert-True 'Write-GuardQuarantineList writes flat JSON arrays for 0/1/2/3 items without PS 5.1 value wrapper' `
        $roundTripOk $roundTripMsg
}
finally {
    Remove-Item -LiteralPath $tmpQDir -Recurse -Force -ErrorAction SilentlyContinue
}

$reg12Raw = [System.IO.File]::ReadAllText((Join-Path $repo 'scripts\12-regression.ps1'), [System.Text.Encoding]::UTF8)
$acl13Raw = [System.IO.File]::ReadAllText((Join-Path $repo 'scripts\13-harden-acl.ps1'), [System.Text.Encoding]::UTF8)
$quarantineWiredOk = ($mode07Raw -match 'Read-GuardQuarantineList') -and ($mode07Raw -match 'Write-GuardQuarantineList') -and `
    ($mode07Raw -notmatch '@\(Get-Content -LiteralPath \$quarantineFile') -and ($mode07Raw -notmatch '\$qList \| ConvertTo-Json') -and `
    ($rollback -match 'Read-GuardQuarantineList') -and `
    ($applyPol -match 'Read-GuardQuarantineList') -and ($applyPol -notmatch '@\(Get-Content -LiteralPath \$qFile')
Assert-True '07-mode, 09-rollback, and 14-apply-policy all read/write quarantine list via Read/Write-GuardQuarantineList' `
    $quarantineWiredOk 'quarantine helper wiring incomplete'

$scriptsRootResolveOk = ($mode07Raw -match "\(Split-Path -Leaf \`$PSScriptRoot\) -ieq 'scripts'") -and `
    ($reg12Raw -match "\(Split-Path -Leaf \`$PSScriptRoot\) -ieq 'scripts'") -and `
    ($acl13Raw -match "\(Split-Path -Leaf \`$PSScriptRoot\) -ieq 'scripts'") -and `
    ($applyPol -match "\(Split-Path -Leaf \`$PSScriptRoot\) -ieq 'scripts'") -and `
    ($reg12Raw -match 'if \(-not \$cnFileExists\)') -and ($reg12Raw -match 'if \(\$before -lt 1000\)')
Assert-True 'scripts\ entrypoints resolve parent install Root and 12-regression Check 7 guards missing cn-ipv4.txt' `
    $scriptsRootResolveOk 'default Root resolution or Check 7 guard missing'

$libCommonAclRaw = [System.IO.File]::ReadAllText((Join-Path $repo 'scripts\lib-guard-common.ps1'), [System.Text.Encoding]::UTF8)
Assert-True 'Enter-GuardWriteLock supports PowerShell 7 MutexAcl::Create alongside PS 5.1 Mutex ctor' `
    (($libCommonAclRaw -match 'System\.Threading\.MutexAcl') -and ($libCommonAclRaw -match 'New-Object System\.Threading\.Mutex\(') -and ($libCommonAclRaw -match 'if \(-not \$mtx\)')) `
    'MutexAcl / null guard missing in lib-guard-common.ps1'

# ---------------------------------------------------------------- 22. Anti-PII / local path & personal IP leak gate
$piiMarkers = @(
    ('C:' + [char]92 + 'Us' + 'ers' + [char]92 + '86' + '198'),
    ('deepseek-' + 'harness'),
    ('default-' + 'workspace'),
    ('183.' + '188.' + '38.12'),
    ('20.' + '89.' + '232.246'),
    ('192.168.' + '1.165')
)
$piiFiles = New-Object System.Collections.Generic.List[string]
foreach ($rootMd in @(Get-ChildItem -LiteralPath $repo -Filter '*.md' -File -ErrorAction SilentlyContinue)) {
    $piiFiles.Add($rootMd.FullName)
}
foreach ($subDir in @('scripts', 'docs', 'tests')) {
    $subPath = Join-Path $repo $subDir
    if (Test-Path -LiteralPath $subPath) {
        foreach ($sf in @(Get-ChildItem -LiteralPath $subPath -Recurse -File -ErrorAction SilentlyContinue)) {
            if ($sf.Extension -in @('.md', '.ps1', '.bat')) { $piiFiles.Add($sf.FullName) }
        }
    }
}
$guiDirPath = Join-Path $repo 'gui'
if (Test-Path -LiteralPath $guiDirPath) {
    foreach ($gf in @(Get-ChildItem -LiteralPath $guiDirPath -Recurse -File -ErrorAction SilentlyContinue)) {
        if ($gf.FullName -match '\\(obj|bin)\\') { continue }
        if ($gf.Extension -in @('.cs', '.xaml', '.csproj', '.ps1')) { $piiFiles.Add($gf.FullName) }
    }
}
$piiHits = New-Object System.Collections.Generic.List[string]
foreach ($pf in $piiFiles) {
    $pTxt = [System.IO.File]::ReadAllText($pf, [System.Text.Encoding]::UTF8)
    foreach ($mk in $piiMarkers) {
        if ($pTxt.IndexOf($mk, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $piiHits.Add((Split-Path -Leaf $pf) + ':' + $mk)
        }
    }
}
Assert-True 'Repository docs, scripts, tests, and GUI contain zero personal paths or private IPs' `
    ($piiHits.Count -eq 0) ($piiHits -join ' | ')

# ---------------------------------------------------------------- 23. Opt-in candidate node whitelist helpers & wiring
$tmpCandDir = Join-Path ([System.IO.Path]::GetTempPath()) ('ai-guard-cand-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpCandDir -Force | Out-Null
try {
    $candJsonPath = Join-Path $tmpCandDir 'candidate-nodes.json'
    $missingCand = Read-GuardCandidateNodes -Path $candJsonPath
    [System.IO.File]::WriteAllText($candJsonPath, '{corrupt', (New-Object System.Text.UTF8Encoding($false)))
    $corruptCand = Read-GuardCandidateNodes -Path $candJsonPath

    Write-GuardCandidateNodes -Path $candJsonPath `
        -Ips @('198.51.100.10', '203.0.113.20', '127.0.0.1', '192.168.1.10', '10.0.0.1', '999.1.1.1') `
        -TcpPorts @('443', '0', '70000', 'abc') `
        -UdpPorts @('20000-30000', '500-100')
    $loadedCand = Read-GuardCandidateNodes -Path $candJsonPath
    $candFilterOk = (-not $missingCand.Enabled) -and (-not $corruptCand.Enabled) -and $loadedCand.Enabled -and `
        ($loadedCand.Ips.Count -eq 2) -and ($loadedCand.Ips -contains '198.51.100.10') -and ($loadedCand.Ips -contains '203.0.113.20') -and `
        ($loadedCand.TcpPorts.Count -eq 1) -and ($loadedCand.TcpPorts[0] -eq '443') -and `
        ($loadedCand.UdpPorts.Count -eq 1) -and ($loadedCand.UdpPorts[0] -eq '20000-30000')

    # Verify single-item round-trip stays clean array in both PS 5.1 and PS 7.x
    Write-GuardCandidateNodes -Path $candJsonPath -Ips @('198.51.100.99') -TcpPorts @('8443') -UdpPorts @()
    $singleCand = Read-GuardCandidateNodes -Path $candJsonPath
    $singleCandOk = $singleCand.Enabled -and ($singleCand.Ips.Count -eq 1) -and ($singleCand.Ips[0] -eq '198.51.100.99') -and `
        ($singleCand.TcpPorts.Count -eq 1) -and ($singleCand.TcpPorts[0] -eq '8443') -and ($singleCand.UdpPorts.Count -eq 0)

    Assert-True 'Read/Write-GuardCandidateNodes validates public IPs & ports, fails closed, and round-trips single-item arrays' `
        ($candFilterOk -and $singleCandOk) `
        ('filterOk=' + $candFilterOk + ' singleOk=' + $singleCandOk + ' ips=' + ($loadedCand.Ips -join ','))
}
finally {
    Remove-Item -LiteralPath $tmpCandDir -Recurse -Force -ErrorAction SilentlyContinue
}

$sync10Raw = [System.IO.File]::ReadAllText((Join-Path $repo 'scripts\10-sync-node-rule.ps1'), [System.Text.Encoding]::UTF8)
$candWireOk = ($sync10Raw -match '\[switch\]\$IncludeAllNodes') -and ($sync10Raw -match '\[switch\]\$ClearCandidateNodes') -and `
    ($sync10Raw -match "\(Split-Path -Leaf \`$PSScriptRoot\) -ieq 'scripts'") -and `
    ($sync10Raw -match 'mode=ro') -and ($sync10Raw -match 'AI-Guard-Allow-Candidates-') -and `
    ($sync10Raw -match '-NodeIps \$foreignNodeIps') -and `
    ($sync10Raw -match 'PRAGMA table_info\(ProfileItem\)') -and ($sync10Raw -match 'ProtoExtra') -and `
    ($sync10Raw -match 'Merge-GuardPortSpecs') -and `
    ($mode07Raw -match 'Read-GuardCandidateNodes') -and ($mode07Raw -match 'AI-Guard-Allow-Candidates-') -and `
    ($mode07Raw -match '\$isCandidateRule') -and ($rollback -match 'candidate-nodes\.json')
Assert-True '10-sync-node-rule, 07-mode, and 09-rollback wire opt-in candidate node whitelist and foreign-block exemption' `
    $candWireOk 'candidate node wiring check failed'

# ---------------------------------------------------------------- 24. Merge-GuardPortSpecs & ProtoExtra.Ports extraction
$mergedSample = Merge-GuardPortSpecs -Specs @('60000', '35000', '35000-39000', '38000-40000', '60000:63000', '443', '444', '0', 'abc', '900-100')
$mergedSingle = Merge-GuardPortSpecs -Specs @('443')
$mergedEmpty = Merge-GuardPortSpecs -Specs @()
$mergeOk = ($mergedSample -is [System.Array]) -and ($mergedSample.Count -eq 3) -and `
    ($mergedSample[0] -eq '443-444') -and ($mergedSample[1] -eq '35000-40000') -and ($mergedSample[2] -eq '60000-63000') -and `
    ($mergedSingle -is [System.Array]) -and ($mergedSingle.Count -eq 1) -and ($mergedSingle[0] -eq '443') -and `
    ($mergedEmpty -is [System.Array]) -and ($mergedEmpty.Count -eq 0)
Assert-True 'Merge-GuardPortSpecs merges overlapping/adjacent ports and preserves array shape for 0/1/N specs' `
    $mergeOk ('sample=' + ($mergedSample -join ',') + ' singleCount=' + $mergedSingle.Count + ' emptyCount=' + $mergedEmpty.Count)

$pyTestExe = ''
foreach ($candPy in @('python', 'python3', 'py')) {
    $cmdPy = Get-Command $candPy -ErrorAction SilentlyContinue
    if ($cmdPy) { $pyTestExe = $cmdPy.Source; break }
}
Assert-True 'Python 3 is available to run Get-V2rayNCandidateNodes SQLite test' ([bool]$pyTestExe) 'python executable not found'

$syncAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'scripts\10-sync-node-rule.ps1'), [ref]$null, [ref]$null)
$candFnAst = $syncAst.FindAll({ param($n) ($n -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and ($n.Name -eq 'Get-V2rayNCandidateNodes') }, $true) | Select-Object -First 1
Assert-True 'Get-V2rayNCandidateNodes AST definition found in 10-sync-node-rule.ps1' ($null -ne $candFnAst) 'function AST missing'
if ($candFnAst -and $pyTestExe) {
    . ([scriptblock]::Create($candFnAst.Extent.Text))
    $tmpDbDir = Join-Path ([System.IO.Path]::GetTempPath()) ('ai-guard-db-test-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmpDbDir -Force | Out-Null
    try {
        $db1 = Join-Path $tmpDbDir 'v7.db'
        $db2 = Join-Path $tmpDbDir 'legacy.db'
        $mkDbPy = Join-Path $tmpDbDir 'mkdb.py'
        [System.IO.File]::WriteAllText($mkDbPy, @'
import sqlite3, sys
c1 = sqlite3.connect(sys.argv[1])
c1.execute("CREATE TABLE ProfileItem (ConfigType INT, Address TEXT, Port INT, Ports TEXT, Network TEXT, Alpn TEXT, ProtoExtra TEXT)")
c1.executemany("INSERT INTO ProfileItem VALUES (?,?,?,?,?,?,?)", [
    (7, '198.51.100.10', 35000, None, '', '', '{"SalamanderPass":"","Ports":"35000-39000"}'),
    (7, '203.0.113.20', 60000, '', '', '', '{"Ports":"60000:63000"}'),
    (7, '198.51.100.11', 25000, '25000-25100', '', '', None),
    (5, '198.51.100.12', 443, None, 'tcp', '', '{"Flow":"xtls-rprx-vision"}'),
])
c1.commit(); c1.close()

c2 = sqlite3.connect(sys.argv[2])
c2.execute("CREATE TABLE ProfileItem (ConfigType INT, Address TEXT, Port INT, Ports TEXT, Network TEXT, Alpn TEXT)")
c2.execute("INSERT INTO ProfileItem VALUES (?,?,?,?,?,?)", (7, '198.51.100.20', 443, '20000-20010', '', ''))
c2.commit(); c2.close()
'@, (New-Object System.Text.UTF8Encoding($false)))
        & $pyTestExe $mkDbPy $db1 $db2
        $res1 = Get-V2rayNCandidateNodes -DbPath $db1
        $res2 = Get-V2rayNCandidateNodes -DbPath $db2
        $db1Ok = ($res1.Ips.Count -eq 4) -and `
            (($res1.UdpPorts -join ',') -eq '25000-25100,35000-39000,60000-63000') -and `
            (($res1.TcpPorts -join ',') -eq '443,25000,35000,60000')
        $db2Ok = ($res2.Ips.Count -eq 1) -and (($res2.UdpPorts -join ',') -eq '443,20000-20010')
        Assert-True 'Get-V2rayNCandidateNodes extracts and merges ProtoExtra.Ports on v2rayN 7.x DB and supports legacy schema without ProtoExtra' `
            ($db1Ok -and $db2Ok) `
            ('db1Udp=' + ($res1.UdpPorts -join ',') + ' db1Tcp=' + ($res1.TcpPorts -join ',') + ' db2Udp=' + ($res2.UdpPorts -join ','))

        # ---------------------------------------------------------------- 25. Temporary IPv6 node sync & policy wiring
        $v6PassAll = (Test-GuardPublicNodeIpv6 -IpStr '2001:db8::1') -and `
            (Test-GuardPublicNodeIpv6 -IpStr '2400:3200::1') -and `
            (Test-GuardPublicNodeIpv6 -IpStr '[2606:4700::1]')
        $v6RejectBad = $true
        foreach ($badV6 in @('::', '::1', 'fe80::1', 'fc00::1', 'fd12::1', 'ff02::1', '::ffff:192.0.2.1', '198.51.100.10', '')) {
            if (Test-GuardPublicNodeIpv6 -IpStr $badV6) { $v6RejectBad = $false }
        }
        Assert-True 'Test-GuardPublicNodeIpv6 accepts global unicast 2000::/3 and rejects loopback/ULA/link-local/multicast/IPv4' `
            ($v6PassAll -and $v6RejectBad) ('passAll=' + $v6PassAll + ' rejectBad=' + $v6RejectBad)

        $v6CandPath = Join-Path $tmpDbDir 'cand-v6.json'
        Write-GuardCandidateNodes -Path $v6CandPath `
            -Ips @('198.51.100.10') `
            -Ipv6Ips @('2001:DB8::1', '2001:db8::2', 'fe80::1', 'fd12::1') `
            -TcpPorts @('443') `
            -UdpPorts @()
        $v6CandLoaded = Read-GuardCandidateNodes -Path $v6CandPath
        $v6OnlyPath = Join-Path $tmpDbDir 'cand-v6-only.json'
        Write-GuardCandidateNodes -Path $v6OnlyPath -Ips @() -Ipv6Ips @('2001:DB8::9') -TcpPorts @('8443') -UdpPorts @()
        $v6OnlyLoaded = Read-GuardCandidateNodes -Path $v6OnlyPath
        $v6RoundTripOk = $v6CandLoaded.Enabled -and ($v6CandLoaded.Ips.Count -eq 1) -and `
            ($v6CandLoaded.Ipv6Ips.Count -eq 2) -and ($v6CandLoaded.Ipv6Ips[0] -eq '2001:db8::1') -and ($v6CandLoaded.Ipv6Ips[1] -eq '2001:db8::2') -and `
            $v6OnlyLoaded.Enabled -and ($v6OnlyLoaded.Ips.Count -eq 0) -and ($v6OnlyLoaded.Ipv6Ips.Count -eq 1) -and ($v6OnlyLoaded.Ipv6Ips[0] -eq '2001:db8::9')
        Assert-True 'Write/Read-GuardCandidateNodes normalizes and round-trips IPv6 candidate IPs alongside IPv4 and IPv6-only sets' `
            $v6RoundTripOk ('v6=' + ($v6CandLoaded.Ipv6Ips -join ',') + ' v6Only=' + $v6OnlyLoaded.Enabled)

        $dbV6 = Join-Path $tmpDbDir 'v6-nodes.db'
        $mkV6Py = Join-Path $tmpDbDir 'mkv6.py'
        [System.IO.File]::WriteAllText($mkV6Py, @'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("CREATE TABLE ProfileItem (ConfigType INT, Address TEXT, Port INT, Ports TEXT, Network TEXT, Alpn TEXT, ProtoExtra TEXT)")
c.executemany("INSERT INTO ProfileItem VALUES (?,?,?,?,?,?,?)", [
    (5, '198.51.100.30', 443, None, 'raw', '', '{}'),
    (5, '2001:db8::10', 2100, None, 'raw', '', '{}'),
    (5, '[2001:DB8::20]', 2101, None, 'raw', '', '{}'),
    (5, 'fe80::1', 2102, None, 'raw', '', '{}'),
])
c.commit(); c.close()
'@, (New-Object System.Text.UTF8Encoding($false)))
        & $pyTestExe $mkV6Py $dbV6
        $resV4Only = Get-V2rayNCandidateNodes -DbPath $dbV6
        $resWithV6 = Get-V2rayNCandidateNodes -DbPath $dbV6 -IncludeIpv6
        $candV6Ok = ($resV4Only.Ips.Count -eq 1) -and ($resV4Only.Ipv6Ips.Count -eq 0) -and `
            ($resWithV6.Ips.Count -eq 1) -and ($resWithV6.Ipv6Ips.Count -eq 2) -and `
            (($resWithV6.Ipv6Ips -join ',') -eq '2001:db8::10,2001:db8::20') -and `
            (($resWithV6.TcpPorts -join ',') -eq '443,2100-2101')
        Assert-True 'Get-V2rayNCandidateNodes keeps IPv6 excluded by default and extracts public IPv6 nodes when -IncludeIpv6 is passed' `
            $candV6Ok ('defaultV6=' + $resV4Only.Ipv6Ips.Count + ' optInV6=' + ($resWithV6.Ipv6Ips -join ','))

        $apply14Raw = [System.IO.File]::ReadAllText((Join-Path $repo 'scripts\14-apply-policy.ps1'), [System.Text.Encoding]::UTF8)
        $mode07Updated = [System.IO.File]::ReadAllText((Join-Path $repo 'scripts\07-mode.ps1'), [System.Text.Encoding]::UTF8)
        $sync10Updated = [System.IO.File]::ReadAllText((Join-Path $repo 'scripts\10-sync-node-rule.ps1'), [System.Text.Encoding]::UTF8)
        $v6WireOk = ($apply14Raw -match '\$TemporaryIpv6') -and ($apply14Raw -match 'AI-Guard-Allow-DHCPv6') -and `
            ($apply14Raw -match 'AI-Guard-Allow-NDP') -and ($apply14Raw -match '0x20') -and `
            ($mode07Updated -match 'AI-Guard-Allow-DHCPv6') -and ($mode07Updated -match 'RA\[46\]=') -and `
            ($mode07Updated -match '/128') -and ($sync10Updated -match '-IncludeIpv6:\$allowIpv6Nodes') -and `
            ($sync10Updated -match '/128')
        Assert-True '14-apply-policy, 07-mode, and 10-sync-node-rule wire temporary IPv6 bootstrap, DisabledComponents=0x20, RA[46]=, and /128 host routes' `
            $v6WireOk 'temporary IPv6 wiring check failed'
    }
    finally {
        Remove-Item -LiteralPath $tmpDbDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ' '
if ($script:fail -gt 0) {
    Write-Host ('=== ' + $script:fail + ' assertion(s) FAILED ===') -ForegroundColor Red
    exit 1
}
Write-Host '=== all port-set assertions passed ===' -ForegroundColor Green
exit 0
