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
     11. a protocol-scoped preceding rule is a caveat, never a false SHADOWED.

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
$gui = Get-Content -LiteralPath (Join-Path (Join-Path $repo 'gui') 'MainWindow.xaml.cs') -Raw
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

Write-Host ' '
if ($script:fail -gt 0) {
    Write-Host ('=== ' + $script:fail + ' assertion(s) FAILED ===') -ForegroundColor Red
    exit 1
}
Write-Host '=== all port-set assertions passed ===' -ForegroundColor Green
exit 0
