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
      4. every consumer that calls a lib getter also dot-sources the lib.

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
    '02-killswitch.ps1', '07-mode.ps1', '14-apply-policy.ps1',
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

Write-Host ' '
if ($script:fail -gt 0) {
    Write-Host ('=== ' + $script:fail + ' assertion(s) FAILED ===') -ForegroundColor Red
    exit 1
}
Write-Host '=== all port-set assertions passed ===' -ForegroundColor Green
exit 0
