<#
.SYNOPSIS
    AI-Net-Guard v5.4 - regenerate cn-ipv4.txt from v2rayN's own geoip data.

.DESCRIPTION
    Reads the same geoip database that v2rayN's "bypass mainland China"
    routing uses (geoip-only-cn-private.dat, fallback geoip.dat), extracts the
    CN IPv4 prefixes, normalizes host bits, collapses overlapping/adjacent
    CIDR blocks, and atomically replaces <Root>\cn-ipv4.txt.

    v5.1 improvements:
      - Fast in-place protobuf country-code pre-scan (skips non-CN countries
        without allocating CIDR byte arrays; ~50x faster on full geoip.dat).
      - Host-bit normalization + numerical sort + lossless sibling/overlap
        CIDR aggregation (smaller WFP filter table, exact same IP coverage).
      - If parsing yields fewer than 1000 prefixes the old file is kept unchanged
        (a broken/truncated database must never shrink the allow list).
      - Atomic replace: write .tmp, validate, then Move-Item -Force.

    Called automatically by 07-mode.ps1 when the geo file is newer than
    cn-ipv4.txt, and by the 15-minute fallback task through it.
#>

[CmdletBinding()]
param(
    [string]$Root = $(if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\AI-Net-Guard' }),
    [string]$V2rayNRoot = '',
    [string]$GeoFile = '',
    [string]$OutFile = '',
    [switch]$Quiet,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
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
function Say($m) { if (-not $Quiet) { Write-Host $m } }

if (-not $OutFile) {
    $OutFile = Join-Path $Root 'cn-ipv4.txt'
}

$explicitGeo = $PSBoundParameters.ContainsKey('GeoFile') -and (-not [string]::IsNullOrWhiteSpace($GeoFile))
if (-not $explicitGeo) {
    $GeoFile = Join-Path $V2rayNRoot 'bin\geoip-only-cn-private.dat'
    if (-not (Test-Path -LiteralPath $GeoFile)) {
        $alt = Join-Path $V2rayNRoot 'bin\geoip.dat'
        if (Test-Path -LiteralPath $alt) { $GeoFile = $alt }
    }
}

if (-not (Test-Path -LiteralPath $GeoFile)) {
    Say ('geo file not found: ' + $GeoFile)
    exit 2
}

if (-not $Force -and (Test-Path -LiteralPath $OutFile) -and
    ((Get-Item -LiteralPath $OutFile).LastWriteTime -ge (Get-Item -LiteralPath $GeoFile).LastWriteTime)) {
    Say 'cn-ipv4.txt is up to date'
    exit 0
}

# ---------------------------------------------------------------- protobuf
function Read-Varint {
    param([byte[]]$Buf, [ref]$Pos, [int]$End)
    $result = [uint64]0
    $shift = 0
    while ($true) {
        if ($Pos.Value -ge $End) { throw 'truncated varint' }
        $b = $Buf[$Pos.Value]
        $Pos.Value = $Pos.Value + 1
        $result = $result -bor ([uint64]($b -band 0x7F) -shl $shift)
        if (($b -band 0x80) -eq 0) { return $result }
        $shift += 7
        if ($shift -gt 63) { throw 'varint too long' }
    }
}

function Skip-Field {
    param([byte[]]$Buf, [int]$WireType, [ref]$Pos, [int]$End)
    switch ($WireType) {
        0 { [void](Read-Varint -Buf $Buf -Pos $Pos -End $End) }
        1 { $Pos.Value += 8; if ($Pos.Value -gt $End) { throw 'truncated fixed64' } }
        2 {
            $len = [int](Read-Varint -Buf $Buf -Pos $Pos -End $End)
            if ($len -lt 0 -or ($Pos.Value + $len) -gt $End) { throw 'truncated length-delimited field' }
            $Pos.Value += $len
        }
        5 { $Pos.Value += 4; if ($Pos.Value -gt $End) { throw 'truncated fixed32' } }
        default { throw ('unsupported wire type ' + $WireType) }
    }
}

function Get-EntryCountryCode {
    param([byte[]]$Buf, [int]$Start, [int]$End)
    $pos = $Start
    while ($pos -lt $End) {
        $key = Read-Varint -Buf $Buf -Pos ([ref]$pos) -End $End
        $field = [int]($key -shr 3)
        $wt = [int]($key -band 7)
        if ($field -eq 1 -and $wt -eq 2) {
            $len = [int](Read-Varint -Buf $Buf -Pos ([ref]$pos) -End $End)
            if ($len -lt 0 -or ($pos + $len) -gt $End) { throw 'truncated country_code' }
            if ($len -eq 0) { return '' }
            return ([System.Text.Encoding]::ASCII.GetString($Buf, $pos, $len)).ToUpperInvariant()
        }
        Skip-Field -Buf $Buf -WireType $wt -Pos ([ref]$pos) -End $End
    }
    return ''
}

function Collapse-Ipv4Cidrs {
    param([System.Collections.Generic.List[uint64]]$PackedList)
    if ($PackedList.Count -eq 0) { return @() }
    $arr = $PackedList.ToArray()
    [Array]::Sort($arr)

    $netStack = New-Object System.Collections.Generic.List[uint64]
    $plenStack = New-Object System.Collections.Generic.List[int]
    $endStack = New-Object System.Collections.Generic.List[uint64]

    foreach ($item in $arr) {
        $net = [uint64]($item -shr 8)
        $plen = [int]($item -band 0xFF)
        $size = [uint64]1 -shl (32 - $plen)
        $end = $net + $size - [uint64]1

        $cnt = $netStack.Count
        if ($cnt -gt 0 -and $net -le $endStack[$cnt - 1]) {
            # Already covered by the current supernet/identical prefix on stack.
            continue
        }

        $netStack.Add($net)
        $plenStack.Add($plen)
        $endStack.Add($end)

        while ($netStack.Count -ge 2) {
            $top = $netStack.Count - 1
            $prev = $top - 1
            $p1 = $plenStack[$prev]
            $p2 = $plenStack[$top]
            if ($p1 -ne $p2 -or $p1 -le 0) { break }

            $parentPlen = $p1 - 1
            $parentMask = if ($parentPlen -eq 0) { [uint64]0 } else { (([uint64]4294967295 -shl (32 - $parentPlen)) -band [uint64]4294967295) }
            $n1 = $netStack[$prev]
            $e1 = $endStack[$prev]
            $n2 = $netStack[$top]
            $e2 = $endStack[$top]

            if ((($n1 -band $parentMask) -eq $n1) -and (($e1 + [uint64]1) -eq $n2)) {
                $netStack.RemoveAt($top)
                $plenStack.RemoveAt($top)
                $endStack.RemoveAt($top)
                $plenStack[$prev] = $parentPlen
                $endStack[$prev] = $e2
            }
            else {
                break
            }
        }
    }

    $out = New-Object System.Collections.Generic.List[string] ($netStack.Count)
    for ($i = 0; $i -lt $netStack.Count; $i++) {
        $n = $netStack[$i]
        $p = $plenStack[$i]
        $b0 = [int](($n -shr 24) -band 0xFF)
        $b1 = [int](($n -shr 16) -band 0xFF)
        $b2 = [int](($n -shr 8) -band 0xFF)
        $b3 = [int]($n -band 0xFF)
        $out.Add(('{0}.{1}.{2}.{3}/{4}' -f $b0, $b1, $b2, $b3, $p))
    }
    return ,$out
}

try {
    $bytes = [System.IO.File]::ReadAllBytes($GeoFile)
    $lenTotal = $bytes.Length
    $packedCidrs = New-Object System.Collections.Generic.List[uint64]
    $rawCount = 0

    $pos = 0
    while ($pos -lt $lenTotal) {
        $key = Read-Varint -Buf $bytes -Pos ([ref]$pos) -End $lenTotal
        $field = [int]($key -shr 3)
        $wt = [int]($key -band 7)
        if ($field -eq 1 -and $wt -eq 2) {
            $entryLen = [int](Read-Varint -Buf $bytes -Pos ([ref]$pos) -End $lenTotal)
            if ($entryLen -lt 0 -or ($pos + $entryLen) -gt $lenTotal) { throw 'truncated GeoIP entry' }
            $entryStart = $pos
            $entryEnd = $pos + $entryLen
            $pos = $entryEnd

            $cc = Get-EntryCountryCode -Buf $bytes -Start $entryStart -End $entryEnd
            if ($cc -ne 'CN') { continue }

            $ep = $entryStart
            while ($ep -lt $entryEnd) {
                $ekey = Read-Varint -Buf $bytes -Pos ([ref]$ep) -End $entryEnd
                $ef = [int]($ekey -shr 3)
                $ewt = [int]($ekey -band 7)
                if ($ef -eq 2 -and $ewt -eq 2) {
                    $cLen = [int](Read-Varint -Buf $bytes -Pos ([ref]$ep) -End $entryEnd)
                    if ($cLen -lt 0 -or ($ep + $cLen) -gt $entryEnd) { throw 'truncated CIDR entry' }
                    $cStart = $ep
                    $cEnd = $ep + $cLen
                    $ep = $cEnd

                    $cp = $cStart
                    $ipOffset = -1
                    $ipLen = -1
                    $plen = -1
                    while ($cp -lt $cEnd) {
                        $ckey = Read-Varint -Buf $bytes -Pos ([ref]$cp) -End $cEnd
                        $cf = [int]($ckey -shr 3)
                        $cwt = [int]($ckey -band 7)
                        if ($cf -eq 1 -and $cwt -eq 2) {
                            $ipLen = [int](Read-Varint -Buf $bytes -Pos ([ref]$cp) -End $cEnd)
                            if ($ipLen -lt 0 -or ($cp + $ipLen) -gt $cEnd) { throw 'truncated CIDR ip' }
                            $ipOffset = $cp
                            $cp += $ipLen
                        }
                        elseif ($cf -eq 2 -and $cwt -eq 0) {
                            $plen = [int](Read-Varint -Buf $bytes -Pos ([ref]$cp) -End $cEnd)
                        }
                        else {
                            Skip-Field -Buf $bytes -WireType $cwt -Pos ([ref]$cp) -End $cEnd
                        }
                    }

                    if ($ipLen -eq 4 -and $ipOffset -ge 0 -and $plen -ge 0 -and $plen -le 32) {
                        $rawCount++
                        $ip = ([uint64]$bytes[$ipOffset] -shl 24) -bor
                              ([uint64]$bytes[$ipOffset + 1] -shl 16) -bor
                              ([uint64]$bytes[$ipOffset + 2] -shl 8) -bor
                              ([uint64]$bytes[$ipOffset + 3])
                        $mask = if ($plen -eq 0) { [uint64]0 } else { (([uint64]4294967295 -shl (32 - $plen)) -band [uint64]4294967295) }
                        $net = $ip -band $mask
                        $packedCidrs.Add((($net -shl 8) -bor [uint64]$plen))
                    }
                }
                else {
                    Skip-Field -Buf $bytes -WireType $ewt -Pos ([ref]$ep) -End $entryEnd
                }
            }
        }
        else {
            Skip-Field -Buf $bytes -WireType $wt -Pos ([ref]$pos) -End $lenTotal
        }
    }

    $collapsed = Collapse-Ipv4Cidrs -PackedList $packedCidrs
}
catch {
    Say ('ERROR: failed parsing geoip database (' + $_.Exception.Message + ') - keeping the old list')
    exit 3
}

if ($collapsed.Count -lt 1000) {
    Say ('ERROR: parsed only ' + $collapsed.Count + ' prefixes - keeping the old list')
    exit 3
}

$outDir = Split-Path -Parent $OutFile
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$tmp = $OutFile + '.tmp'
$header = @(
    '# China mainland IPv4 prefixes (auto-generated from v2rayN geoip data)',
    ('# source: ' + (Split-Path -Leaf $GeoFile)),
    ('# generated: ' + (Get-Date).ToString('o')),
    ('# raw prefixes: ' + $rawCount + ', collapsed: ' + $collapsed.Count)
)
$all = New-Object System.Collections.Generic.List[string] ($collapsed.Count + 4)
foreach ($h in $header) { $all.Add($h) }
foreach ($c in $collapsed) { $all.Add($c) }
[System.IO.File]::WriteAllLines($tmp, $all, [System.Text.Encoding]::ASCII)
Move-Item -LiteralPath $tmp -Destination $OutFile -Force

Say ('cn-ipv4.txt updated: ' + $collapsed.Count + ' prefixes (raw ' + $rawCount + ', source ' + $GeoFile + ')')
exit 0
