# AI-Net-Guard - v2rayN routing-level STUN/TURN block (WebRTC leak guard, layer B)
# Pure ASCII script.
#
# Why this exists:
#   The firewall layer cannot stop a WebRTC leak on this host. Measured with an
#   independent STUN client (no browser involved): stun.miwifi.com and
#   stun.chat.bilibili.com still answered with the real ISP address while all eight
#   AI-Guard-Block-WebRTC-* rules were Active=TRUE, with the exact core path, the
#   exact STUN port list and the correct interface GUIDs. The chain is
#   app -> xray_tun -> core -> physical NIC, and the TUN provider terminates
#   ALE_AUTH_CONNECT for the core's own re-send with a PERMIT, so the firewall block
#   filters are never evaluated. Windows Firewall cannot win that comparison.
#
#   The only layer that sees the packet before it is re-sent is the core's own
#   routing table. v2rayN already ships a rule of exactly this shape ("block udp:443")
#   to kill QUIC, so the same mechanism is used here for the STUN/TURN port set:
#   the packet is dropped inside the core, nothing is sent anywhere, domestic direct
#   rules are untouched and proxy quota does not move by a single byte.
#
# Safety:
#   - Never writes while v2rayN or a core is running: v2rayN keeps the routing rules
#     in memory and would overwrite the database on exit.
#   - Backs up guiNDB.db to <Root>\backup\v2rayn-routing\<stamp>\ before touching it.
#   - Idempotent: rules tagged 'STUN-GUARD:' are stripped and re-inserted at the top.
#   - -Restore puts the newest backup back.
#
# .PARAMETER Root
#   Guard root, used only for the backup destination. Defaults to the parent of this
#   script folder, otherwise C:\AI-Net-Guard.
#
# .PARAMETER V2rayNRoot
#   v2rayN install folder that holds guiConfigs\guiNDB.db.
#
# .PARAMETER Apply
#   Insert the STUN/TURN block rules at the top of the active routing set.
#
# .PARAMETER Verify
#   Default action. Read-only: show the active routing set and whether the guard
#   rules are present.
#
# .PARAMETER Restore
#   Copy the newest backup of guiNDB.db back over the live database.
#
# .PARAMETER Force
#   Skip the "v2rayN is running" refusal. Only for a database you know is idle.
#
# .EXAMPLE
#   .\18-route-stun-guard.ps1
#   .\18-route-stun-guard.ps1 -Apply
#   .\18-route-stun-guard.ps1 -Restore
#
# .NOTES
#   Requires python 3 on PATH (sqlite3 is not available from PowerShell 5.1).
#   Exit codes: 0 ok, 1 error, 2 refused / not applicable, 3 verification failed.

[CmdletBinding()]
param(
    [string]$Root = '',
    [string]$V2rayNRoot = 'D:\v2rayN-windows-64-desktop\v2rayN-windows-64',
    [switch]$Apply,
    [switch]$Verify,
    [switch]$Restore,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# Same convention as 13/17: the install root is the PARENT of the script folder, so a run
# from C:\AI-Net-Guard\scripts puts backups in C:\AI-Net-Guard\backup instead of nesting a
# backup tree inside the shipped scripts directory.
if (-not $Root) {
    $selfDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    if ((Split-Path -Leaf $selfDir) -eq 'scripts') { $Root = Split-Path -Parent $selfDir } else { $Root = $selfDir }
}
$Root = $Root.TrimEnd('\')

# The routing database stores localised remarks. Child stdout is decoded with the console
# code page by default, which turns those into mojibake on a zh-CN host, so force UTF-8
# on both sides of the pipe.
$env:PYTHONIOENCODING = 'utf-8'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

# Kept in sync with 15-webrtc-browser-shield.ps1 and the AI-Guard-Block-WebRTC-* rules.
$StunPorts = '3478,3479,5349,5350,19302,19303,19304,19305,19306,19307,19308,19309'
$GuardTag = 'STUN-GUARD:'

function Say($msg, $color = 'Gray') { Write-Host $msg -ForegroundColor $color }

function Get-PythonExe {
    foreach ($cand in @('python', 'python3', 'py')) {
        $cmd = Get-Command $cand -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return ''
}

function Invoke-DbOp {
    param([string]$Op)

    $py = Get-PythonExe
    if (-not $py) { Say '[!] python 3 not found on PATH - cannot read guiNDB.db from PowerShell 5.1' 'Red'; exit 1 }

    $payload = @'
import json, sqlite3, sys

db, op, ports, tag = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

def connect():
    return sqlite3.connect(db, timeout=5)

def active_item(con):
    cur = con.cursor()
    cur.execute("SELECT Id, Remarks, RuleSet, RuleNum FROM RoutingItem WHERE IsActive=1")
    rows = cur.fetchall()
    if not rows:
        return None
    for r in rows:
        if 'Whit' in (r[1] or ''):
            return r
    return rows[0]

con = connect()
item = active_item(con)
if not item:
    print('NO_ACTIVE_ITEM')
    sys.exit(2)

item_id, remarks, ruleset, rule_num = item
rules = json.loads(ruleset or '[]')

if op == 'dump':
    print('ITEM\t%s\t%s\t%d' % (item_id, remarks, len(rules)))
    for i, x in enumerate(rules):
        print('RULE\t%d\t%s\t%s\t%s\t%s' % (
            i, x.get('OutboundTag') or '-', x.get('Remarks') or '-',
            x.get('Port') or '-', x.get('Network') or '-'))
    has = any(str(x.get('Remarks') or '').startswith(tag) for x in rules)
    print('GUARD\t%d' % (1 if has else 0))
    sys.exit(0)

if op == 'apply':
    kept = [x for x in rules if not str(x.get('Remarks') or '').startswith(tag)]
    removed = len(rules) - len(kept)
    block = [
        {
            'Id': '8800000000000000001',
            'Port': ports,
            'Network': 'udp',
            'OutboundTag': 'block',
            'Enabled': True,
            'Remarks': tag + ' block STUN/TURN UDP (anti WebRTC leak)',
        },
        {
            'Id': '8800000000000000002',
            'Port': ports,
            'Network': 'tcp',
            'OutboundTag': 'block',
            'Enabled': True,
            'Remarks': tag + ' block STUN/TURN TCP (anti WebRTC leak)',
        },
    ]
    final = block + kept
    cur = con.cursor()
    cur.execute("UPDATE RoutingItem SET RuleSet=?, RuleNum=? WHERE Id=?",
                (json.dumps(final, ensure_ascii=False), len(final), item_id))
    con.commit()
    print('APPLIED\t%s\t%d\t%d' % (item_id, len(final), removed))
    sys.exit(0)

print('UNKNOWN_OP')
sys.exit(2)
'@

    $tmp = Join-Path $env:TEMP ('aiguard-routing-' + [guid]::NewGuid().ToString('N') + '.py')
    try {
        [System.IO.File]::WriteAllText($tmp, $payload, (New-Object System.Text.UTF8Encoding($false)))
        $out = & $py $tmp $script:DbPath $Op $StunPorts $GuardTag 2>&1
        return [pscustomobject]@{ Code = $LASTEXITCODE; Lines = @($out) }
    }
    finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Get-RunningBlocker {
    foreach ($n in @('v2rayN', 'xray', 'sing-box', 'mihomo', 'mihomo-windows-amd64-v1')) {
        $p = @(Get-Process -Name $n -ErrorAction SilentlyContinue)
        if ($p.Count -gt 0) { return ($n + ' (pid ' + $p[0].Id + ')') }
    }
    return ''
}

# ------------------------------------------------------------------ main
$dbDir = Join-Path $V2rayNRoot 'guiConfigs'
$script:DbPath = Join-Path $dbDir 'guiNDB.db'

Say ' '
Say '=== AI-Net-Guard STUN routing guard (v2rayN layer) ===' 'Cyan'
Say ('v2rayN root : ' + $V2rayNRoot)
Say ('database    : ' + $script:DbPath)
Say ('STUN ports  : ' + $StunPorts)

if (-not (Test-Path -LiteralPath $script:DbPath)) {
    Say '[!] guiNDB.db not found - check -V2rayNRoot' 'Red'
    exit 1
}

if ($Restore) {
    $bkRoot = Join-Path $Root 'backup\v2rayn-routing'
    $newest = Get-ChildItem -Path $bkRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $newest) {
        Say '[!] no backup found under:' 'Red'
        Say ('    ' + $bkRoot) 'Red'
        exit 1
    }
    $src = Join-Path $newest.FullName 'guiNDB.db'
    if (-not (Test-Path -LiteralPath $src)) {
        Say '[!] backup folder has no guiNDB.db:' 'Red'
        Say ('    ' + $src) 'Red'
        exit 1
    }

    $blocker = Get-RunningBlocker
    if ($blocker -and -not $Force) {
        Say ('[!] ' + $blocker + ' is running - close v2rayN first (its memory copy would overwrite the restore)') 'Red'
        exit 2
    }
    Copy-Item -LiteralPath $src -Destination $script:DbPath -Force
    Say ('[+] restored guiNDB.db from ' + $newest.Name) 'Green'
    Say '    reopen v2rayN so the core regenerates its config' 'DarkGray'
    exit 0
}

$r = Invoke-DbOp 'dump'
if ($r.Code -ne 0) {
    Say ('[!] cannot read routing set (exit ' + $r.Code + ')') 'Red'
    $r.Lines | ForEach-Object { Say ('    ' + $_) 'DarkGray' }
    exit 1
}

$itemId = ''; $itemName = ''; $ruleCount = 0; $hasGuard = $false
$rows = @()
foreach ($line in $r.Lines) {
    $f = ([string]$line) -split "`t"
    switch ($f[0]) {
        'ITEM' { $itemId = $f[1]; $itemName = $f[2]; $ruleCount = [int]$f[3] }
        'RULE' { $rows += , $f }
        'GUARD' { $hasGuard = ([int]$f[1] -eq 1) }
        'NO_ACTIVE_ITEM' { Say '[!] no active routing item in the database' 'Red'; exit 2 }
    }
}

Say ' '
Say ('active set  : ' + $itemName + '  (id ' + $itemId + ', ' + $ruleCount + ' rules)') 'Cyan'
Say 'top rules   :'
$i = 0
foreach ($f in $rows) {
    if ($i -ge 6) { Say '    ...' 'DarkGray'; break }
    Say ('    [' + $f[1] + '] out=' + $f[2].PadRight(8) + ' net=' + $f[5].PadRight(5) + ' port=' + $f[4].PadRight(6) + ' ' + $f[3]) 'Gray'
    $i++
}

if (-not $Apply) {
    Say ' '
    if ($hasGuard) {
        Say '[+] STUN-GUARD rules present' 'Green'
        Say '    note: the running core only picks them up after a v2rayN restart' 'DarkGray'
        exit 0
    }
    Say '[i] STUN-GUARD rules absent - run: .\18-route-stun-guard.ps1 -Apply' 'Yellow'
    exit 0
}

# ------------------------------------------------------------------ apply
$blocker = Get-RunningBlocker
if ($blocker -and -not $Force) {
    Say ' '
    Say ('[!] ' + $blocker + ' is running') 'Red'
    Say '    v2rayN keeps the routing set in memory and overwrites guiNDB.db on exit,' 'Yellow'
    Say '    so the edit would be silently reverted. Close v2rayN completely, re-run' 'Yellow'
    Say '    this script, then start v2rayN again.' 'Yellow'
    exit 2
}

$bkDir = Join-Path $Root ('backup\v2rayn-routing\' + (Get-Date).ToString('yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $bkDir -Force | Out-Null
Copy-Item -LiteralPath $script:DbPath -Destination (Join-Path $bkDir 'guiNDB.db') -Force
Say ' '
Say ('[+] backup: ' + $bkDir) 'Green'

$a = Invoke-DbOp 'apply'
if ($a.Code -ne 0) {
    Say ('[!] apply failed (exit ' + $a.Code + ')') 'Red'
    $a.Lines | ForEach-Object { Say ('    ' + $_) 'DarkGray' }
    Say ('    database untouched: ' + $script:DbPath) 'DarkGray'
    exit 1
}
foreach ($line in $a.Lines) {
    $f = ([string]$line) -split "`t"
    if ($f[0] -eq 'APPLIED') {
        Say ('[+] inserted 2 STUN/TURN block rules at the top of "' + $itemName + '"') 'Green'
        Say ('    rules now: ' + $f[2] + '  (replaced ' + $f[3] + ' older guard rule(s))')
    }
}

$v = Invoke-DbOp 'dump'
$ok = $false
foreach ($line in $v.Lines) {
    $f = ([string]$line) -split "`t"
    if ($f[0] -eq 'GUARD' -and [int]$f[1] -eq 1) { $ok = $true }
}
if (-not $ok) { Say '[!] read-back did not find the guard rules - treat as failed' 'Red'; exit 3 }

Say ' '
Say 'next steps:' 'Cyan'
Say '  1. start v2rayN again (it regenerates the core config from the database)'
Say '  2. confirm the core config carries the rule:'
Say ('       Select-String -Path "' + (Join-Path $V2rayNRoot 'binConfigs\config.json') + '" -Pattern "3478"')
Say '  3. re-run the leak probe; CN STUN servers must stop answering with the real IP'
Say 'to roll back: .\18-route-stun-guard.ps1 -Restore' 'DarkGray'
exit 0
