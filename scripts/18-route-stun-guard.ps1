# AI-Net-Guard - v2rayN routing-level STUN/TURN block (WebRTC leak guard, layer B1)
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
#   routing table. v2rayN already ships a rule of exactly this shape - its generated
#   binConfigs\config.json starts with
#       {"port": "135,137-139,5353", "network": "udp", "outboundTag": "block"}
#   and the user set's first entry is {"Port":"443","Network":"udp",
#   "OutboundTag":"block"} - and QUIC really is dead on this host, so the mechanism
#   is proven. The same shape is used here for the STUN/TURN port set:
#   the packet is dropped inside the core, nothing is sent anywhere, domestic direct
#   rules are untouched and proxy quota does not move by a single byte.
#
#   DESIGN CHOICE - B1 (global port block), not B2 (per-target list):
#     These rules match on DESTINATION PORT ONLY and match every address. Consequence,
#     stated plainly because it drives the acceptance test: after -Apply, no STUN server
#     reachable on one of these ports answers, foreign ones included.
#     stun.l.google.com:19302 is dropped the same way stun.miwifi.com:3478 is.
#
#     SCOPE, stated just as plainly, because "STUN is blocked" would be an overclaim:
#     this guard covers the twelve ports below - 3478, 3479, 5349, 5350 and 19302-19309 -
#     over udp and tcp, for every destination. STUN/TURN carried on any other port (udp/443
#     is the common one) is NOT covered by these rules and remains reachable through the
#     normal routing table. Closing that class needs a different mechanism (a server list,
#     or blocking udp/443 outright, which breaks QUIC and HTTP/3 as well).
#
#     Within that scope a STUN socket whose packets actually traverse these rules gets no
#     reply, so a srflx candidate cannot be gathered from it and calls fall back to relay or
#     fail. "Actually traverse" carries two limits, both reported rather than hidden: a rule
#     ahead of the pair can take the packet first (surfaced as a caveat), and a port outside
#     the set is not covered at all. That is the intended trade: closing the real-IP leak matters more
#     than keeping WebRTC fully working. A B2 variant (match CN STUN ip/domain, block only
#     those) would keep foreign STUN alive but needs a maintained target list and leaves a
#     fail-open path whenever the list goes stale, so it is deliberately not implemented.
#
# Safety:
#   - Never writes while v2rayN or a core is running: v2rayN keeps the routing rules
#     in memory and would overwrite the database on exit.
#   - Refuses to touch a database that still has a non-empty -wal sidecar, and checks this
#     before opening it at all: measured on this host, opening guiNDB.db with sqlite3 is
#     enough to delete a leftover -wal, so a check placed after the first read would never
#     fire. The newest routing edits can live only in that sidecar, and a plain file copy
#     would take the stale main file. guiNDB.db normally runs journal_mode=delete, so this
#     is a "v2rayN did not exit cleanly" alarm, not the common path.
#   - Backs up guiNDB.db to <Root>\backup\v2rayn-routing\<stamp>\ before touching it,
#     then proves the copy is readable (PRAGMA quick_check + per-rule JSON equality)
#     before the first write. A failed backup aborts the run.
#   - Refuses to guess which routing set is active: exactly one row may have
#     IsActive=1, otherwise -RoutingId is required. A wrong pick silently edits the
#     wrong set. The resolved Id is then carried through every later call - apply,
#     compare and the restore comparison - so the row that was inspected is always the
#     row that is written, even if IsActive changes in between.
#   - Refuses to write when a rule that is not ours already owns one of the two fixed
#     guard Ids. Reusing an occupied Id would make v2rayN treat two rows as the same
#     rule and could drop or corrupt the other one.
#   - Idempotent: rules tagged 'STUN-GUARD:' are stripped and re-inserted at the top.
#   - After the write it re-reads the database and asserts (a) the two guard rules sit
#     at index 0 and 1, (b) every other rule still carries exactly the same keys and
#     values as in the backup, in the same order, so "nothing else was touched" is a
#     checked fact. The comparison is on parsed objects, not raw bytes: the RuleSet is
#     re-serialised as a whole when written, so the formatting of untouched rules may
#     change while their content does not.
#   - -Restore snapshots the live database to <Root>\backup\v2rayn-restore-pre\<stamp>\
#     first, so a restore that turns out to be unwanted is itself undoable. It then
#     copies the newest backup that does NOT already contain guard rules back, and
#     verifies the result the same way; success is never printed unless the live
#     database matches that backup. Picking the newest backup blindly would restore a
#     state that still carries the block, which looks like a rollback but changes nothing.
#
# .PARAMETER Root
#   Guard root, used only for the backup destination. Defaults to the parent of this
#   script folder, otherwise C:\AI-Net-Guard.
#
# .PARAMETER V2rayNRoot
#   v2rayN install folder that holds guiConfigs\guiNDB.db and binConfigs\config.json.
#
# .PARAMETER Apply
#   Insert the STUN/TURN block rules at the top of the active routing set.
#
# .PARAMETER Verify
#   Default action. Read-only: show the active routing set, whether the guard rules
#   are in the database, and whether the running core config actually carries both of
#   them with the complete port set.
#
# .PARAMETER Restore
#   Copy the newest backup (or -BackupDir) of guiNDB.db back over the live database
#   and verify the restore. The pre-restore state is snapshotted first.
#
# .PARAMETER RoutingId
#   Target this routing set by Id instead of relying on IsActive. Needed only when
#   the database reports more than one active set.
#
# .PARAMETER BackupDir
#   Explicit backup folder to restore from. Defaults to the newest under
#   <Root>\backup\v2rayn-routing.
#
# There is deliberately NO -Force switch. Two of the refusals below are not preferences
# but data-integrity gates, and a switch that skips them turns "the script protects your
# routing table" into "the script protects it unless you are in a hurry":
#   - a non-empty guiNDB.db-wal means the newest transactions are not in the main file,
#     so a backup or a restore that copies guiNDB.db alone would silently drop them;
#   - a running v2rayN/core holds the routing set in memory and rewrites the database on
#     exit, so any write made past it is reverted, and any restore made under it can be
#     overwritten mid-flight.
# Both are fixed by closing v2rayN (which checkpoints the WAL and releases the file), so
# there is nothing a bypass could rescue.
#
# .EXAMPLE
#   .\18-route-stun-guard.ps1
#   .\18-route-stun-guard.ps1 -Apply
#   .\18-route-stun-guard.ps1 -Restore
#
# .NOTES
#   Requires python 3 on PATH (sqlite3 is not available from PowerShell 5.1).
#   Exit codes: 0 ok, 1 error, 2 refused / not applicable, 3 verification failed,
#   4 a guard rule Id is already used by another rule.

[CmdletBinding()]
param(
    [string]$Root = '',
    [string]$V2rayNRoot = '',
    [switch]$Apply,
    [switch]$Verify,
    [switch]$Restore,
    [string]$RoutingId = '',
    [string]$BackupDir = ''
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

if (-not $V2rayNRoot) {
    $polFile = Join-Path $Root 'backup\guard-policy.json'
    if (Test-Path -LiteralPath $polFile) {
        try {
            $polObj = Get-Content -LiteralPath $polFile -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($polObj -and $polObj.V2rayNRoot -and (Test-Path -LiteralPath $polObj.V2rayNRoot)) {
                $V2rayNRoot = [string]$polObj.V2rayNRoot
            }
        } catch { }
    }
}
if (-not $V2rayNRoot) {
    if ($env:V2RAYN_ROOT -and (Test-Path -LiteralPath $env:V2RAYN_ROOT)) { $V2rayNRoot = $env:V2RAYN_ROOT }
    else {
        foreach ($cand in @('D:\v2rayN-windows-64-desktop\v2rayN-windows-64', 'D:\v2rayN-windows-64-desktop', 'C:\v2rayN-windows-64-desktop\v2rayN-windows-64', 'C:\v2rayN-windows-64', 'D:\v2rayN-windows-64', 'C:\v2rayN', 'D:\v2rayN', (Join-Path $env:LOCALAPPDATA 'v2rayN'), 'C:\Program Files\v2rayN')) {
            if ($cand -and ((Test-Path -LiteralPath (Join-Path $cand 'v2rayN.exe')) -or (Test-Path -LiteralPath (Join-Path $cand 'binConfigs')))) { $V2rayNRoot = $cand; break }
        }
        if (-not $V2rayNRoot) { try { $vp = [System.Diagnostics.Process]::GetProcessesByName('v2rayN'); if ($vp.Length -gt 0 -and $vp[0].MainModule.FileName) { $V2rayNRoot = Split-Path -Parent $vp[0].MainModule.FileName } } catch { } }
        if (-not $V2rayNRoot) { $V2rayNRoot = 'C:\v2rayN-windows-64' }
    }
}

# The routing database stores localised remarks. Child stdout is decoded with the console
# code page by default, which turns those into mojibake on a zh-CN host, so force UTF-8
# on both sides of the pipe.
$env:PYTHONIOENCODING = 'utf-8'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$GuardTag = 'STUN-GUARD:'
$V2Config = Join-Path $V2rayNRoot 'binConfigs\config.json'

function Say($msg, $color = 'Gray') { Write-Host $msg -ForegroundColor $color }

# ---------------------------------------------------------------- shared guard logic
# The port set AND the config checks live in lib-stun-guard.ps1, not here. Two reasons:
#
#   * The port list used to be a literal in this file, in 02-killswitch, in 07-mode twice,
#     in 14-apply-policy, in 15-webrtc-browser-shield twice and in verify-leak-test. That
#     is seven chances for the firewall rule and the routing rule to cover different ports
#     while both report healthy.
#   * verify-leak-test.ps1 asks the same questions about the same config.json. Two copies of
#     the checks is how one script reports SHADOWED while the other reports PASS.
#
# Loaded here (before any database call) rather than further down, because the port value
# is passed into every database operation.
$libPath = Join-Path $(if ($PSScriptRoot) { $PSScriptRoot } else { (Split-Path -Parent $PSCommandPath) }) 'lib-stun-guard.ps1'
if (-not (Test-Path -LiteralPath $libPath)) {
    Say ('[!] lib-stun-guard.ps1 not found next to this script: ' + $libPath) 'Red'
    Say '    the guard checks and the port set are shared and cannot be skipped' 'Yellow'
    exit 1
}
. $libPath
$StunPorts = Get-StunGuardPortSpec

function Get-PythonExe {
    foreach ($cand in @('python', 'python3', 'py')) {
        $cmd = Get-Command $cand -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return ''
}

function Invoke-DbOp {
    param([string]$Op, [string]$Extra = '', [string]$Mode = '', [string]$Id = '')

    $py = Get-PythonExe
    if (-not $py) { Say '[!] python 3 not found on PATH - cannot read guiNDB.db from PowerShell 5.1' 'Red'; exit 1 }

    $payload = @'
import hashlib
import json
import sqlite3
import sys

db, op, ports, tag = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

# Options are NAMED, not positional, on purpose. PowerShell drops empty-string arguments
# when it splats an array onto a native command, so a positional tail where only some slots
# are filled silently shifts every value one place left: the routing id would arrive where
# the backup path is expected, and the write would then target whatever row happened to be
# active instead of the row that was inspected. Named options cannot be shifted.
opts = {}
for a in sys.argv[5:]:
    if a.startswith('--') and '=' in a:
        k, v = a[2:].split('=', 1)
        opts[k] = v
extra = opts.get('backup', '')
mode_arg = opts.get('mode', '')
routing_id = opts.get('routing-id', '')

wanted = set(int(p) for p in ports.split(',') if p.strip())
GUARD_IDS = ('8800000000000000001', '8800000000000000002')
# Everything except the one UPDATE runs on a read-only connection, so "does not touch your
# database" is enforced by SQLite rather than by careful coding.
READONLY_OPS = ('dump', 'compare')


def open_db(path, readonly=False):
    if readonly:
        uri = 'file:%s?mode=ro' % path.replace('%', '%25').replace('?', '%3f').replace('#', '%23')
        con = sqlite3.connect(uri, uri=True, timeout=5)
    else:
        con = sqlite3.connect(path, timeout=5)
    con.row_factory = sqlite3.Row
    # A structurally broken file has to be caught HERE, before it is copied over the live
    # database or before a restore overwrites anything. quick_check is the cheap sibling of
    # integrity_check: exactly one row holding 'ok' when sound, otherwise one row per
    # complaint. Note this is a real check, not a comment describing one.
    rows = [tuple(r) for r in con.execute('PRAGMA quick_check').fetchall()]
    if rows != [('ok',)]:
        con.close()
        raise RuntimeError('quick_check: %s' % (rows[:3],))
    return con


def read_rows(con):
    cur = con.cursor()
    cur.execute('SELECT Id, Remarks, RuleSet, RuleNum, Enabled, Locked, Url, Sort, IsActive FROM RoutingItem')
    return cur.fetchall()


def pick(rows):
    """Return (row, how) without ever guessing when the database is ambiguous.

    routing_id wins for EVERY operation, not just for the first read. Resolving it only in
    dump/apply meant a run could inspect set A and then write set B: the ambiguity check
    passed, the read picked the id the operator named, and the UPDATE re-derived the target
    from IsActive and edited whatever was active instead.
    """
    if routing_id:
        for r in rows:
            if str(r['Id']) == routing_id:
                return r, 'explicit-id'
        return None, 'ID_NOT_FOUND'
    active = [r for r in rows if r['IsActive'] == 1]
    if len(active) == 1:
        return active[0], 'isactive'
    if len(active) > 1:
        return active, 'AMBIGUOUS'
    return None, 'NO_ACTIVE_ITEM'


def guard(rules):
    return [i for i, x in enumerate(rules) if str(x.get('Remarks') or '').startswith(tag)]


def canon(x):
    return json.dumps(x, ensure_ascii=False, sort_keys=True)


try:
    con = open_db(db, readonly=(op in READONLY_OPS))
    rows = read_rows(con)
except (RuntimeError, sqlite3.Error) as exc:
    print('DB_UNUSABLE\t%s' % exc)
    sys.exit(3)

row, how = pick(rows)

if how in ('NO_ACTIVE_ITEM', 'ID_NOT_FOUND'):
    print(how)
    sys.exit(2)
if how == 'AMBIGUOUS':
    print('AMBIGUOUS\t' + ' ; '.join('%s (%s)' % (r['Id'], r['Remarks']) for r in row))
    sys.exit(2)

item_id = str(row['Id'])
remarks = row['Remarks'] or ''
rules = json.loads(row['RuleSet'] or '[]')
idx = guard(rules)

if op == 'dump':
    print('ITEM\t%s\t%s\t%d\t%d\t%d\t%s\t%s' % (
        item_id, remarks, len(rules), row['Enabled'], row['Locked'], row['Url'] or '', how))
    for i, x in enumerate(rules):
        print('RULE\t%d\t%s\t%s\t%s\t%s' % (
            i, x.get('OutboundTag') or '-', x.get('Network') or '-',
            x.get('Port') or '-', x.get('Remarks') or '-'))
    print('GUARD\t%s' % (','.join(str(i) for i in idx) if idx else 'none'))
    sys.exit(0)

if op == 'apply':
    kept = [x for x in rules if not str(x.get('Remarks') or '').startswith(tag)]
    removed = len(rules) - len(kept)
    # Ids are reused on every apply so a second apply replaces rather than duplicates.
    # That is only safe while nobody else owns them.
    for x in kept:
        xid = str(x.get('Id') or '')
        if xid in GUARD_IDS:
            print('ID_CONFLICT\t%s\t%s' % (xid, canon(x)[:200]))
            sys.exit(4)
    block = [
        {
            'Enabled': True,
            'Id': GUARD_IDS[0],
            'Network': 'udp',
            'OutboundTag': 'block',
            'Port': ports,
            'Remarks': tag + ' block STUN/TURN UDP (anti WebRTC leak, B1 all hosts)',
        },
        {
            'Enabled': True,
            'Id': GUARD_IDS[1],
            'Network': 'tcp',
            'OutboundTag': 'block',
            'Port': ports,
            'Remarks': tag + ' block STUN/TURN TCP (anti WebRTC leak, B1 all hosts)',
        },
    ]
    final = block + kept
    cur = con.cursor()
    cur.execute('UPDATE RoutingItem SET RuleSet=?, RuleNum=? WHERE Id=?',
                (json.dumps(final, ensure_ascii=False, sort_keys=True), len(final), item_id))
    con.commit()
    print('APPLIED\t%s\t%d\t%d' % (item_id, len(final), removed))
    sys.exit(0)

if op == 'compare':
    # extra = backup database path. 'applied' asserts two guard rules on top plus every
    # other rule identical to the backup; 'restored' asserts the live set is identical to
    # the backup in full (guard included or not - restoring a backup that was taken after
    # an earlier apply legitimately brings the guard rules back).
    mode = mode_arg if mode_arg else 'restored'
    try:
        bak = open_db(extra, readonly=True)
        brows = read_rows(bak)
    except (RuntimeError, sqlite3.Error) as exc:
        print('BACKUP_UNUSABLE\t%s' % exc)
        sys.exit(3)
    brow, bhow = pick(brows)
    if brow is None or bhow == 'AMBIGUOUS':
        print('BACKUP_UNREADABLE\t%s' % bhow)
        sys.exit(3)
    # Both sides must be the same routing set, otherwise "the other rules are unchanged"
    # is comparing two different tables and the assertion means nothing.
    if str(brow['Id']) != item_id:
        print('BACKUP_OTHER_ITEM\t%s\t%s' % (item_id, brow['Id']))
        sys.exit(3)
    brules = json.loads(brow['RuleSet'] or '[]')
    bguard = len(guard(brules))

    if mode == 'applied':
        if len(rules) < 2 or idx[:2] != [0, 1]:
            print('GUARD_NOT_ON_TOP\t%s' % (','.join(str(i) for i in idx) or 'none'))
            sys.exit(3)
        for pos, net in ((0, 'udp'), (1, 'tcp')):
            g = rules[pos]
            got = set(int(p) for p in str(g.get('Port') or '').split(',') if p.strip())
            if (g.get('OutboundTag') != 'block' or g.get('Network') != net
                    or g.get('Enabled') is not True or got != wanted):
                print('GUARD_RULE_BAD\t%d\t%s' % (pos, canon(g)))
                sys.exit(3)
            if str(g.get('Id') or '') != GUARD_IDS[pos]:
                print('GUARD_ID_BAD\t%d\t%s' % (pos, g.get('Id')))
                sys.exit(3)
        if len(idx) != 2:
            print('GUARD_EXTRA_COPIES\t%s' % ','.join(str(i) for i in idx[2:]))
            sys.exit(3)
        # The backup may itself carry guard rules from an earlier apply, so both sides of
        # the comparison are taken without them: the claim under test is "the user's own
        # rules are untouched", not "the backup was pristine".
        rest = [x for x in rules if not str(x.get('Remarks') or '').startswith(tag)]
        ref = [x for x in brules if not str(x.get('Remarks') or '').startswith(tag)]
    else:
        rest = rules
        ref = brules

    if len(rest) != len(ref):
        print('RULE_COUNT_DIFFERS\t%d\t%d' % (len(rest), len(ref)))
        sys.exit(3)
    for i, (a, b) in enumerate(zip(rest, ref)):
        if canon(a) != canon(b):
            print('RULE_DIFFERS\t%d\t%s\t%s' % (i, canon(a)[:120], canon(b)[:120]))
            sys.exit(3)
    print('MATCH\t%d\t%d' % (len(rest), bguard))
    sys.exit(0)

print('UNKNOWN_OP')
sys.exit(2)
'@

    $tmp = Join-Path $env:TEMP ('aiguard-routing-' + [guid]::NewGuid().ToString('N') + '.py')
    try {
        [System.IO.File]::WriteAllText($tmp, $payload, (New-Object System.Text.UTF8Encoding($false)))
        $argv = @($tmp, $script:DbPath, $Op, $StunPorts, $GuardTag)
        if ($Extra) { $argv += ('--backup=' + $Extra) }
        if ($Mode) { $argv += ('--mode=' + $Mode) }
        if ($Id) { $argv += ('--routing-id=' + $Id) }
        $out = & $py @argv 2>&1
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

function Get-FileSha([string]$Path) {
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower() } catch { return '' }
}

# ---------------------------------------------------------------- core config checks
# A database row proves nothing until v2rayN has regenerated the core config from it, so
# the loaded table is checked directly. The checks themselves live in lib-stun-guard.ps1
# because verify-leak-test.ps1 asks the same questions: two copies of this logic is how
# one script reports SHADOWED while the other reports PASS for the same config file.
function Get-ExpectedPortSet {
    # Unrolled int[]: the only caller binds this straight into [int[]]$Expected, and a
    # unary comma here would make '@(Get-ExpectedPortSet)' see Count=1 (one nested array)
    # for anyone who adds a second caller later. Plain @() keeps the shape obvious.
    return @(Get-StunGuardPorts)
}

function Get-CoreGuardState {
    return Get-StunGuardAnalysis -ConfigPath $V2Config -Expected (Get-ExpectedPortSet)
}

# ------------------------------------------------------------------ main
$dbDir = Join-Path $V2rayNRoot 'guiConfigs'
$script:DbPath = Join-Path $dbDir 'guiNDB.db'

Say ' '
Say '=== AI-Net-Guard STUN routing guard (v2rayN layer, B1) ===' 'Cyan'
Say ('v2rayN root : ' + $V2rayNRoot)
Say ('database    : ' + $script:DbPath)
Say ('STUN ports  : ' + $StunPorts)
Say 'design      : B1, port-only match on every host - foreign STUN is dropped too'

if (-not (Test-Path -LiteralPath $script:DbPath)) {
    Say '[!] guiNDB.db not found - check -V2rayNRoot' 'Red'
    exit 1
}

# ------------------------------------------------------------------ pending WAL
# This has to come before ANY sqlite connection, including the read-only dump. Measured on
# this host: merely opening guiNDB.db with sqlite3 deletes a leftover -wal sidecar, so a
# check placed after the first read would always report "no WAL" and never fire. It also
# guards -Verify and -Restore: reading or overwriting a database whose newest transactions
# sit in the WAL is exactly what must not happen silently.
$walPath = $script:DbPath + '-wal'
$walSize = 0
if (Test-Path -LiteralPath $walPath) { $walSize = (Get-Item -LiteralPath $walPath).Length }
# Unconditional, with no switch to pass it. A non-empty WAL means the newest routing edits
# are NOT in guiNDB.db, so neither the backup taken by -Apply nor the overwrite done by
# -Restore can be correct: one would miss the edits, the other would erase them. There is
# no "I know better" case here, because closing v2rayN is what checkpoints the WAL.
if ($walSize -gt 0) {
    Say ' '
    Say ('[!] guiNDB.db-wal is present and not empty (' + $walSize + ' bytes)') 'Red'
    Say '    v2rayN did not close cleanly, so the newest routing edits may live only in' 'Yellow'
    Say '    that sidecar file and not in the main database.' 'Yellow'
    Say '    start v2rayN once and exit it from the tray icon so the WAL is checkpointed,' 'Yellow'
    Say '    then re-run. Nothing has been read or written yet.' 'Yellow'
    Say '    (this refusal has no bypass: a backup or a restore taken now would be wrong)' 'Yellow'
    exit 2
}

# ------------------------------------------------------------------ restore
if ($Restore) {
    $liveDb = $script:DbPath

    function Get-GuardCount([string]$DbFile) {
        $keep = $script:DbPath
        $script:DbPath = $DbFile
        $d = Invoke-DbOp 'dump'
        $script:DbPath = $keep
        if ($d.Code -ne 0) { return -1 }
        $g = [string](@($d.Lines | ForEach-Object { [string]$_ } | Where-Object { $_ -like 'GUARD*' })[0])
        if ($g -like '*none') { return 0 }
        return (@(($g -replace '^GUARD\s*', '') -split ',') | Where-Object { $_ }).Count
    }

    $bkDir = $BackupDir
    if (-not $bkDir) {
        # Prefer the newest backup that does NOT already contain the guard rules: restoring
        # the newest one after two applies just brings the block straight back, which looks
        # like a successful rollback while changing nothing.
        $bkRoot = Join-Path $Root 'backup\v2rayn-routing'
        $cands = @(Get-ChildItem -Path $bkRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
        $clean = $null
        $anyOk = $null
        foreach ($c in $cands) {
            $p = Join-Path $c.FullName 'guiNDB.db'
            if (-not (Test-Path -LiteralPath $p)) { continue }
            if ($null -eq $anyOk) { $anyOk = $c }
            if ((Get-GuardCount $p) -eq 0) { $clean = $c; break }
        }
        if ($clean) {
            $bkDir = $clean.FullName
        }
        elseif ($anyOk) {
            $bkDir = $anyOk.FullName
            Say '[!] every backup already carries STUN-GUARD rules - the newest one is used,' 'Yellow'
            Say '    so the guard will still be in place after this restore.' 'Yellow'
        }
        if ($clean -and $anyOk -and $clean.FullName -ne $anyOk.FullName) {
            Say ('[i] newest backup ' + $anyOk.Name + ' already had the guard; using the clean one ' + $clean.Name) 'DarkGray'
        }
    }
    if (-not $bkDir -or -not (Test-Path -LiteralPath $bkDir)) {
        Say '[!] no backup folder found.' 'Red'
        Say ('    looked under: ' + (Join-Path $Root 'backup\v2rayn-routing')) 'Red'
        exit 1
    }
    $src = Join-Path $bkDir 'guiNDB.db'
    if (-not (Test-Path -LiteralPath $src)) {
        Say ('[!] backup folder has no guiNDB.db: ' + $src) 'Red'
        exit 1
    }

    $blocker = Get-RunningBlocker
    # No bypass. A restore under a running v2rayN is not merely likely to be reverted: the
    # core holds guiNDB.db open and writes the in-memory routing set back on exit, so the
    # restored file can be overwritten seconds later with the state we just removed.
    if ($blocker) {
        Say ('[!] ' + $blocker + ' is running - close v2rayN first (its memory copy would overwrite the restore)') 'Red'
        Say '    this refusal has no bypass' 'Yellow'
        exit 2
    }

    # Prove the backup opens and parses before it replaces anything. This runs quick_check
    # too, so a corrupt file is rejected here rather than discovered afterwards with the
    # live database already gone.
    $script:DbPath = $src
    $probe = Invoke-DbOp 'dump'
    $script:DbPath = $liveDb
    if ($probe.Code -ne 0) {
        Say '[!] backup is not a usable routing database - restore aborted, live database untouched' 'Red'
        $probe.Lines | ForEach-Object { Say ('    ' + $_) 'DarkGray' }
        exit 3
    }
    # The routing set inside the backup is the one this restore is about; every later
    # comparison is pinned to it instead of re-deriving the target from IsActive.
    $bkItemId = ''
    foreach ($ln in $probe.Lines) {
        $f = ([string]$ln) -split "`t"
        if ($f[0] -eq 'ITEM') { $bkItemId = $f[1] }
    }
    Say ' '
    Say ('[*] backup    : ' + $bkDir) 'DarkGray'
    Say ('    sha256   : ' + (Get-FileSha $src)) 'DarkGray'

    # Snapshot the live database before overwriting it. Without this, a restore that has to
    # be undone leaves no way back: the "backup" being restored is the older state, and the
    # current state would exist nowhere. Kept in a sibling tree so the "newest clean backup"
    # discovery above never picks a snapshot up as a restore source.
    $preDir = Join-Path $Root ('backup\v2rayn-restore-pre\' + (Get-Date).ToString('yyyyMMdd-HHmmss'))
    $preFile = Join-Path $preDir 'guiNDB.db'
    # Hash the live file BEFORE copying, then prove the copy carries the same hash. A
    # Copy-Item that returns without an exception is not evidence: a partial read, a
    # concurrent writer or a locked file can all leave a shortened copy behind, and this
    # snapshot is the only way back if the restore turns out to be wrong.
    $liveBefore = Get-FileSha $liveDb
    try {
        New-Item -ItemType Directory -Path $preDir -Force | Out-Null
        Copy-Item -LiteralPath $liveDb -Destination $preFile -Force
    }
    catch {
        Say '[!] cannot snapshot the current database - restore aborted, nothing was written' 'Red'
        Say ('    ' + $_.Exception.Message) 'DarkGray'
        exit 2
    }
    $preSha = Get-FileSha $preFile
    if (-not $liveBefore -or -not $preSha -or $liveBefore -ne $preSha) {
        Say '[!] pre-restore snapshot does not match the live database - restore aborted' 'Red'
        Say ('    live     : ' + $liveBefore) 'DarkGray'
        Say ('    snapshot : ' + $preSha) 'DarkGray'
        Say '    nothing was overwritten; the snapshot is incomplete and cannot be trusted' 'Yellow'
        exit 3
    }
    Say ('[+] pre-restore snapshot: ' + $preFile) 'DarkGray'
    Say ('    sha256   : ' + $preSha + '  (identical to the live database)') 'DarkGray'

    try { Copy-Item -LiteralPath $src -Destination $liveDb -Force }
    catch {
        Say '[!] cannot write guiNDB.db - a core process still holds it' 'Red'
        Say ('    ' + $_.Exception.Message) 'DarkGray'
        Say ('    the live database was not modified; snapshot at ' + $preFile) 'DarkGray'
        exit 2
    }
    Say '[+] copied backup over the live database' 'Green'

    # Whole-file identity first: the restore is a file copy, so the bytes must be equal.
    # The per-rule comparison below says the rules match; this says the file does.
    $srcSha = Get-FileSha $src
    $liveAfter = Get-FileSha $liveDb
    if (-not $srcSha -or -not $liveAfter -or $srcSha -ne $liveAfter) {
        Say '[!] restored file is not byte-identical to the backup - restore FAILED' 'Red'
        Say ('    backup   : ' + $srcSha) 'DarkGray'
        Say ('    live     : ' + $liveAfter) 'DarkGray'
        Say ('    pre-restore snapshot : ' + $preFile) 'DarkGray'
        Say ('    to go back: copy that file over ' + $liveDb) 'Yellow'
        exit 3
    }

    $v = Invoke-DbOp 'compare' -Extra $src -Id $bkItemId
    $lines = @($v.Lines | ForEach-Object { [string]$_ })
    if ($v.Code -ne 0 -or -not ($lines -match '^MATCH')) {
        Say '[!] restore verification FAILED - the live database does not match the backup' 'Red'
        $lines | ForEach-Object { Say ('    ' + $_) 'DarkGray' }
        Say ('    pre-restore sha256   : ' + $liveBefore) 'DarkGray'
        Say ('    pre-restore snapshot : ' + $preFile) 'DarkGray'
        Say ('    to go back: copy that file over ' + $liveDb) 'Yellow'
        exit 3
    }
    $m = ($lines | Where-Object { $_ -match '^MATCH' }) -split "`t"
    Say ('[+] verified: ' + $m[1] + ' rule(s) identical in content to the backup') 'Green'
    if ([int]$m[2] -gt 0) {
        Say ('[!] this backup still contained ' + $m[2] + ' STUN-GUARD rule(s) - the guard is back in place') 'Yellow'
    }
    else {
        Say '[+] the restored set carries no STUN-GUARD rule - the block is fully undone' 'Green'
    }
    Say ('    live sha256: ' + (Get-FileSha $liveDb)) 'DarkGray'

    # A restore replaces the main file only. Any journal sidecar still sitting next to it
    # describes the database that was just replaced, and the next client to open the file
    # would try to roll it in - silently undoing the restore or corrupting the result. The
    # pre-flight check refused to start with a non-empty -wal, so this ASSERTS the restore
    # left nothing behind rather than assuming it. This runs after every sqlite call on
    # purpose: a connection can itself clear a sidecar, which would hide the evidence.
    $stale = @()
    foreach ($sfx in @('-wal', '-journal', '-shm')) {
        $f = $liveDb + $sfx
        if (Test-Path -LiteralPath $f) {
            $len = 0
            try { $len = (Get-Item -LiteralPath $f).Length } catch { $len = -1 }
            $stale += ('' + $sfx + '(' + $len + 'B)')
        }
    }
    if ($stale.Count -gt 0) {
        Say ('[!] journal sidecar(s) survived the restore: ' + ($stale -join ', ')) 'Red'
        Say '    they belong to the state that was just replaced; replaying them would undo' 'Yellow'
        Say '    this restore. Remove them before starting v2rayN:' 'Yellow'
        Say ('      Remove-Item -LiteralPath "' + $liveDb + '-wal","' + $liveDb + '-shm","' + $liveDb + '-journal" -ErrorAction SilentlyContinue') 'DarkGray'
        Say ('    pre-restore snapshot : ' + $preFile) 'DarkGray'
        exit 3
    }
    Say '[+] no journal sidecar next to the database - the restored file is the whole story' 'Green'

    Say ('    undo this restore by copying ' + $preFile) 'DarkGray'
    Say '    reopen v2rayN so the core regenerates its config' 'DarkGray'
    exit 0
}

# ------------------------------------------------------------------ read
$r = Invoke-DbOp 'dump' -Id $RoutingId
if ($r.Code -ne 0) {
    $first = [string](@($r.Lines)[0])
    if ($first -eq 'NO_ACTIVE_ITEM') {
        Say '[!] no routing set is marked active in the database' 'Red'
        Say '    open v2rayN, select a routing set, close v2rayN, re-run' 'Yellow'
    }
    elseif ($first -like 'AMBIGUOUS*') {
        Say '[!] more than one routing set reports IsActive=1 - refusing to guess' 'Red'
        Say ('    ' + $first.Split("`t")[1]) 'DarkGray'
        Say '    pick the one you actually use and pass -RoutingId <id>' 'Yellow'
    }
    elseif ($first -eq 'ID_NOT_FOUND') {
        Say ('[!] -RoutingId ' + $RoutingId + ' does not exist in guiNDB.db') 'Red'
    }
    elseif ($first -like 'DB_UNUSABLE*') {
        Say '[!] guiNDB.db failed SQLite quick_check - the file is damaged' 'Red'
        Say ('    ' + $first) 'DarkGray'
        Say '    restore a backup with -Restore before changing anything else' 'Yellow'
    }
    else {
        Say ('[!] cannot read routing set (exit ' + $r.Code + ')') 'Red'
        $r.Lines | ForEach-Object { Say ('    ' + $_) 'DarkGray' }
    }
    exit 2
}

$itemId = ''; $itemName = ''; $ruleCount = 0; $itemEnabled = 1; $itemLocked = 0
$itemUrl = ''; $pickedBy = ''; $guardIdx = ''
$rows = @()
foreach ($line in $r.Lines) {
    $f = ([string]$line) -split "`t"
    switch ($f[0]) {
        'ITEM' {
            $itemId = $f[1]; $itemName = $f[2]; $ruleCount = [int]$f[3]
            $itemEnabled = [int]$f[4]; $itemLocked = [int]$f[5]
            $itemUrl = $f[6]; $pickedBy = $f[7]
        }
        'RULE' { $rows += , $f }
        'GUARD' { $guardIdx = $f[1] }
    }
}

function Format-PortList([string]$p) {
    if (-not $p) { return '-' }
    if ($p.Length -le 28) { return $p }
    return $p.Substring(0, 25) + '...'
}

Say ' '
Say ('active set  : ' + $itemName + '  (id ' + $itemId + ', ' + $ruleCount + ' rules, picked by ' + $pickedBy + ')') 'Cyan'
if ($itemLocked -eq 1) { Say '[!] this routing set is LOCKED in v2rayN - it may be reverted on start' 'Yellow' }
if ($itemUrl) { Say ('[!] this routing set has a remote Url and may be re-downloaded: ' + $itemUrl) 'Yellow' }
if ($itemEnabled -eq 0) { Say '[!] this routing set is DISABLED' 'Yellow' }
Say 'top rules   :'
$i = 0
foreach ($f in $rows) {
    if ($i -ge 6) { Say '    ...' 'DarkGray'; break }
    Say ('    [' + $f[1] + '] out=' + $f[2].PadRight(7) + ' net=' + $f[3].PadRight(4) + ' port=' + (Format-PortList $f[4]).PadRight(29) + ' ' + $f[5]) 'Gray'
    $i++
}

$core = Get-CoreGuardState
$dbSome = [bool]($guardIdx -and $guardIdx -ne 'none')
$dbTop = ($guardIdx -eq '0,1')

if (-not $Apply) {
    Say ' '
    if ($dbTop) { Say 'database    : STUN-GUARD pair at index 0/1 (udp then tcp)' 'Green' }
    elseif ($dbSome) { Say ('database    : STUN-GUARD present but NOT at index 0/1 (found at ' + $guardIdx + ')') 'Yellow' }
    else { Say 'database    : no STUN-GUARD rule' 'Yellow' }

    switch ($core.State) {
        'present' {
            Say ('core config : both rules loaded at routing index ' + $core.Index + '/' + ($core.Index + 1) + ', complete port set') 'Green'
            if ($core.Shadow -gt 0) {
                Say ('[!] ' + $core.Shadow + ' rule(s) ahead of the pair can match STUN traffic -') 'Yellow'
                Say '    the pair may never be reached. Inspect binConfigs\config.json:' 'Yellow'
                $core.ShadowRules | ForEach-Object { Say ('      [shadow] ' + $_) 'Yellow' }
            }
            elseif ($core.Preceding -gt 0) {
                Say ('              ' + $core.Preceding + ' non-block rule(s) precede them (v2rayN built-ins);') 'DarkGray'
                Say '              each is provably unable to swallow the pair (port / inbound / domain)' 'DarkGray'
            }
            if ($core.Caveat -gt 0) {
                # Not silent, not fatal: these rules fire only for a named origin, so they
                # cannot hide STUN from an arbitrary application, but traffic from that
                # origin does bypass the pair. Printing them is the point.
                Say ('[i] ' + $core.Caveat + ' rule(s) ahead of the pair are origin-scoped (caveat, not') 'DarkGray'
                Say '    a blanket match) - STUN they originate is not covered by this guard:' 'DarkGray'
                $core.CaveatRules | ForEach-Object { Say ('      [caveat] ' + $_) 'DarkGray' }
            }
        }
        'partial' { Say ('core config : PARTIAL - ' + $core.Detail) 'Yellow' }
        'absent' { Say 'core config : NO STUN block rule - the running core still egresses STUN' 'Yellow' }
        'no-config' { Say 'core config : binConfigs\config.json not found (v2rayN never started here?)' 'DarkGray' }
        'unparsable' { Say ('core config : unparsable - ' + $core.Detail) 'Yellow' }
        default { Say ('core config : ' + $core.State) 'DarkGray' }
    }
    Say ' '
    if ($dbTop -and $core.State -eq 'present' -and $core.Shadow -eq 0) {
        Say 'verdict: B1 ACTIVE - both rules loaded and shaped correctly, so by configuration' 'Green'
        Say '         every port in the configured STUN/TURN set is dropped inside the core for' 'Green'
        Say '         ALL destinations, foreign included. This is a routing-table statement,' 'Green'
        Say '         not a packet capture: it says what the table would do, not what one probe' 'Green'
        Say '         observed. Pair it with verify-leak-test.ps1 for measured behaviour.' 'Green'
        Say '         scope: these twelve ports over udp+tcp. STUN/TURN over any other port' 'Green'
        Say '         (udp/443, vendor ports) is outside this guard by design.' 'Green'
        if ($core.Caveat -gt 0) {
            # ACTIVE is a statement about blanket shadowing only. Origin-scoped rules cannot
            # be cleared by static inspection - whether they matter depends on which process
            # or inbound the STUN socket belongs to - so the verdict has to say so instead of
            # letting "no shadow" read as "every preceding rule was ruled out".
            Say ('         caveat: ' + $core.Caveat + ' rule(s) above are origin-scoped and were NOT') 'Yellow'
            Say '         ruled out. They carry no port/domain narrowing, so a packet sent from' 'Yellow'
            Say '         that process or inbound may bypass B1 rather than reach it. ACTIVE means' 'Yellow'
            Say '         "nothing here matches an arbitrary STUN probe", not "all clear".' 'Yellow'
        }
        exit 0
    }
    if ($core.State -eq 'present' -and $core.Shadow -gt 0) {
        Say 'verdict: SHADOWED - the pair is loaded but a rule ahead of it can match STUN' 'Yellow'
        Say '         traffic, so packets may never reach it. Fix the rule order in v2rayN' 'Yellow'
        Say '         before trusting this guard.' 'Yellow'
        exit 0
    }
    if ($dbSome -and $core.State -eq 'present') {
        Say 'verdict: INCONSISTENT - the core loaded the pair but the database does not hold' 'Yellow'
        Say '         it at index 0/1. Re-run -Apply to normalise, then restart v2rayN.' 'Yellow'
        exit 0
    }
    if ($dbSome) {
        Say 'verdict: PENDING - rules are in the database but the core has not loaded a' 'Yellow'
        Say '         complete pair yet. Restart v2rayN, then re-run this script.' 'Yellow'
        exit 0
    }
    Say 'verdict: NOT APPLIED - the core can still reach a mainland STUN server and' 'Yellow'
    Say '         answer with the real ISP address.' 'Yellow'
    Say '         run: .\18-route-stun-guard.ps1 -Apply  (with v2rayN closed)' 'Yellow'
    exit 0
}

# ------------------------------------------------------------------ apply
$blocker = Get-RunningBlocker
# No bypass, same reason as the restore path: v2rayN rewrites guiNDB.db from memory when it
# exits, so an edit written under it is not "risky", it is discarded.
if ($blocker) {
    Say ' '
    Say ('[!] ' + $blocker + ' is running') 'Red'
    Say '    v2rayN keeps the routing set in memory and overwrites guiNDB.db on exit,' 'Yellow'
    Say '    so the edit would be silently reverted. Close v2rayN completely, re-run' 'Yellow'
    Say '    this script, then start v2rayN again.' 'Yellow'
    Say '    this refusal has no bypass' 'Yellow'
    exit 2
}

$bkDir = Join-Path $Root ('backup\v2rayn-routing\' + (Get-Date).ToString('yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $bkDir -Force | Out-Null
$bkFile = Join-Path $bkDir 'guiNDB.db'
try {
    Copy-Item -LiteralPath $script:DbPath -Destination $bkFile -Force
}
catch {
    # v2rayN takes the database with no write share, so an unnoticed background instance
    # (including one started after Get-RunningBlocker ran) lands here instead of a crash.
    Say '[!] cannot read guiNDB.db - a core process still holds it' 'Red'
    Say ('    ' + $_.Exception.Message) 'DarkGray'
    Say '    close v2rayN (tray icon -> exit), then re-run -Apply' 'Yellow'
    exit 2
}

$srcSha = Get-FileSha $script:DbPath
$bkSha = Get-FileSha $bkFile
if (-not $srcSha -or $srcSha -ne $bkSha) {
    Say '[!] backup copy does not match the source - aborting before any write' 'Red'
    Say ('    source: ' + $srcSha) 'DarkGray'
    Say ('    backup: ' + $bkSha) 'DarkGray'
    exit 3
}
$script:DbPath = $bkFile
$chk = Invoke-DbOp 'dump'
$script:DbPath = Join-Path $dbDir 'guiNDB.db'
if ($chk.Code -ne 0) {
    Say '[!] backup is not readable by sqlite (quick_check or parse failed) - aborting before any write' 'Red'
    $chk.Lines | ForEach-Object { Say ('    ' + $_) 'DarkGray' }
    exit 3
}
Say ' '
Say ('[+] backup    : ' + $bkDir) 'Green'
Say ('    sha256   : ' + $bkSha + '  (identical to the live database)') 'DarkGray'

# -Id pins the write to the row that was inspected above. Without it the UPDATE re-derives
# its target from IsActive, which is exactly how a run can read set A and edit set B.
$a = Invoke-DbOp 'apply' -Id $itemId
if ($a.Code -eq 4) {
    Say ' '
    Say '[!] a rule that is not ours already uses one of the two guard rule Ids' 'Red'
    $a.Lines | ForEach-Object { Say ('    ' + $_) 'DarkGray' }
    Say '    writing now would make v2rayN treat two different rules as one.' 'Yellow'
    Say ('    live database unchanged; backup kept at ' + $bkDir) 'Yellow'
    exit 4
}
if ($a.Code -ne 0) {
    Say ('[!] apply failed (exit ' + $a.Code + ')') 'Red'
    $a.Lines | ForEach-Object { Say ('    ' + $_) 'DarkGray' }
    Say ('    live database unchanged; backup kept at ' + $bkDir) 'DarkGray'
    exit 1
}
foreach ($line in $a.Lines) {
    $f = ([string]$line) -split "`t"
    if ($f[0] -eq 'APPLIED') {
        Say ('[+] inserted 2 STUN/TURN block rules at the top of "' + $itemName + '"') 'Green'
        Say ('    rules now: ' + $f[2] + '  (replaced ' + $f[3] + ' older guard rule(s))')
    }
}

# Post-write assertions: guard on top AND nothing else moved. Both are read back from
# the database, not assumed.
$v = Invoke-DbOp 'compare' -Extra $bkFile -Mode 'applied' -Id $itemId

$lines = @($v.Lines | ForEach-Object { [string]$_ })
if ($v.Code -ne 0 -or -not ($lines -match '^MATCH')) {
    Say '[!] post-write verification FAILED' 'Red'
    $lines | ForEach-Object { Say ('    ' + $_) 'DarkGray' }
    Say ('    roll back with: .\18-route-stun-guard.ps1 -Restore -BackupDir "' + $bkDir + '"') 'Yellow'
    exit 3
}
$m = ($lines | Where-Object { $_ -match '^MATCH' }) -split "`t"
Say ('[+] verified: guard rules at index 0/1, the other ' + $m[1] + ' rule(s) unchanged in content') 'Green'

$core2 = Get-CoreGuardState
Say ' '
Say 'next steps:' 'Cyan'
Say '  1. start v2rayN again (it regenerates the core config from the database)'
Say '  2. run scripts\18-route-stun-guard.ps1 (no switch) - expect "B1 ACTIVE"'
Say '  3. run scripts\verify-leak-test.ps1 - section 9 must show every probed endpoint'
Say '     silent, foreign ones included. Any reply at all, domestic or foreign, fails.'
Say ('to roll back: .\18-route-stun-guard.ps1 -Restore -BackupDir "' + $bkDir + '"') 'DarkGray'
Say ('    (core config currently on disk: ' + $core2.State + ' - restart v2rayN to load the change)') 'DarkGray'
exit 0
