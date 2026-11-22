# AI-Net-Guard Leak & Connectivity Verification Test (v5.8.2)
#
# .PARAMETER V2rayNRoot
#   Optional. v2rayN install folder, used only to locate binConfigs\config.json for the
#   section 9 check "did the running core actually load both guard rules". When omitted
#   the folder is discovered from the running core's path, then by a shallow scan of the
#   fixed drives for a directory whose name contains v2rayN.
param([string]$V2rayNRoot = '')

$ErrorActionPreference = 'Continue'
Write-Host '===============================================================================' -ForegroundColor Cyan
Write-Host '               AI-Net-Guard Post-Optimization Leak & Health Test               ' -ForegroundColor Cyan
Write-Host '===============================================================================' -ForegroundColor Cyan
Write-Host ''

# 1. Check for dangerous rogue blanket allow rule
$rogueRule = Get-NetFirewallRule -DisplayName 'AI-Guard-Allow-TUN-Xray' -ErrorAction SilentlyContinue
if ($rogueRule) {
    Write-Host '[FAIL] Dangerous rogue blanket rule AI-Guard-Allow-TUN-Xray is STILL PRESENT in firewall!' -ForegroundColor Red
} else {
    Write-Host '[PASS] Rogue blanket rule AI-Guard-Allow-TUN-Xray is ABSENT (Firewall secured)' -ForegroundColor Green
}

# 1b. Check WebRTC STUN/TURN firewall rules and Chromium enterprise policies
$wrtcUdp = Get-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-UDP' -ErrorAction SilentlyContinue
$wrtcTcp = Get-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-TCP' -ErrorAction SilentlyContinue
$wrtcLocalUdp = Get-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-LocalIP-UDP' -ErrorAction SilentlyContinue
$wrtcLocalTcp = Get-NetFirewallRule -Name 'AI-Guard-Block-WebRTC-LocalIP-TCP' -ErrorAction SilentlyContinue
if ($wrtcUdp -and $wrtcUdp.Enabled -eq 'True' -and $wrtcTcp -and $wrtcTcp.Enabled -eq 'True' -and
    $wrtcLocalUdp -and $wrtcLocalUdp.Enabled -eq 'True' -and $wrtcLocalTcp -and $wrtcLocalTcp.Enabled -eq 'True') {
    Write-Host '[PASS] WebRTC physical NIC + LocalIP block rules (UDP+TCP STUN/TURN) are ACTIVE' -ForegroundColor Green
} else {
    Write-Host '[FAIL] WebRTC block rules AI-Guard-Block-WebRTC-(LocalIP-)UDP/TCP missing or disabled!' -ForegroundColor Red
}

$cWrtc = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome' -ErrorAction SilentlyContinue).WebRtcIPHandlingPolicy
$eWrtc = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -ErrorAction SilentlyContinue).WebRtcIPHandlingPolicy
if ($cWrtc -eq 'disable_non_proxied_udp' -and $eWrtc -eq 'disable_non_proxied_udp') {
    Write-Host '[PASS] Chromium WebRTC policy active (Chrome+Edge: disable_non_proxied_udp)' -ForegroundColor Green
} else {
    Write-Host ('[WARN] Chromium WebRtcIPHandlingPolicy incomplete (Chrome=' + $cWrtc + ', Edge=' + $eWrtc + ')') -ForegroundColor Yellow
}

$cDoh = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome' -ErrorAction SilentlyContinue).DnsOverHttpsMode
$eDoh = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -ErrorAction SilentlyContinue).DnsOverHttpsMode
if ($cDoh -eq 'off' -and $eDoh -eq 'off') {
    Write-Host '[PASS] Chromium built-in DoH disabled (Chrome+Edge DnsOverHttpsMode=off)' -ForegroundColor Green
} else {
    Write-Host ('[WARN] Chromium DnsOverHttpsMode not off (Chrome=' + $cDoh + ', Edge=' + $eDoh + ')') -ForegroundColor Yellow
}

$mdns = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -ErrorAction SilentlyContinue).EnableMDNS
if ($mdns -eq 0) {
    Write-Host '[PASS] Windows mDNS disabled (Dnscache EnableMDNS=0)' -ForegroundColor Green
} else {
    Write-Host ('[WARN] Windows Dnscache EnableMDNS=' + $mdns + ' (expected 0)') -ForegroundColor Yellow
}

# 2. Check TUN adapter status
$activeTuns = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.Name -match '(?i)tun' })
if ($activeTuns.Count -gt 0) {
    Write-Host ('[PASS] Active TUN Adapter: ' + (($activeTuns | ForEach-Object { $_.Name }) -join ', ')) -ForegroundColor Green
} else {
    Write-Host '[WARN] No active TUN adapter detected' -ForegroundColor Yellow
}

# 3. Direct Physical NIC Leak Probe (Target: Foreign Non-CN IP 13.107.246.51:443)
$physNics = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch '(?i)wintun|singbox|xray|tap|loopback|virtual|hyper-v|vethernet' })
if ($physNics.Count -gt 0) {
    foreach ($pNic in $physNics) {
        $pIp = (Get-NetIPAddress -InterfaceIndex $pNic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
        if (-not $pIp) { continue }
        $targetForeignIp = '13.107.246.51' # Foreign Microsoft Anycast IP (outside CN, not NCSI)
        $localEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($pIp), 0)
        $sock = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
        try {
            $sock.Bind($localEp)
            $async = $sock.BeginConnect($targetForeignIp, 443, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne(2000, $false)) {
                $sock.EndConnect($async)
                Write-Host ('[LEAK DETECTED!] Direct physical connection via ' + $pNic.Name + ' (' + $pIp + ') to ' + $targetForeignIp + ':443 SUCCEEDED!') -ForegroundColor Red
                Write-Host '                 The firewall default outbound block is not enforcing!' -ForegroundColor Red
            } else {
                Write-Host ('[PASS] Physical ' + $pNic.Name + ' (' + $pIp + ') connection to ' + $targetForeignIp + ':443 was BLOCKED / TIMED OUT.') -ForegroundColor Green
            }
        } catch {
            Write-Host ('[PASS] Physical ' + $pNic.Name + ' (' + $pIp + ') connection to ' + $targetForeignIp + ':443 BLOCKED: ' + $_.Exception.Message) -ForegroundColor Green
        } finally {
            $sock.Close()
        }

        # 3b. Direct Physical NIC WebRTC STUN UDP Leak Probe (74.125.250.129:19302)
        $stunReq = [byte[]]@(0x00,0x01,0x00,0x00,0x21,0x12,0xA4,0x42,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC)
        $udp = New-Object System.Net.Sockets.UdpClient($localEp)
        $udp.Client.ReceiveTimeout = 2000
        try {
            [void]$udp.Send($stunReq, $stunReq.Length, '74.125.250.129', 19302)
            $rem = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $resp = $udp.Receive([ref]$rem)
            if ($resp -and $resp.Length -gt 0) {
                Write-Host ('[LEAK DETECTED!] Physical ' + $pNic.Name + ' (' + $pIp + ') WebRTC STUN UDP to 74.125.250.129:19302 SUCCEEDED (' + $resp.Length + ' bytes)!') -ForegroundColor Red
            } else {
                Write-Host ('[PASS] Physical ' + $pNic.Name + ' (' + $pIp + ') WebRTC STUN UDP to 74.125.250.129:19302 BLOCKED / empty.') -ForegroundColor Green
            }
        } catch {
            Write-Host ('[PASS] Physical ' + $pNic.Name + ' (' + $pIp + ') WebRTC STUN UDP to 74.125.250.129:19302 BLOCKED / TIMED OUT.') -ForegroundColor Green
        } finally {
            $udp.Close()
        }
    }
} else {
    Write-Host '[INFO] No active physical adapter detected for raw socket bind test' -ForegroundColor Yellow
}

# 4. Proxy / TUN Connectivity Tests
#    Proxy = $null turns off the WinINET/system proxy - it does NOT bypass the TUN adapter.
#    Every request below therefore still travels the routing table, so a 200/204 here only
#    proves "the datapath carries HTTP". It does not prove that domestic traffic is direct
#    and foreign traffic is proxied; section 4b checks that separately by comparing the
#    source address each side sees.
Write-Host ''
Write-Host '--- Proxy / TUN Datapath Check ---' -ForegroundColor Cyan
$testUrls = @(
    @{ Name = 'Domestic (Baidu)'; Url = 'https://www.baidu.com'; Expect = '200' },
    @{ Name = 'Google (Overseas)'; Url = 'https://www.google.com/generate_204'; Expect = '204' },
    @{ Name = 'OpenAI API'; Url = 'https://api.openai.com'; Expect = '421' },
    @{ Name = 'Anthropic Claude'; Url = 'https://api.anthropic.com'; Expect = '404' }
)

foreach ($t in $testUrls) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'TIMEOUT'
    try {
        $req = [System.Net.HttpWebRequest]::Create($t.Url)
        $req.Proxy = $null
        $req.Timeout = 6000
        $req.AllowAutoRedirect = $false
        $resp = $req.GetResponse()
        $status = [string][int]$resp.StatusCode
        $resp.Close()
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            $status = [string][int]$_.Exception.Response.StatusCode
        } else {
            $status = $_.Exception.Status.ToString()
        }
    }
    $color = if ($status -eq $t.Expect) { 'Green' } else { 'Yellow' }
    Write-Host ('{0,-22}: Status={1,-8} (Elapsed: {2} ms)' -f $t.Name, $status, $sw.ElapsedMilliseconds) -ForegroundColor $color
}

# 4b. Egress identity - is the split routing actually splitting?
#     The only way to tell "domestic direct, foreign proxied" from "everything proxied"
#     without a packet capture is to ask a domestic service and a foreign service what
#     source address they see. Different addresses = two exits = routing is splitting.
#     Informational on purpose: identical addresses are ambiguous (both direct and both
#     proxied look the same), so this never decides PASS/FAIL for the suite.
Write-Host ''
Write-Host '--- 4b. Egress identity (informational) ---' -ForegroundColor Cyan
function Get-EgressIp([string]$Url, [string]$Pattern, [int]$TimeoutMs = 6000) {
    $out = [pscustomobject]@{ Ok = $false; Ip = ''; Detail = '' }
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Proxy = $null
        $req.Timeout = $TimeoutMs
        $req.ReadWriteTimeout = $TimeoutMs
        $req.AllowAutoRedirect = $true
        $req.UserAgent = 'curl/8.5.0'
        $resp = $req.GetResponse()
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
        $body = $sr.ReadToEnd()
        $sr.Close()
        $resp.Close()
        $m = [regex]::Match($body, $Pattern)
        if ($m.Success) { $out.Ok = $true; $out.Ip = $m.Groups[1].Value.Trim() }
        else { $out.Detail = 'no address in response body' }
    }
    catch { $out.Detail = $_.Exception.Message }
    return $out
}

$egCn = Get-EgressIp 'https://myip.ipip.net' '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
$egFg = Get-EgressIp 'https://www.cloudflare.com/cdn-cgi/trace' '(?m)^ip=([0-9a-fA-F:.]+)\s*$'
$cnTxt = if ($egCn.Ok) { $egCn.Ip } else { 'unavailable (' + $egCn.Detail + ')' }
$fgTxt = if ($egFg.Ok) { $egFg.Ip } else { 'unavailable (' + $egFg.Detail + ')' }
Write-Host ('domestic exit          : ' + $cnTxt) -ForegroundColor Gray
Write-Host ('foreign  exit          : ' + $fgTxt) -ForegroundColor Gray
if ($egCn.Ok -and $egFg.Ok) {
    if ($egCn.Ip -ne $egFg.Ip) {
        Write-Host '[PASS] two different exits - domestic direct and foreign proxied are distinct paths' -ForegroundColor Green
    } else {
        Write-Host '[INCONCLUSIVE] both exits report the same address - all traffic takes one path' -ForegroundColor Yellow
        Write-Host '               (could be everything proxied, or everything direct; not decidable here)' -ForegroundColor DarkGray
    }
} else {
    Write-Host '[INCONCLUSIVE] at least one echo endpoint was unreachable - no egress comparison' -ForegroundColor Yellow
}

# 9. Live STUN egress probe - the B1 acceptance test.
#    "Every rule is Active=TRUE" is not the same statement as "nothing leaks". Measured on
#    2026-11-22: eight Active=TRUE BLOCK rules (program, port list and interface GUIDs all
#    correct) did not stop a raw UDP STUN request from reaching stun.miwifi.com and coming
#    back with the real ISP address, because the TUN provider permits the core's own re-send
#    before the firewall filters run. So the accept criterion here is behavioural.
#
#    Design B1 (scripts\18-route-stun-guard.ps1) drops the STUN/TURN port set inside the
#    core's routing table by DESTINATION PORT ONLY, matching every address. Its consequence
#    is the whole point of this section:
#
#        ANY answer fails, domestic or foreign. A foreign reply is not "expected tunnel
#        egress" - it means the port is not being dropped and the guard is not loaded.
#
#    The earlier version downgraded a foreign reply to [WARN] and still printed PASS when
#    every domestic server was silent. That was wrong for B1: the one case it waved through
#    is exactly the case that proves the block is not in effect.
#
#    Silence alone is also not proof. A blocked port and a broken network look identical to
#    a UDP socket, so PASS additionally requires that the core really loaded BOTH guard
#    rules with the complete port set (checked below), and that the TUN adapter is up.
#    Everything else is INCONCLUSIVE, never PASS.
function Invoke-StunProbe {
    param([string]$Target, [int]$Port = 3478, [int]$TimeoutMs = 2200)
    $res = [pscustomobject]@{ State = 'error'; Detail = ''; Mapped = '' }
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Connect($Target, $Port)
        $b = New-Object byte[] 20
        $b[1] = 0x01
        $b[4] = 0x21; $b[5] = 0x12; $b[6] = 0xA4; $b[7] = 0x42
        for ($i = 8; $i -lt 20; $i++) { $b[$i] = [byte](Get-Random -Minimum 0 -Maximum 256) }
        [void]$udp.Send($b, $b.Length)
        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $udp.Receive([ref]$ep)
        $res.State = 'reply'
        $len = ([int]$resp[2] -shl 8) -bor [int]$resp[3]
        $i = 20
        while (($i + 12) -le $resp.Length -and $i -lt (20 + $len)) {
            $t = ([int]$resp[$i] -shl 8) -bor [int]$resp[$i + 1]
            $l = ([int]$resp[$i + 2] -shl 8) -bor [int]$resp[$i + 3]
            $v = $i + 4
            if ($t -eq 0x0020 -and $resp[$v + 1] -eq 0x01 -and ($v + 8) -le $resp.Length) {
                $ck = [BitConverter]::GetBytes([uint32]0x2112A442)
                if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($ck) }
                $ipb = @()
                for ($k = 0; $k -lt 4; $k++) { $ipb += [string]([byte]($resp[$v + 4 + $k] -bxor $ck[$k])) }
                $res.Mapped = ($ipb -join '.')
                break
            }
            $i = $v + $l + ((4 - ($l % 4)) % 4)
        }
    }
    catch {
        # Match on the socket error code, never on the message text: Windows localises it,
        # so a zh-CN host would report 10060 as plain text and a text match would mislabel
        # a blocked port as a probe error. The codes are also kept apart, because they mean
        # different things: a timeout is consistent with a drop, whereas "unreachable" or a
        # refusal says the packet left the host and something answered - that cannot be
        # counted as evidence of a drop.
        $se = $null
        if ($_.Exception -is [System.Net.Sockets.SocketException]) { $se = $_.Exception }
        elseif ($_.Exception.InnerException -is [System.Net.Sockets.SocketException]) { $se = $_.Exception.InnerException }
        $code = if ($se) { [string]$se.SocketErrorCode } else { '' }
        $res.Detail = if ($code) { $code } else { $_.Exception.Message }
        switch ($code) {
            'TimedOut' { $res.State = 'timeout' }
            'ConnectionRefused' { $res.State = 'refused' }
            # Windows surfaces an ICMP port-unreachable on a UDP socket as WSAECONNRESET
            # (10054), not as a refusal. Same meaning for this test: something answered, so
            # the packet is not being dropped.
            'ConnectionReset' { $res.State = 'refused' }
            'HostUnreachable' { $res.State = 'unreachable' }
            'NetworkUnreachable' { $res.State = 'unreachable' }
            'NetworkDown' { $res.State = 'unreachable' }
            'HostDown' { $res.State = 'unreachable' }
            'HostNotFound' { $res.State = 'dnsfail' }
            'NoData' { $res.State = 'dnsfail' }
            default {
                if (-not $code -and $_.Exception.Message -match '(?i)timed?\s*out') { $res.State = 'timeout' }
                else { $res.State = 'error' }
            }
        }
    }
    finally { $udp.Close() }
    return $res
}

function Find-CoreConfig {
    # A non-elevated shell cannot read the path of an elevated core (both Get-Process.Path and
    # CIM ExecutablePath come back empty), so path discovery alone is not enough here.
    if ($V2rayNRoot) {
        $p = Join-Path $V2rayNRoot 'binConfigs\config.json'
        if (Test-Path -LiteralPath $p) { return $p }
    }

    foreach ($name in @('xray', 'sing-box', 'mihomo', 'v2rayN')) {
        foreach ($pr in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
            $exe = ''
            try { $exe = $pr.Path } catch { }
            if (-not $exe) { continue }
            if ($name -eq 'v2rayN') {
                $p = Join-Path (Split-Path -Parent $exe) 'binConfigs\config.json'
                if (Test-Path -LiteralPath $p) { return $p }
                continue
            }
            $p = Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $exe))) 'binConfigs\config.json'
            if (Test-Path -LiteralPath $p) { return $p }
        }
    }

    foreach ($drv in @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { $_.Root -match '^[A-Za-z]:\\$' })) {
        foreach ($d in @(Get-ChildItem -LiteralPath $drv.Root -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '(?i)v2rayn' })) {
            $p = Join-Path $d.FullName 'binConfigs\config.json'
            if (Test-Path -LiteralPath $p) { return $p }
            foreach ($sub in @(Get-ChildItem -LiteralPath $d.FullName -Directory -ErrorAction SilentlyContinue)) {
                $p2 = Join-Path $sub.FullName 'binConfigs\config.json'
                if (Test-Path -LiteralPath $p2) { return $p2 }
            }
        }
    }
    return ''
}

# Same port set as 18-route-stun-guard.ps1 and 15-webrtc-browser-shield.ps1.
$expectedPorts = @(3478, 3479, 5349, 5350, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309)

function Get-PortSpecSet([string]$Spec) {
    $set = New-Object 'System.Collections.Generic.HashSet[int]'
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

function Test-StunBlockRule($Rule, [string]$Network) {
    if (-not $Rule) { return $false }
    if ([string]$Rule.outboundTag -ne 'block') { return $false }
    if ([string]$Rule.network -ne $Network) { return $false }
    $got = Get-PortSpecSet ([string]$Rule.port)
    if ($got.Count -ne $expectedPorts.Count) { return $false }
    foreach ($p in $expectedPorts) { if (-not $got.Contains($p)) { return $false } }
    return $true
}

function Get-StunGuardLoaded {
    # The database row proves nothing; only the config the core actually loaded does. The
    # check requires the udp and tcp rules to be ADJACENT and each to carry the complete
    # port set - "a block rule that mentions 3478" would accept a half-written table, which
    # is precisely the false "B1 ACTIVE" this function exists to prevent.
    $res = [pscustomobject]@{ State = 'nofile'; Index = -1; Detail = ''; Config = '' }
    $cfg = Find-CoreConfig
    if (-not $cfg) { return $res }
    $res.Config = $cfg
    try { $j = Get-Content -LiteralPath $cfg -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { $res.State = 'unparsable'; $res.Detail = $_.Exception.Message; return $res }
    $rules = @($j.routing.rules | Where-Object { $_ })

    for ($i = 0; $i -lt $rules.Count - 1; $i++) {
        if ((Test-StunBlockRule $rules[$i] 'udp') -and (Test-StunBlockRule $rules[$i + 1] 'tcp')) {
            $res.State = 'loaded'
            $res.Index = $i
            return $res
        }
    }

    for ($i = 0; $i -lt $rules.Count; $i++) {
        $r = $rules[$i]
        if ([string]$r.outboundTag -ne 'block') { continue }
        if (([string]$r.port) -notmatch '(^|,)3478(,|$)') { continue }
        $got = Get-PortSpecSet ([string]$r.port)
        $missing = @($expectedPorts | Where-Object { -not $got.Contains($_) })
        $res.State = 'partial'
        $res.Index = $i
        $res.Detail = 'rule #' + $i + ' net=' + $r.network + ' has ' + $got.Count + '/' + $expectedPorts.Count + ' ports'
        if ($missing.Count -gt 0) { $res.Detail += ', missing ' + (($missing | Select-Object -First 6) -join ',') }
        return $res
    }

    $res.State = 'absent'
    return $res
}

Write-Host ''
Write-Host '--- 9. Live STUN egress probe (B1: any answer fails) ---' -ForegroundColor Cyan
$tunIsUp = ($activeTuns.Count -gt 0)
$guard = Get-StunGuardLoaded

switch ($guard.State) {
    'loaded' {
        Write-Host ('[i] core config : both guard rules loaded at routing index ' + $guard.Index + '/' + ($guard.Index + 1) + ',') -ForegroundColor DarkGray
        Write-Host ('                  complete ' + $expectedPorts.Count + '-port set, udp then tcp') -ForegroundColor DarkGray
    }
    'partial' {
        Write-Host ('[i] core config : PARTIAL - ' + $guard.Detail) -ForegroundColor Yellow
        Write-Host '                  the port set is not fully blocked' -ForegroundColor Yellow
    }
    'absent' {
        Write-Host '[i] core config : NO guard pair for the STUN/TURN ports - design B1 is not loaded' -ForegroundColor Yellow
    }
    'nofile' {
        Write-Host '[i] core config : v2rayN folder not found - cannot confirm the loaded routing table' -ForegroundColor DarkGray
        Write-Host '    pass -V2rayNRoot <folder> if you want this checked' -ForegroundColor DarkGray
    }
    default {
        Write-Host ('[i] core config : unparsable - ' + $guard.Config) -ForegroundColor Yellow
    }
}
if ($guard.Config) { Write-Host ('                  ' + $guard.Config) -ForegroundColor DarkGray }

Write-Host '    B1 drops these ports for every destination, so a foreign STUN reply is a failure' -ForegroundColor DarkGray
Write-Host '    exactly like a domestic one. webRTC may then fall back to relay, by design.' -ForegroundColor DarkGray

$stunTargets = @(
    @{ Name = 'miwifi (CN)'; Target = 'stun.miwifi.com'; Port = 3478 },
    @{ Name = 'bilibili (CN)'; Target = 'stun.chat.bilibili.com'; Port = 3478 },
    @{ Name = 'qq (CN)'; Target = 'stun.qq.com'; Port = 3478 },
    @{ Name = 'google (foreign)'; Target = 'stun.l.google.com'; Port = 19302 },
    @{ Name = 'cloudflare (foreign)'; Target = 'stun.cloudflare.com'; Port = 3478 }
)

$stunFail = 0
$stunPass = 0
$stunInc = 0
foreach ($t in $stunTargets) {
    $r = Invoke-StunProbe -Target $t.Target -Port $t.Port
    switch ($r.State) {
        'reply' {
            $mapped = if ($r.Mapped) { $r.Mapped } else { 'unknown address' }
            $stunFail++
            Write-Host ('[FAIL] ' + $t.Name + ' answered with ' + $mapped + ' - the port is not blocked') -ForegroundColor Red
            Write-Host '       a reply here means the guard rule is not in effect for this traffic' -ForegroundColor DarkGray
        }
        'timeout' {
            if ($guard.State -eq 'loaded' -and $tunIsUp) {
                $stunPass++
                Write-Host ('[PASS] ' + $t.Name + ' silent - dropped by the guard pair in the core') -ForegroundColor Green
            }
            elseif (-not $tunIsUp) {
                $stunInc++
                Write-Host ('[INCONCLUSIVE] ' + $t.Name + ' silent, but no TUN adapter is up') -ForegroundColor Yellow
            }
            else {
                $stunInc++
                Write-Host ('[INCONCLUSIVE] ' + $t.Name + ' silent, but the core carries no complete guard pair') -ForegroundColor Yellow
                Write-Host '               silence cannot be attributed to a rule that is not loaded' -ForegroundColor DarkGray
            }
        }
        'refused' {
            $stunInc++
            Write-Host ('[INCONCLUSIVE] ' + $t.Name + ': ' + $r.Detail + ' - the packet left the host') -ForegroundColor Yellow
            Write-Host '               a refusal or reset is not a drop, so it cannot count as evidence' -ForegroundColor DarkGray
        }
        'unreachable' {
            $stunInc++
            Write-Host ('[INCONCLUSIVE] ' + $t.Name + ': ' + $r.Detail + ' - routing or link problem') -ForegroundColor Yellow
        }
        'dnsfail' {
            $stunInc++
            Write-Host ('[INCONCLUSIVE] ' + $t.Name + ': DNS resolution failed (' + $r.Detail + ')') -ForegroundColor Yellow
        }
        default {
            $stunInc++
            Write-Host ('[INCONCLUSIVE] ' + $t.Name + ': probe error (' + $r.Detail + ')') -ForegroundColor Yellow
        }
    }
}

Write-Host ''
if ($stunFail -gt 0) {
    Write-Host ('[FAIL] ' + $stunFail + '/' + $stunTargets.Count + ' STUN endpoint(s) still answered - B1 is not in effect') -ForegroundColor Red
    Write-Host '       fix: close v2rayN, run scripts\18-route-stun-guard.ps1 -Apply, start v2rayN again' -ForegroundColor Yellow
    Write-Host '       a foreign reply is not acceptable here: B1 blocks the port for every host' -ForegroundColor Yellow
}
elseif ($stunPass -eq $stunTargets.Count) {
    Write-Host ('[PASS] all ' + $stunTargets.Count + ' STUN endpoints silent with both guard rules loaded -') -ForegroundColor Green
    Write-Host '       no srflx candidate can carry the real address. webRTC calls may need a relay.' -ForegroundColor Green
}
else {
    Write-Host ('[INCONCLUSIVE] ' + $stunPass + ' silent / ' + $stunInc + ' undecided / ' + $stunTargets.Count + ' probed') -ForegroundColor Yellow
    Write-Host '       no endpoint answered, but the preconditions for claiming a drop are not met.' -ForegroundColor Yellow
    Write-Host '       start v2rayN so a TUN is up and run scripts\18-route-stun-guard.ps1 to confirm' -ForegroundColor Yellow
    Write-Host '       the pair is loaded, then re-run this test.' -ForegroundColor Yellow
    Write-Host '       (if you expected a reply here, the probe itself may be broken - it must answer' -ForegroundColor DarkGray
    Write-Host '        before -Apply, so a silent result before -Apply is a red flag, not a pass)' -ForegroundColor DarkGray
}

Write-Host ''
Write-Host 'Verification completed.' -ForegroundColor Cyan
