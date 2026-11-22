# AI-Net-Guard Leak & Connectivity Verification Test (v5.8.1)
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

# 9. Live STUN egress probe.
#    "Every rule is Active=TRUE" is not the same statement as "nothing leaks". Measured on
#    2026-11-22: eight Active=TRUE BLOCK rules (program, port list and interface GUIDs all
#    correct) did not stop a raw UDP STUN request from reaching stun.miwifi.com and coming
#    back with the real ISP address, because the TUN provider permits the core's own re-send
#    before the firewall filters run. So the accept criterion here is behavioural: with a TUN
#    up, no mainland STUN server may answer at all - the guard drops that port set inside the
#    core's routing table (scripts\18-route-stun-guard.ps1).
function Invoke-StunProbe {
    param([string]$Target, [int]$Port = 3478, [int]$TimeoutMs = 2200)
    $res = [pscustomobject]@{ State = 'error'; Mapped = ''; Detail = '' }
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
        # a blocked port as a probe error.
        $se = $null
        if ($_.Exception -is [System.Net.Sockets.SocketException]) { $se = $_.Exception }
        elseif ($_.Exception.InnerException -is [System.Net.Sockets.SocketException]) { $se = $_.Exception.InnerException }
        if ($se -and @('TimedOut', 'ConnectionRefused', 'HostUnreachable', 'NetworkUnreachable') -contains [string]$se.SocketErrorCode) {
            $res.State = 'silent'
        }
        elseif ($_.Exception.Message -match 'timed out|timeout') { $res.State = 'silent' }
        else { $res.Detail = $_.Exception.Message }
    }
    finally { $udp.Close() }
    return $res
}

Write-Host ''
Write-Host '--- 9. Live STUN egress probe (behaviour, not rule presence) ---' -ForegroundColor Cyan
$tunIsUp = ($activeTuns.Count -gt 0)
$stunTargets = @(
    @{ Name = 'miwifi (CN)'; Target = 'stun.miwifi.com'; Port = 3478 },
    @{ Name = 'bilibili (CN)'; Target = 'stun.chat.bilibili.com'; Port = 3478 },
    @{ Name = 'qq (CN)'; Target = 'stun.qq.com'; Port = 3478 },
    @{ Name = 'google (foreign)'; Target = 'stun.l.google.com'; Port = 19302 }
)
$stunLeaks = 0
foreach ($t in $stunTargets) {
    $isCn = ($t.Name -like '*CN*')
    $r = Invoke-StunProbe -Target $t.Target -Port $t.Port
    if ($r.State -eq 'reply') {
        if ($isCn -and $tunIsUp) {
            Write-Host ('[FAIL] ' + $t.Name + ' answered with ' + $r.Mapped + ' - mainland STUN reachable from the physical NIC') -ForegroundColor Red
            $stunLeaks++
        }
        elseif ($isCn) {
            Write-Host ('[WARN] ' + $t.Name + ' answered with ' + $r.Mapped + ' (no TUN up - informational only)') -ForegroundColor Yellow
        }
        else {
            Write-Host ('[PASS] ' + $t.Name + ' answered with ' + $r.Mapped + ' (tunnel egress, expected)') -ForegroundColor Green
        }
    }
    elseif ($r.State -eq 'silent') {
        if ($isCn) {
            Write-Host ('[PASS] ' + $t.Name + ' silent (STUN port set dropped inside the core)') -ForegroundColor Green
        }
        else {
            Write-Host ('[WARN] ' + $t.Name + ' silent - tunnel may be down, CN results are inconclusive') -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ('[WARN] ' + $t.Name + ' probe error: ' + $r.Detail) -ForegroundColor Yellow
    }
}
if ($stunLeaks -gt 0) {
    Write-Host ('[FAIL] ' + $stunLeaks + ' mainland STUN server(s) reachable - the WebRTC leak path is open') -ForegroundColor Red
    Write-Host '       fix: close v2rayN, run scripts\18-route-stun-guard.ps1 -Apply, start v2rayN again' -ForegroundColor Yellow
}

Write-Host ''
Write-Host 'Verification completed.' -ForegroundColor Cyan
