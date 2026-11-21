# AI-Net-Guard Leak & Connectivity Verification Test (v5.7.5)
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

Write-Host ''
Write-Host 'Verification completed.' -ForegroundColor Cyan
