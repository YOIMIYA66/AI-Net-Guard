<#
.SYNOPSIS
    AI-Net-Guard v5.4 - step 0b: audit Xray's WFP filters and prove/disprove
    whether xray.exe is exempt from Windows Firewall blocks (run as Administrator).

.DESCRIPTION
    Xray's TUN leak protection (autoSystemWfpBlockLeak) installs its own WFP
    sublayer named "Xray TUN". In the ALE_AUTH_CONNECT_V4/V6 layers it adds a
    filter named "permit Xray" for its own executable with
    FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT. That flag makes the permit hard: blocks
    from lower-weight sublayers, Windows Defender Firewall rules among them, do
    not override it. Consequence:

        while Xray TUN runs, Windows Firewall cannot constrain xray.exe's
        outbound connections. It still constrains every other process, and it
        applies fully again as soon as Xray exits (the WFP session is dynamic).

    This script is READ-ONLY. It dumps the WFP state, counts the Xray filters and
    reports whether the hard permit is present. Use it before and after enabling
    TUN so the difference is visible.

.PARAMETER CaptureSeconds
    Also capture port-53 traffic for N seconds with pktmon and report which
    adapter carried it. Use it while browsing to check for plaintext DNS.

.NOTES
    Requires Administrator. Changes nothing; writes only under <Root>\logs.
#>

[CmdletBinding()]
param(
    [string]$Root = $(if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\AI-Net-Guard' }),
    [int]$CaptureSeconds = 0,
    [switch]$KeepCaptures
)

$ErrorActionPreference = 'Continue'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'ERROR: run this script in an elevated PowerShell.' -ForegroundColor Red
    exit 1
}

$logDir = Join-Path $Root 'logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$dir = Join-Path $logDir ('wfp-' + $stamp)
New-Item -ItemType Directory -Path $dir -Force | Out-Null

Write-Host ''
Write-Host 'Xray WFP audit' -ForegroundColor Cyan

# ---------------------------------------------------------------- TUN state
$tun = Get-NetAdapter -Name 'xray_tun' -ErrorAction SilentlyContinue
if ($tun) { Write-Host ('  TUN: ' + $tun.Name + ' (' + $tun.Status + ')') }
else { Write-Host '  TUN: not present (Xray TUN is off)' -ForegroundColor Yellow }

# ---------------------------------------------------------------- dump
$filtersXml = Join-Path $dir 'wfp-filters.xml'
$stateXml = Join-Path $dir 'wfp-state.xml'
Write-Host '  exporting WFP state (can take ~10 s)...'
netsh wfp show filters file="$filtersXml" | Out-Null
netsh wfp show state file="$stateXml" 2>$null | Out-Null
if (-not (Test-Path $filtersXml)) {
    Write-Host 'ERROR: netsh wfp show filters failed.' -ForegroundColor Red
    exit 1
}

$text = Get-Content -LiteralPath $filtersXml -Raw

# ---------------------------------------------------------------- analysis
Write-Host ''
Write-Host '--- Xray TUN filters ---' -ForegroundColor Cyan

$patterns = @(
    'permit Xray',
    'permit DNS through the TUN',
    'block DNS',
    'block the DNS Client service',
    'block IPv4',
    'block IPv6',
    'permit DHCP'
)
$found = @{}
foreach ($pat in $patterns) {
    $n = ([regex]::Matches($text, [regex]::Escape($pat))).Count
    $found[$pat] = $n
    if ($n -gt 0) { Write-Host ('  {0,-32} : {1}' -f $pat, $n) -ForegroundColor Green }
    else { Write-Host ('  {0,-32} : 0' -f $pat) -ForegroundColor DarkGray }
}

$hasHardPermit = ($found['permit Xray'] -gt 0)
$subLayerCount = ([regex]::Matches($text, 'Xray TUN')).Count

Write-Host ''
if ($hasHardPermit) {
    Write-Host 'RESULT: xray.exe has a HARD PERMIT in ALE_AUTH_CONNECT.' -ForegroundColor Yellow
    Write-Host '  => Windows Firewall cannot block xray.exe outbound while this filter exists.' -ForegroundColor Yellow
    Write-Host '  => It disappears when Xray exits (dynamic WFP session).' -ForegroundColor DarkGray
    Write-Host '  => To enforce "xray may only reach the node" you need either:' -ForegroundColor Yellow
    Write-Host '       a) router-level egress whitelist (recommended, strongest), or' -ForegroundColor DarkGray
    Write-Host '       b) disable autoSystemWfpBlockLeak in the Xray TUN config and let the' -ForegroundColor DarkGray
    Write-Host '          Windows Firewall rule set govern xray.exe as well.' -ForegroundColor DarkGray
}
else {
    Write-Host 'RESULT: no "permit Xray" filter found.' -ForegroundColor Green
    if ($tun -and $tun.Status -eq 'Up') {
        Write-Host '  Xray TUN is up but the hard permit is absent - the Windows Firewall' -ForegroundColor DarkGray
        Write-Host '  rule set governs xray.exe too. Verify with 03-verify.ps1.' -ForegroundColor DarkGray
    }
    else {
        Write-Host '  TUN is down, so the filters are not installed. Re-run with TUN up' -ForegroundColor Yellow
        Write-Host '  to see the difference.' -ForegroundColor Yellow
    }
}

Write-Host ''
Write-Host ('  sublayer/text hits for "Xray TUN": ' + $subLayerCount)
Write-Host ('  files: ' + $dir) -ForegroundColor DarkGray

# ---------------------------------------------------------------- firewall state
Write-Host ''
Write-Host '--- Windows Firewall state ---' -ForegroundColor Cyan
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize

# ---------------------------------------------------------------- optional DNS capture
if ($CaptureSeconds -gt 0) {
    Write-Host ''
    Write-Host ('--- pktmon: capturing port 53 for ' + $CaptureSeconds + ' s ---') -ForegroundColor Cyan
    $etl = Join-Path $dir 'dns.etl'
    $txt = Join-Path $dir 'dns.txt'
    pktmon filter remove | Out-Null
    pktmon filter add -p 53 | Out-Null
    pktmon start --capture --pkt-size 128 -f "$etl" | Out-Null
    Write-Host '  browse some sites now...'
    Start-Sleep -Seconds $CaptureSeconds
    pktmon stop | Out-Null
    pktmon filter remove | Out-Null
    pktmon etl2txt "$etl" -o "$txt" | Out-Null
    if (Test-Path $txt) {
        $hits = @(Select-String -LiteralPath $txt -Pattern ':53' -ErrorAction SilentlyContinue)
        Write-Host ('  port-53 packet lines: ' + $hits.Count)
        $adapters = @($hits | ForEach-Object { $_.Line } | Select-String -Pattern 'WLAN|xray_tun|Ethernet' -AllMatches)
        $hits | Select-Object -First 20 | ForEach-Object { Write-Host ('    ' + $_.Line) -ForegroundColor DarkGray }
        Write-Host ('  full text: ' + $txt) -ForegroundColor DarkGray
        Write-Host '  EXPECTED: nothing on WLAN; only xray_tun (encrypted DoH is 443, not captured).' -ForegroundColor Yellow
    }
}

if (-not $KeepCaptures) {
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host '  (temporary WFP/pktmon dump cleaned up; pass -KeepCaptures to retain raw XML/ETL)' -ForegroundColor DarkGray
}
