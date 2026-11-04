<#
.SYNOPSIS
    AI-Net-Guard v5.7.3 - opt-in event-driven resident health monitor (zero polling CPU).

.DESCRIPTION
    The guard itself is static: opening/closing the proxy needs no firewall or
    adapter reconfiguration. In v5.1 this monitor replaces the 1-second busy
    polling loop with a pure CLR NetworkChange event bridge:

      * sleeps at 0% CPU until Windows signals a network interface / address
        change (or the periodic VerifyMinutes timer expires);
      * logs TUN up/down transitions with full yyyy-MM-dd HH:mm:ss timestamps
        and log rotation (watchdog.log -> watchdog.log.1 at 2 MB);
      * on TUN OFF -> UP transition, immediately flushes Windows DNS cache
        (<2 ms) to purge any poisoned/negative records cached while TUN was off;
      * when a new physical adapter comes up (e.g. Wi-Fi reconnect or USB phone
        hotspot), immediately runs a quiet guard check so DNS (223.5.5.5) and
        IPv6 disablement apply right away;
      * every VerifyMinutes runs 07-mode.ps1 -Mode Auto -Quiet (~0.1-0.3 s).

    Log: <Root>\logs\watchdog.log
#>

[CmdletBinding()]
param(
    [string]$Root = $(if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\AI-Net-Guard' }),
    [string]$TunName = 'xray_tun',
    [int]$DebounceMs = 250,
    [int]$VerifyMinutes = 5
)

$ErrorActionPreference = 'Continue'
$logDir = Join-Path $Root 'logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$log = Join-Path $logDir 'watchdog.log'

function Log($msg) {
    try {
        if ((Test-Path -LiteralPath $log) -and ((Get-Item -LiteralPath $log).Length -gt 2MB)) {
            $bak = $log + '.1'
            Move-Item -LiteralPath $log -Destination $bak -Force -ErrorAction SilentlyContinue
        }
        Add-Content -LiteralPath $log -Value ((Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '  ' + $msg) -Encoding UTF8
    }
    catch { }
}

function Get-NetworkSnapshot {
    $tunUp = $false
    $phys = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($ni in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($ni.OperationalStatus -ne 'Up') { continue }
            $hasIp = $ni.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv4) -or
                     $ni.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv6)
            if (-not $hasIp) { continue }
            if ($ni.Name -in @($TunName, 'xray_tun', 'singbox_tun', 'mihomo_tun', 'Meta', 'Mihomo') -or $ni.Description -match '(?i)Wintun|sing-tun|Mihomo') {
                $tunUp = $true
            }
            elseif ($ni.NetworkInterfaceType -ne 'Loopback' -and
                    $ni.Description -notmatch 'Loopback|WAN Miniport') {
                $phys.Add($ni.Name)
            }
        }
    }
    catch { }
    $physArr = $phys.ToArray()
    [Array]::Sort($physArr)
    [pscustomobject]@{
        TunUp       = $tunUp
        PhysicalKey = ($physArr -join ',')
    }
}

function Invoke-QuietVerify([string]$Reason) {
    try {
        & (if (Test-Path (Join-Path (Join-Path $Root 'scripts') '07-mode.ps1')) { Join-Path (Join-Path $Root 'scripts') '07-mode.ps1' } else { Join-Path $Root '07-mode.ps1' }) -Mode Auto -Quiet -Root $Root -TunName $TunName | Out-Null
        $code = $LASTEXITCODE
        if ($code -eq 2) { Log ($Reason + ': CN list invalid -> Protected (fail closed)') }
        elseif ($code -eq 3) { Log ($Reason + ': WARNING - one or more companion firewall rules missing (check mode-state.json)') }
        else { Log ($Reason + ': ok (static guard intact)') }
    }
    catch {
        Log ($Reason + ' failed: ' + $_.Exception.Message)
    }
}

# Pure CLR bridge avoids PowerShell Runspace thread-pool errors on NetworkChange callbacks
$useEventBridge = $false
try {
    if (-not ('AiGuardNetSignal' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Net.NetworkInformation;
using System.Threading;
public static class AiGuardNetSignal {
    public static readonly AutoResetEvent Signal = new AutoResetEvent(false);
    private static int _hooked = 0;
    public static void Start() {
        if (Interlocked.Exchange(ref _hooked, 1) == 0) {
            NetworkChange.NetworkAddressChanged += OnChange;
            NetworkChange.NetworkAvailabilityChanged += OnAvail;
        }
    }
    public static void Stop() {
        if (Interlocked.Exchange(ref _hooked, 0) == 1) {
            NetworkChange.NetworkAddressChanged -= OnChange;
            NetworkChange.NetworkAvailabilityChanged -= OnAvail;
        }
    }
    private static void OnChange(object s, EventArgs e) { try { Signal.Set(); } catch {} }
    private static void OnAvail(object s, NetworkAvailabilityEventArgs e) { try { Signal.Set(); } catch {} }
}
'@ -ErrorAction Stop
    }
    $useEventBridge = $true
}
catch {
    $useEventBridge = $false
}

# Single-instance mutex so duplicate launches exit cleanly
$mutex = New-Object System.Threading.Mutex($false, 'Global\AI-Net-Guard-Watchdog')
$hasHandle = $false
try {
    try {
        $hasHandle = $mutex.WaitOne(0, $false)
    }
    catch [System.Threading.AbandonedMutexException] {
        $hasHandle = $true
    }
    if (-not $hasHandle) {
        Log 'another watchdog instance is already running; exiting duplicate'
        exit 0
    }

    if ($useEventBridge) {
        [AiGuardNetSignal]::Start()
        Log 'monitor v5.4 started (event-driven CLR NetworkChange, static guard)'
    }
    else {
        Log 'monitor v5.4 started (fallback polling 2s, static guard)'
    }

    $lastTun = $null
    $lastPhysKey = $null
    $nextVerify = [datetime]::MinValue

    try {
        while ($true) {
            $snap = Get-NetworkSnapshot
            $up = $snap.TunUp
            $physKey = $snap.PhysicalKey

            if ($null -eq $lastTun -or $up -ne $lastTun) {
                if ($up) {
                    if ($lastTun -eq $false) {
                        Clear-DnsClientCache -ErrorAction SilentlyContinue
                        Log 'proxy path UP (TUN present) - flushed stale/poisoned DNS cache'
                    }
                    else {
                        Log 'proxy path UP (TUN present) - nothing to reconfigure'
                    }
                }
                else {
                    Log 'proxy path OFF (TUN gone) - domestic direct allowed, foreign blocked'
                }
                $lastTun = $up
            }

            $physChanged = ($null -ne $lastPhysKey -and $physKey -ne $lastPhysKey -and $physKey -ne '')
            $lastPhysKey = $physKey

            $now = Get-Date
            if ($physChanged) {
                Log ('physical adapter change detected (' + $physKey + ') - running immediate guard check')
                Invoke-QuietVerify -Reason 'adapter-change verify'
                $nextVerify = (Get-Date).AddMinutes($VerifyMinutes)
            }
            elseif ($now -ge $nextVerify) {
                Invoke-QuietVerify -Reason 'periodic verify'
                $nextVerify = (Get-Date).AddMinutes($VerifyMinutes)
            }

            if ($useEventBridge) {
                $remainMs = [int]([math]::Max(1000, ($nextVerify - (Get-Date)).TotalMilliseconds))
                if ([AiGuardNetSignal]::Signal.WaitOne($remainMs)) {
                    if ($DebounceMs -gt 0) { Start-Sleep -Milliseconds $DebounceMs }
                    [void][AiGuardNetSignal]::Signal.Reset()
                }
            }
            else {
                Start-Sleep -Seconds 2
            }
        }
    }
    finally {
        if ($useEventBridge) { [AiGuardNetSignal]::Stop() }
    }
}
finally {
    if ($hasHandle) { try { $mutex.ReleaseMutex() } catch { } }
    $mutex.Dispose()
}
