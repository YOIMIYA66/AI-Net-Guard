# AI-Net-Guard v5.8.6 - rollback & baseline restore (100% thorough uninstaller)
[CmdletBinding()]
param(
    [string]$Root = 'C:\AI-Net-Guard',
    [switch]$KeepAclLocked
)

$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogDir = Join-Path $Root 'logs'
$BackupDir = Join-Path $Root 'backup'

if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
if (-not (Test-Path -LiteralPath $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }

$Log = Join-Path $LogDir ('rollback-' + $stamp + '.txt')

function Log ($msg) {
    $line = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '  ' + $msg
    Write-Host $line
    Add-Content -LiteralPath $Log -Value $line -Encoding ASCII
}

$DohServer = '223.5.5.5'
Log 'AI-Net-Guard v5.8.6 thorough rollback started'
Log ('user: ' + [System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

# ------------------------------------------------------------------ admin check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Log 'ERROR: rollback requires an elevated Administrator session'
    exit 2
}

# ------------------------------------------------------------------ 0. stop all AI-Guard tasks & processes
$allTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like 'AI-Guard*' } | Select-Object -ExpandProperty TaskName)
foreach ($tn in $allTasks) {
    try {
        Stop-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
        Log ('removed scheduled task: ' + $tn)
    }
    catch { Log ('warning removing task ' + $tn + ': ' + $_.Exception.Message) }
}

try {
    $wdProcs = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -match 'watchdog\.ps1' })
    foreach ($wp in $wdProcs) {
        if ($wp.ProcessId -eq $PID) { continue }
        Stop-Process -Id $wp.ProcessId -Force -ErrorAction SilentlyContinue
        Log ('terminated watchdog.ps1 process pid=' + $wp.ProcessId)
    }
}
catch { }

# ------------------------------------------------------------------ baseline discovery
function Get-Baseline {
    $b = $null
    $bf = Join-Path $BackupDir 'baseline.json'
    if (Test-Path -LiteralPath $bf) {
        try {
            $rawB = [System.IO.File]::ReadAllText($bf, [System.Text.Encoding]::UTF8)
            $b = $rawB | ConvertFrom-Json
        }
        catch {
            try { $b = Get-Content -LiteralPath $bf -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
        }
    }
    if (-not $b) {
        Log 'baseline.json missing, falling back to oldest backup files'
        $b = [pscustomobject]@{ Firewall = $null; AllowRules = $null; Dns = $null }
    }
    if (-not $b.Firewall) {
        $wfw = Get-ChildItem -Path $BackupDir -Filter 'firewall-before-*.wfw' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -First 1
        if ($wfw) { $b | Add-Member -NotePropertyName Firewall -NotePropertyValue $wfw.FullName -Force }
    }
    if (-not $b.AllowRules) {
        $json = Get-ChildItem -Path $BackupDir -Filter 'disabled-outbound-allow-*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -First 1
        if ($json) { $b | Add-Member -NotePropertyName AllowRules -NotePropertyValue $json.FullName -Force }
    }
    if (-not $b.Dns) {
        $dns = Get-ChildItem -Path $BackupDir -Filter 'dns-*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -First 1
        if ($dns) { $b | Add-Member -NotePropertyName Dns -NotePropertyValue $dns.FullName -Force }
    }
    $b
}
$baseline = Get-Baseline

# ------------------------------------------------------------------ 1. firewall restoration
if ($baseline.Firewall -and (Test-Path -LiteralPath $baseline.Firewall)) {
    Log ('importing firewall backup: ' + $baseline.Firewall)
    $out = netsh advfirewall import "$($baseline.Firewall)" 2>&1
    Log ($out -join ' ')
}

# Ensure all 3 firewall profiles allow outbound traffic by default
try {
    Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction NotConfigured -DefaultOutboundAction Allow
    Log 'ensured DefaultOutboundAction is Allow across Domain, Private, Public profiles'
}
catch { Log ('warning setting firewall profile: ' + $_.Exception.Message) }

# Re-enable original outbound allow rules
if ($baseline.AllowRules -and (Test-Path -LiteralPath $baseline.AllowRules)) {
    Log ('re-enabling outbound allow rules from ' + (Split-Path -Leaf $baseline.AllowRules))
    try {
        $rawRules = [System.IO.File]::ReadAllText($baseline.AllowRules, [System.Text.Encoding]::UTF8)
        $items = @($rawRules | ConvertFrom-Json)
        $n = 0
        foreach ($i in $items) {
            try { Enable-NetFirewallRule -Name $i.Name -ErrorAction SilentlyContinue; $n++ } catch { }
        }
        Log ('re-enabled: ' + $n + ' / ' + $items.Count)
    }
    catch { Log ('warning reading allow-rule list: ' + $_.Exception.Message) }
}

$autoQuarantine = Join-Path $BackupDir 'auto-disabled-outbound-allow.json'
if (Test-Path -LiteralPath $autoQuarantine) {
    try {
        $rawQ = [System.IO.File]::ReadAllText($autoQuarantine, [System.Text.Encoding]::UTF8)
        $qItems = @($rawQ | ConvertFrom-Json)
        $qn = 0
        foreach ($qi in $qItems) {
            try { Enable-NetFirewallRule -Name $qi.Name -ErrorAction SilentlyContinue; $qn++ } catch { }
        }
        Log ('re-enabled auto-quarantined rules: ' + $qn + ' / ' + $qItems.Count)
    }
    catch { }
}

# Remove ALL AI-Guard firewall rules
try {
    $ai = @(Get-NetFirewallRule -DisplayName '*AI-Guard*' -ErrorAction SilentlyContinue) +
          @(Get-NetFirewallRule -Name '*AI-Guard*' -ErrorAction SilentlyContinue) |
          Select-Object -Unique
    if ($ai.Count -gt 0) {
        $ai | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Log ('removed AI-Guard firewall rules: ' + $ai.Count)
    }
    else {
        Log 'no AI-Guard firewall rules found'
    }
}
catch { Log ('warning removing AI-Guard rules: ' + $_.Exception.Message) }

# ------------------------------------------------------------------ 2. NRPT & DoH cleanup
try {
    $nrpt = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -like '*AI-Guard*' -or $_.Namespace -eq '.' })
    if ($nrpt.Count -gt 0) {
        $nrpt | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue
        Log ('removed NRPT rules: ' + $nrpt.Count)
    }
}
catch { Log ('warning removing NRPT: ' + $_.Exception.Message) }

# Remove added DoH servers
$dohCleanups = @('223.5.5.5', '1.1.1.1', '8.8.8.8', '9.9.9.9')
foreach ($srv in $dohCleanups) {
    try {
        $cur = Get-DnsClientDohServerAddress -ServerAddress $srv -ErrorAction SilentlyContinue
        if ($cur) {
            Remove-DnsClientDohServerAddress -ServerAddress $srv -ErrorAction SilentlyContinue
            Log ('removed DoH server: ' + $srv)
        }
    }
    catch { }
}

# ------------------------------------------------------------------ 3. DNS restoration
$dnsBackup = $null
if ($baseline.Dns -and (Test-Path -LiteralPath $baseline.Dns)) {
    Log ('reading DNS backup from ' + (Split-Path -Leaf $baseline.Dns))
    try {
        $rawDns = [System.IO.File]::ReadAllText($baseline.Dns, [System.Text.Encoding]::UTF8)
        $dnsBackup = $rawDns | ConvertFrom-Json
    }
    catch {
        try {
            $rawDns = Get-Content -LiteralPath $baseline.Dns -Raw -Encoding UTF8
            $dnsBackup = $rawDns | ConvertFrom-Json
        }
        catch {
            Log ('warning reading DNS backup: ' + $_.Exception.Message)
        }
    }
}

if ($dnsBackup -and $dnsBackup.Dns) {
    foreach ($d in @($dnsBackup.Dns)) {
        try {
            $exists = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $d.Name }
            if (-not $exists) { continue }
            if ($d.WasStatic -and @($d.Ipv4Servers).Count -gt 0) {
                Set-DnsClientServerAddress -InterfaceAlias $d.Name -ServerAddresses @($d.Ipv4Servers) -ErrorAction SilentlyContinue
                Log ('DNS restored (static): ' + $d.Name + ' -> ' + (@($d.Ipv4Servers) -join ','))
            }
            else {
                Set-DnsClientServerAddress -InterfaceAlias $d.Name -ResetServerAddresses -ErrorAction SilentlyContinue
                Log ('DNS restored (DHCP): ' + $d.Name)
            }
        }
        catch { }
    }
}
else {
    Log 'resetting active network adapters to DHCP DNS'
    foreach ($a in (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch '(?i)Wintun|sing-tun' })) {
        try { Set-DnsClientServerAddress -InterfaceAlias $a.Name -ResetServerAddresses -ErrorAction SilentlyContinue } catch { }
    }
}

# ------------------------------------------------------------------ 4. IPv6 & prefix policy restoration
# Re-enable IPv6 on all physical network adapters
foreach ($a in (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -notmatch '(?i)Wintun|sing-tun' })) {
    try {
        Enable-NetAdapterBinding -Name $a.Name -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue
    }
    catch { }
}
Log 're-enabled IPv6 bindings on physical adapters'

# Restore Tcpip6 DisabledComponents to Windows default (remove property or set to 0)
try {
    $tcpip6Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
    if (Test-Path -LiteralPath $tcpip6Key) {
        if ($dnsBackup -and $dnsBackup.PSObject.Properties.Name -contains 'Tcpip6DisabledComponents' -and $null -ne $dnsBackup.Tcpip6DisabledComponents) {
            New-ItemProperty -Path $tcpip6Key -Name 'DisabledComponents' -Value ([int]$dnsBackup.Tcpip6DisabledComponents) -PropertyType DWord -Force | Out-Null
            Log ('restored Tcpip6 DisabledComponents to: ' + $dnsBackup.Tcpip6DisabledComponents)
        }
        else {
            Remove-ItemProperty -Path $tcpip6Key -Name 'DisabledComponents' -ErrorAction SilentlyContinue
            Log 'removed Tcpip6 DisabledComponents (Windows default IPv6 enabled)'
        }
    }
}
catch { }

# Restore IPv4 prefix policy to Windows standard (precedence 35)
try {
    $wantPrec = 35; $wantLbl = 4
    if ($dnsBackup -and $dnsBackup.PSObject.Properties.Name -contains 'Ipv4PrefixPolicy' -and $dnsBackup.Ipv4PrefixPolicy) {
        $wantPrec = [int]$dnsBackup.Ipv4PrefixPolicy.Precedence
        $wantLbl = [int]$dnsBackup.Ipv4PrefixPolicy.Label
    }
    netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 $wantPrec $wantLbl | Out-Null
    Log ('restored IPv4 prefix policy: ::ffff:0:0/96 precedence=' + $wantPrec)
}
catch { }

# ------------------------------------------------------------------ 5. NTP server restoration
try {
    $w32TimeKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
    if (Test-Path -LiteralPath $w32TimeKey) {
        $targetNtp = if ($dnsBackup -and $dnsBackup.PSObject.Properties.Name -contains 'NtpServer' -and $dnsBackup.NtpServer) { [string]$dnsBackup.NtpServer } else { 'time.windows.com,0x9' }
        New-ItemProperty -Path $w32TimeKey -Name 'NtpServer' -Value $targetNtp -PropertyType String -Force | Out-Null
        $w32svc = Get-Service -Name w32time -ErrorAction SilentlyContinue
        if ($w32svc -and $w32svc.Status -eq 'Running') { w32tm /config /update 2>$null | Out-Null }
        Log ('restored NTP server: ' + $targetNtp)
    }
}
catch { }

# ------------------------------------------------------------------ 6. LLMNR, mDNS & SMHNR policy removal
try {
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    if (Test-Path -LiteralPath $key) {
        Remove-ItemProperty -Path $key -Name 'EnableMulticast' -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $key -Name 'DisableSmartNameResolution' -ErrorAction SilentlyContinue
        Log 'removed LLMNR & SMHNR group policies (Windows defaults restored)'
    }
    $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
    if (Test-Path -LiteralPath $svcKey) {
        if ($dnsBackup -and ($dnsBackup.PSObject.Properties.Name -contains 'MdnsEnabled') -and $null -ne $dnsBackup.MdnsEnabled) {
            New-ItemProperty -Path $svcKey -Name 'EnableMDNS' -Value ([int]$dnsBackup.MdnsEnabled) -PropertyType DWord -Force | Out-Null
            Log ('restored Dnscache EnableMDNS: ' + $dnsBackup.MdnsEnabled)
        }
        else {
            Remove-ItemProperty -Path $svcKey -Name 'EnableMDNS' -ErrorAction SilentlyContinue
            Log 'removed Dnscache EnableMDNS (Windows mDNS default restored)'
        }
    }
}
catch { }

# ------------------------------------------------------------------ 6.5. Browser WebRTC & DoH enterprise policy cleanup
try {
    $cPolKey = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
    $ePolKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    $dnsBackupWrtc = $null
    if ($baseline.Dns -and (Test-Path -LiteralPath $baseline.Dns)) {
        try {
            $rawW = [System.IO.File]::ReadAllText($baseline.Dns, [System.Text.Encoding]::UTF8)
            $dnsBackupWrtc = $rawW | ConvertFrom-Json
        } catch { }
    }
    if (Test-Path -LiteralPath $cPolKey) {
        $origChrome = if ($dnsBackupWrtc -and $dnsBackupWrtc.PSObject.Properties.Name -contains 'ChromeWebRtcPolicy') { $dnsBackupWrtc.ChromeWebRtcPolicy } else { $null }
        if ($null -ne $origChrome) {
            New-ItemProperty -Path $cPolKey -Name 'WebRtcIPHandlingPolicy' -Value ([string]$origChrome) -PropertyType String -Force | Out-Null
            Log ('restored Chrome WebRtcIPHandlingPolicy: ' + $origChrome)
        } else {
            Remove-ItemProperty -Path $cPolKey -Name 'WebRtcIPHandlingPolicy' -ErrorAction SilentlyContinue
            Log 'removed Chrome WebRtcIPHandlingPolicy (restore to default)'
        }
        $origChromeDoh = if ($dnsBackupWrtc -and $dnsBackupWrtc.PSObject.Properties.Name -contains 'ChromeDohMode') { $dnsBackupWrtc.ChromeDohMode } else { $null }
        if ($null -ne $origChromeDoh) {
            New-ItemProperty -Path $cPolKey -Name 'DnsOverHttpsMode' -Value ([string]$origChromeDoh) -PropertyType String -Force | Out-Null
            Log ('restored Chrome DnsOverHttpsMode: ' + $origChromeDoh)
        } else {
            Remove-ItemProperty -Path $cPolKey -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue
            Log 'removed Chrome DnsOverHttpsMode (restore to default)'
        }
    }
    if (Test-Path -LiteralPath $ePolKey) {
        $origEdge = if ($dnsBackupWrtc -and $dnsBackupWrtc.PSObject.Properties.Name -contains 'EdgeWebRtcPolicy') { $dnsBackupWrtc.EdgeWebRtcPolicy } else { $null }
        $origEdgeLo = if ($dnsBackupWrtc -and $dnsBackupWrtc.PSObject.Properties.Name -contains 'EdgeWebRtcLocalhost') { $dnsBackupWrtc.EdgeWebRtcLocalhost } else { $null }
        if ($null -ne $origEdge) {
            New-ItemProperty -Path $ePolKey -Name 'WebRtcIPHandlingPolicy' -Value ([string]$origEdge) -PropertyType String -Force | Out-Null
            Log ('restored Edge WebRtcIPHandlingPolicy: ' + $origEdge)
        } else {
            Remove-ItemProperty -Path $ePolKey -Name 'WebRtcIPHandlingPolicy' -ErrorAction SilentlyContinue
            Log 'removed Edge WebRtcIPHandlingPolicy (restore to default)'
        }
        if ($null -ne $origEdgeLo) {
            New-ItemProperty -Path $ePolKey -Name 'WebRtcLocalhostIpHandling' -Value ([string]$origEdgeLo) -PropertyType String -Force | Out-Null
        } else {
            Remove-ItemProperty -Path $ePolKey -Name 'WebRtcLocalhostIpHandling' -ErrorAction SilentlyContinue
            Log 'removed Edge WebRtcLocalhostIpHandling (restore to default)'
        }
        $origEdgeDoh = if ($dnsBackupWrtc -and $dnsBackupWrtc.PSObject.Properties.Name -contains 'EdgeDohMode') { $dnsBackupWrtc.EdgeDohMode } else { $null }
        if ($null -ne $origEdgeDoh) {
            New-ItemProperty -Path $ePolKey -Name 'DnsOverHttpsMode' -Value ([string]$origEdgeDoh) -PropertyType String -Force | Out-Null
            Log ('restored Edge DnsOverHttpsMode: ' + $origEdgeDoh)
        } else {
            Remove-ItemProperty -Path $ePolKey -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue
            Log 'removed Edge DnsOverHttpsMode (restore to default)'
        }
    }
}
catch { Log ('warning removing WebRTC/DoH browser policy: ' + $_.Exception.Message) }

# ------------------------------------------------------------------ 7. WinINET system proxy cleanup
try {
    $inetKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    if (Test-Path -LiteralPath $inetKey) {
        Set-ItemProperty -Path $inetKey -Name 'ProxyEnable' -Value 0 -ErrorAction SilentlyContinue
        Log 'ensured HKCU WinINET ProxyEnable is 0'
    }
}
catch { }

# ------------------------------------------------------------------ 8. Loopback 1.1.1.1 removal
try {
    $loopAlias = (Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -like '*Loopback*' } | Select-Object -First 1).Name
    if (-not $loopAlias) { $loopAlias = 'Loopback Pseudo-Interface 1' }
    Remove-NetIPAddress -InterfaceAlias $loopAlias -IPAddress '1.1.1.1' -Confirm:$false -ErrorAction SilentlyContinue
    Log 'removed loopback 1.1.1.1 IP if present'
}
catch { }

# Flush DNS cache
try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch { }
ipconfig /flushdns | Out-Null
Log 'flushed Windows DNS client cache'

# ------------------------------------------------------------------ 8.5. Remove proxy node /32 host routes
try {
    $nodeMeta = Join-Path $BackupDir 'node-sync.meta'
    if (Test-Path -LiteralPath $nodeMeta) {
        $metaContent = Get-Content -LiteralPath $nodeMeta -Raw -ErrorAction SilentlyContinue
        if ($metaContent -match '\|([\d\.,]+)\|') {
            $nodeIps = $Matches[1].Split(',')
            foreach ($nip in $nodeIps) {
                if ($nip -match '^\d{1,3}(\.\d{1,3}){3}$') {
                    Remove-NetRoute -DestinationPrefix ($nip + '/32') -Confirm:$false -ErrorAction SilentlyContinue
                    Log ('removed node host route: ' + $nip + '/32')
                }
            }
        }
    }
} catch { }

# ------------------------------------------------------------------ 9. Archive baseline & state files
$bf = Join-Path $BackupDir 'baseline.json'
if (Test-Path -LiteralPath $bf) {
    $archived = Join-Path $BackupDir ('baseline-rolledback-' + $stamp + '.json')
    Move-Item -LiteralPath $bf -Destination $archived -Force -ErrorAction SilentlyContinue
    Log ('archived baseline.json -> ' + (Split-Path -Leaf $archived))
}

$pf = Join-Path $BackupDir 'guard-policy.json'
if (Test-Path -LiteralPath $pf) {
    $archivedPol = Join-Path $BackupDir ('guard-policy-rolledback-' + $stamp + '.json')
    Move-Item -LiteralPath $pf -Destination $archivedPol -Force -ErrorAction SilentlyContinue
    Log ('archived guard-policy.json -> ' + (Split-Path -Leaf $archivedPol))
}

# Remove dynamic metadata files
foreach ($metaFile in @('mode-state.json', 'node-sync.meta', 'cn-rule.sig', 'cn-file.meta', 'auto-disabled-outbound-allow.json', 'hotplug-ipv6.json', 'b1-guard.meta')) {
    $mf = Join-Path $BackupDir $metaFile
    if (Test-Path -LiteralPath $mf) {
        Remove-Item -LiteralPath $mf -Force -ErrorAction SilentlyContinue
        Log ('cleaned up metadata: ' + $metaFile)
    }
}

# ------------------------------------------------------------------ 10. Restore directory ACL
if (-not $KeepAclLocked -and $Root.Length -gt 3 -and $Root -notmatch '(?i)^[A-Z]:\\(Windows|Program Files|Program Files \(x86\)|Users|ProgramData)(\\|$)') {
    try {
        & icacls.exe $Root /reset /T /C /Q 2>$null | Out-Null
        Log ('restored default inherited ACL on ' + $Root)
    }
    catch { }
}

# ------------------------------------------------------------------ 10.5. v2rayN core routing guard
# 18-route-stun-guard.ps1 writes two block rules into v2rayN's guiNDB.db. This
# uninstaller deliberately never rewrites that database: v2rayN may still be running
# and would overwrite the change on exit, or leave a half-checkpointed WAL. Removing
# b1-guard.meta above only clears OUR verdict cache; the rules in the core's routing
# table stay live. Print the manual step instead of claiming a fully clean uninstall.
$routingBk = Join-Path $BackupDir 'v2rayn-routing'
$hasRoutingBk = $false
if (Test-Path -LiteralPath $routingBk) {
    $hasRoutingBk = (@(Get-ChildItem -LiteralPath $routingBk -Directory -ErrorAction SilentlyContinue)).Count -gt 0
}
if ($hasRoutingBk) {
    $notice = 'NOTE: v2rayN routing backups were found under ' + $routingBk
    $fix = '      The B1 STUN block rules may still be live in guiNDB.db. Close v2rayN, then run scripts\18-route-stun-guard.ps1 -Restore to restore the original routing table.'
    Log $notice
    Log $fix
    Write-Host $notice -ForegroundColor Yellow
    Write-Host $fix -ForegroundColor Yellow
}

if ($hasRoutingBk) {
    Log 'rollback finished: Windows guard state restored; manual v2rayN routing step listed above'
}
else {
    Log 'rollback finished: 100% SUCCESS'
}
Write-Host ('rollback log: ' + $Log) -ForegroundColor Green
exit 0
