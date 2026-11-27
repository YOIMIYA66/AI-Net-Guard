# AI-Net-Guard v5.9.7 - rollback & baseline restore (100% thorough uninstaller)
[CmdletBinding()]
param(
    [string]$Root = 'C:\AI-Net-Guard',
    [switch]$Auto,
    [switch]$KeepAclLocked,
    [switch]$ForceAllowOutbound
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
    [System.IO.File]::AppendAllText($Log, $line + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
}

$DohServer = '223.5.5.5'
Log ('AI-Net-Guard v5.9.7 thorough rollback started' + $(if ($Auto) { ' (auto-rollback trigger)' } else { '' }))
Log ('user: ' + [System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

# ------------------------------------------------------------------ admin check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Log 'ERROR: rollback requires an elevated Administrator session'
    exit 2
}

$libCommonRb = ''
foreach ($cand in @((Join-Path $PSScriptRoot 'lib-guard-common.ps1'), (Join-Path (Join-Path $Root 'scripts') 'lib-guard-common.ps1'), (Join-Path $Root 'lib-guard-common.ps1'))) {
    if ($cand -and (Test-Path -LiteralPath $cand)) { $libCommonRb = $cand; break }
}
if ($libCommonRb) { . $libCommonRb }

$rollbackErrors = New-Object System.Collections.Generic.List[string]
$rbWriteLock = $null
if (Get-Command Enter-GuardWriteLock -ErrorAction SilentlyContinue) {
    $rbWriteLock = Enter-GuardWriteLock -TimeoutMs 30000
}
try {

# ------------------------------------------------------------------ 0. stop all AI-Guard tasks & processes
$deferredSelfTasks = New-Object System.Collections.Generic.List[string]
$allTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like 'AI-Guard*' } | Select-Object -ExpandProperty TaskName)
foreach ($tn in $allTasks) {
    # Self-termination guard (#04): when triggered by AI-Guard-Test-Rollback or AI-Guard-Boot-Guard
    # (-Auto), calling Stop-ScheduledTask on the hosting task can terminate this process mid-rollback.
    if ($Auto -and ($tn -in @('AI-Guard-Test-Rollback', 'AI-Guard-Boot-Guard'))) {
        $deferredSelfTasks.Add($tn)
        Log ('deferring unregister of self-trigger task until rollback finishes: ' + $tn)
        continue
    }
    try {
        Stop-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction Stop
        $still = Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
        if ($still) {
            throw ('scheduled task still present after Unregister-ScheduledTask: ' + $tn)
        }
        Log ('removed scheduled task: ' + $tn)
    }
    catch {
        $msg = 'failed removing task ' + $tn + ': ' + $_.Exception.Message
        $rollbackErrors.Add($msg)
        Log ('ERROR: ' + $msg)
    }
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
$fwImported = $false
$hasFwBackupFile = [bool]($baseline.Firewall -and (Test-Path -LiteralPath $baseline.Firewall))
if ($hasFwBackupFile) {
    Log ('importing firewall backup: ' + $baseline.Firewall)
    $out = netsh advfirewall import "$($baseline.Firewall)" 2>&1
    $impRc = $LASTEXITCODE
    Log ($out -join ' ')
    if ($impRc -eq 0) {
        $fwImported = $true
        Log 'firewall baseline imported cleanly (preserving pre-install profile actions)'
    }
    else {
        $errMsg = 'firewall backup import failed (exit=' + $impRc + ')'
        $rollbackErrors.Add($errMsg)
        Log ('ERROR: ' + $errMsg)
    }
}
elseif (-not $ForceAllowOutbound) {
    $errMsg = 'firewall baseline file missing; cannot restore exact pre-install firewall policy without -ForceAllowOutbound'
    $rollbackErrors.Add($errMsg)
    Log ('ERROR: ' + $errMsg)
}

# Only override default profile actions when -ForceAllowOutbound (emergency rescue) is
# explicitly specified. If netsh import failed or the baseline is missing, never silently
# force outbound Allow (#05).
if ($ForceAllowOutbound) {
    try {
        Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction NotConfigured -DefaultOutboundAction Allow -ErrorAction Stop
        Log 'emergency override (-ForceAllowOutbound): set DefaultInboundAction=NotConfigured, DefaultOutboundAction=Allow'
    }
    catch {
        $rollbackErrors.Add('Set-NetFirewallProfile failed: ' + $_.Exception.Message)
        Log ('ERROR setting firewall profile: ' + $_.Exception.Message)
    }
}
elseif (-not $fwImported) {
    Log 'WARNING: leaving firewall profile DefaultOutboundAction untouched (pass -ForceAllowOutbound or run Emergency-Rescue.bat to force-open outbound)'
}

# Abort destructive steps (#06) if firewall baseline could not be restored without -ForceAllowOutbound.
$abortDestructiveRollback = ((-not $fwImported) -and (-not $ForceAllowOutbound))
if ($abortDestructiveRollback) {
    Log 'ERROR: aborting remaining destructive rollback steps because firewall baseline could not be restored; preserving existing firewall rules, DNS, IPv6, baseline, metadata, and locked ACL.'
}
else {

# Re-enable original outbound allow rules
if ($baseline.AllowRules -and (Test-Path -LiteralPath $baseline.AllowRules)) {
    Log ('re-enabling outbound allow rules from ' + (Split-Path -Leaf $baseline.AllowRules))
    try {
        $rawRules = [System.IO.File]::ReadAllText($baseline.AllowRules, [System.Text.Encoding]::UTF8)
        $items = @($rawRules | ConvertFrom-Json)
        $n = 0
        foreach ($i in $items) {
            try {
                if ($i.Name -and (Get-NetFirewallRule -Name $i.Name -ErrorAction SilentlyContinue)) {
                    Enable-NetFirewallRule -Name $i.Name -ErrorAction Stop
                    $n++
                }
            }
            catch {
                $rollbackErrors.Add('Enable-NetFirewallRule failed for ' + $i.Name + ': ' + $_.Exception.Message)
            }
        }
        Log ('re-enabled: ' + $n + ' / ' + $items.Count)
    }
    catch {
        $rollbackErrors.Add('reading allow-rule list failed: ' + $_.Exception.Message)
        Log ('ERROR reading allow-rule list: ' + $_.Exception.Message)
    }
}

$autoQuarantine = Join-Path $BackupDir 'auto-disabled-outbound-allow.json'
if (Test-Path -LiteralPath $autoQuarantine) {
    try {
        if (Get-Command Read-GuardQuarantineList -ErrorAction SilentlyContinue) {
            $qItems = @((Read-GuardQuarantineList -Path $autoQuarantine).Items)
        }
        else {
            $rawQ = [System.IO.File]::ReadAllText($autoQuarantine, [System.Text.Encoding]::UTF8)
            $qItems = @($rawQ | ConvertFrom-Json)
        }
        $qn = 0
        foreach ($qi in $qItems) {
            try {
                if ($qi.Name -and (Get-NetFirewallRule -Name $qi.Name -ErrorAction SilentlyContinue)) {
                    Enable-NetFirewallRule -Name $qi.Name -ErrorAction Stop
                    $qn++
                }
            }
            catch {
                $rollbackErrors.Add('re-enabling auto-quarantined rule ' + $qi.Name + ' failed: ' + $_.Exception.Message)
            }
        }
        Log ('re-enabled auto-quarantined rules: ' + $qn + ' / ' + $qItems.Count)
    }
    catch {
        $rollbackErrors.Add('reading auto-quarantined rule list failed: ' + $_.Exception.Message)
    }
}

# Remove ALL AI-Guard firewall rules
try {
    $ai = @(Get-NetFirewallRule -DisplayName '*AI-Guard*' -ErrorAction SilentlyContinue) +
          @(Get-NetFirewallRule -Name '*AI-Guard*' -ErrorAction SilentlyContinue) |
          Select-Object -Unique
    if ($ai.Count -gt 0) {
        $ai | Remove-NetFirewallRule -ErrorAction Stop
        Log ('removed AI-Guard firewall rules: ' + $ai.Count)
    }
    else {
        Log 'no AI-Guard firewall rules found'
    }
}
catch {
    $rollbackErrors.Add('removing AI-Guard firewall rules failed: ' + $_.Exception.Message)
    Log ('ERROR removing AI-Guard rules: ' + $_.Exception.Message)
}

# ------------------------------------------------------------------ 2. NRPT & DoH cleanup
try {
    $nrpt = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -like '*AI-Guard*' -or $_.Namespace -eq '.' })
    if ($nrpt.Count -gt 0) {
        $nrpt | Remove-DnsClientNrptRule -Force -ErrorAction Stop
        Log ('removed NRPT rules: ' + $nrpt.Count)
    }
}
catch {
    $rollbackErrors.Add('removing NRPT rules failed: ' + $_.Exception.Message)
    Log ('ERROR removing NRPT: ' + $_.Exception.Message)
}

# Remove added DoH servers
$dohCleanups = @('223.5.5.5', '1.1.1.1', '8.8.8.8', '9.9.9.9')
foreach ($srv in $dohCleanups) {
    try {
        $cur = Get-DnsClientDohServerAddress -ServerAddress $srv -ErrorAction SilentlyContinue
        if ($cur) {
            Remove-DnsClientDohServerAddress -ServerAddress $srv -ErrorAction Stop
            Log ('removed DoH server: ' + $srv)
        }
    }
    catch {
        $rollbackErrors.Add('removing DoH server ' + $srv + ' failed: ' + $_.Exception.Message)
        Log ('ERROR removing DoH server ' + $srv + ': ' + $_.Exception.Message)
    }
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
            $rollbackErrors.Add('reading DNS backup failed: ' + $_.Exception.Message)
            Log ('ERROR reading DNS backup: ' + $_.Exception.Message)
        }
    }
}

if ($dnsBackup -and $dnsBackup.Dns) {
    foreach ($d in @($dnsBackup.Dns)) {
        try {
            $exists = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $d.Name }
            if (-not $exists) { continue }
            if ($d.WasStatic -and @($d.Ipv4Servers).Count -gt 0) {
                Set-DnsClientServerAddress -InterfaceAlias $d.Name -ServerAddresses @($d.Ipv4Servers) -ErrorAction Stop
                Log ('DNS restored (static): ' + $d.Name + ' -> ' + (@($d.Ipv4Servers) -join ','))
            }
            else {
                Set-DnsClientServerAddress -InterfaceAlias $d.Name -ResetServerAddresses -ErrorAction Stop
                Log ('DNS restored (DHCP): ' + $d.Name)
            }
        }
        catch {
            $rollbackErrors.Add('DNS restore failed on ' + $d.Name + ': ' + $_.Exception.Message)
            Log ('ERROR restoring DNS on ' + $d.Name + ': ' + $_.Exception.Message)
        }
    }
}
else {
    Log 'resetting active network adapters to DHCP DNS'
    foreach ($a in (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch '(?i)Wintun|sing-tun' })) {
        try { Set-DnsClientServerAddress -InterfaceAlias $a.Name -ResetServerAddresses -ErrorAction Stop }
        catch {
            $rollbackErrors.Add('DNS DHCP reset failed on ' + $a.Name + ': ' + $_.Exception.Message)
            Log ('ERROR resetting DNS on ' + $a.Name + ': ' + $_.Exception.Message)
        }
    }
}

# ------------------------------------------------------------------ 4. IPv6 & prefix policy restoration
# Restore ms_tcpip6 binding per physical adapter from baseline (plus hotplug-ipv6.json).
$origIpv6Map = @{}
if ($dnsBackup -and $dnsBackup.Dns) {
    foreach ($d in @($dnsBackup.Dns)) {
        if ($d.Name -and ($d.PSObject.Properties.Name -contains 'Ipv6Binding') -and $null -ne $d.Ipv6Binding) {
            $origIpv6Map[[string]$d.Name] = [bool]$d.Ipv6Binding
        }
    }
}
$hpNames = @()
$hpFile = Join-Path $BackupDir 'hotplug-ipv6.json'
if (Test-Path -LiteralPath $hpFile) {
    try { $hpNames = @(Get-Content -LiteralPath $hpFile -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { }
}
$hasIpv6Baseline = ($origIpv6Map.Count -gt 0) -or ($hpNames.Count -gt 0)
foreach ($a in (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -notmatch '(?i)Wintun|sing-tun' })) {
    try {
        if ($origIpv6Map.ContainsKey($a.Name)) {
            if ($origIpv6Map[$a.Name]) {
                Enable-NetAdapterBinding -Name $a.Name -ComponentID 'ms_tcpip6' -ErrorAction Stop
            }
            else {
                Disable-NetAdapterBinding -Name $a.Name -ComponentID 'ms_tcpip6' -ErrorAction Stop
            }
        }
        elseif ($hpNames -contains $a.Name) {
            Enable-NetAdapterBinding -Name $a.Name -ComponentID 'ms_tcpip6' -ErrorAction Stop
        }
        elseif (-not $hasIpv6Baseline) {
            Enable-NetAdapterBinding -Name $a.Name -ComponentID 'ms_tcpip6' -ErrorAction Stop
        }
    }
    catch {
        $rollbackErrors.Add('IPv6 binding restore failed on ' + $a.Name + ': ' + $_.Exception.Message)
        Log ('ERROR restoring IPv6 binding on ' + $a.Name + ': ' + $_.Exception.Message)
    }
}
Log 'restored IPv6 bindings on physical adapters per baseline'

# Restore Tcpip6 DisabledComponents to Windows default (remove property or set to original)
try {
    $tcpip6Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
    if (Test-Path -LiteralPath $tcpip6Key) {
        if ($dnsBackup -and $dnsBackup.PSObject.Properties.Name -contains 'Tcpip6DisabledComponents' -and $null -ne $dnsBackup.Tcpip6DisabledComponents) {
            New-ItemProperty -Path $tcpip6Key -Name 'DisabledComponents' -Value ([int]$dnsBackup.Tcpip6DisabledComponents) -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            Log ('restored Tcpip6 DisabledComponents to: ' + $dnsBackup.Tcpip6DisabledComponents)
        }
        else {
            $curDcProp = Get-ItemProperty -LiteralPath $tcpip6Key -Name 'DisabledComponents' -ErrorAction SilentlyContinue
            if ($null -ne $curDcProp) {
                Remove-ItemProperty -Path $tcpip6Key -Name 'DisabledComponents' -ErrorAction Stop
            }
            Log 'removed Tcpip6 DisabledComponents (Windows default IPv6 enabled)'
        }
    }
}
catch {
    $rollbackErrors.Add('restoring Tcpip6 DisabledComponents failed: ' + $_.Exception.Message)
    Log ('ERROR restoring Tcpip6 DisabledComponents: ' + $_.Exception.Message)
}

# Restore IPv4 prefix policy to Windows standard (precedence 35)
try {
    $wantPrec = 35; $wantLbl = 4
    if ($dnsBackup -and $dnsBackup.PSObject.Properties.Name -contains 'Ipv4PrefixPolicy' -and $dnsBackup.Ipv4PrefixPolicy) {
        $wantPrec = [int]$dnsBackup.Ipv4PrefixPolicy.Precedence
        $wantLbl = [int]$dnsBackup.Ipv4PrefixPolicy.Label
    }
    $ppOut = netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 $wantPrec $wantLbl 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ('netsh prefixpolicy exit=' + $LASTEXITCODE + ' (' + ($ppOut -join ' ') + ')')
    }
    Log ('restored IPv4 prefix policy: ::ffff:0:0/96 precedence=' + $wantPrec)
}
catch {
    $rollbackErrors.Add('restoring IPv4 prefix policy failed: ' + $_.Exception.Message)
    Log ('ERROR restoring IPv4 prefix policy: ' + $_.Exception.Message)
}

# ------------------------------------------------------------------ 5. NTP server restoration
try {
    $w32TimeKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
    if (Test-Path -LiteralPath $w32TimeKey) {
        $targetNtp = if ($dnsBackup -and $dnsBackup.PSObject.Properties.Name -contains 'NtpServer' -and $dnsBackup.NtpServer) { [string]$dnsBackup.NtpServer } else { 'time.windows.com,0x9' }
        New-ItemProperty -Path $w32TimeKey -Name 'NtpServer' -Value $targetNtp -PropertyType String -Force -ErrorAction Stop | Out-Null
        $w32svc = Get-Service -Name w32time -ErrorAction SilentlyContinue
        if ($w32svc -and $w32svc.Status -eq 'Running') { w32tm /config /update 2>$null | Out-Null }
        Log ('restored NTP server: ' + $targetNtp)
    }
}
catch {
    $rollbackErrors.Add('restoring NTP server failed: ' + $_.Exception.Message)
    Log ('ERROR restoring NTP server: ' + $_.Exception.Message)
}

# ------------------------------------------------------------------ 6. LLMNR, mDNS & SMHNR policy removal
try {
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    if (Test-Path -LiteralPath $key) {
        if ($null -ne (Get-ItemProperty -LiteralPath $key -Name 'EnableMulticast' -ErrorAction SilentlyContinue)) {
            Remove-ItemProperty -Path $key -Name 'EnableMulticast' -ErrorAction Stop
        }
        if ($null -ne (Get-ItemProperty -LiteralPath $key -Name 'DisableSmartNameResolution' -ErrorAction SilentlyContinue)) {
            Remove-ItemProperty -Path $key -Name 'DisableSmartNameResolution' -ErrorAction Stop
        }
        Log 'removed LLMNR & SMHNR group policies (Windows defaults restored)'
    }
    $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
    if (Test-Path -LiteralPath $svcKey) {
        if ($dnsBackup -and ($dnsBackup.PSObject.Properties.Name -contains 'MdnsEnabled') -and $null -ne $dnsBackup.MdnsEnabled) {
            New-ItemProperty -Path $svcKey -Name 'EnableMDNS' -Value ([int]$dnsBackup.MdnsEnabled) -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            Log ('restored Dnscache EnableMDNS: ' + $dnsBackup.MdnsEnabled)
        }
        elseif ($null -ne (Get-ItemProperty -LiteralPath $svcKey -Name 'EnableMDNS' -ErrorAction SilentlyContinue)) {
            Remove-ItemProperty -Path $svcKey -Name 'EnableMDNS' -ErrorAction Stop
            Log 'removed Dnscache EnableMDNS (Windows mDNS default restored)'
        }
    }
}
catch {
    $rollbackErrors.Add('restoring DNS client policies failed: ' + $_.Exception.Message)
    Log ('ERROR restoring DNS client policies: ' + $_.Exception.Message)
}

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
catch {
    $rollbackErrors.Add('restoring WebRTC/DoH browser policy failed: ' + $_.Exception.Message)
    Log ('ERROR removing WebRTC/DoH browser policy: ' + $_.Exception.Message)
}

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
    $nodeIpsToRemove = @()
    $nodeMeta = Join-Path $BackupDir 'node-sync.meta'
    if (Test-Path -LiteralPath $nodeMeta) {
        $metaContent = Get-Content -LiteralPath $nodeMeta -Raw -ErrorAction SilentlyContinue
        if ($metaContent -match '\|([\d\.,]+)\|') {
            $nodeIpsToRemove += @($Matches[1].Split(','))
        }
    }
    $nodeRoutesMeta = Join-Path $BackupDir 'node-routes.meta'
    if (Test-Path -LiteralPath $nodeRoutesMeta) {
        $nrContent = [System.IO.File]::ReadAllText($nodeRoutesMeta, [System.Text.Encoding]::UTF8).Trim()
        if ($nrContent) {
            $nodeIpsToRemove += @($nrContent.Split(','))
        }
    }
    foreach ($nip in @($nodeIpsToRemove | Where-Object { $_ -and ($_ -match '^\d{1,3}(\.\d{1,3}){3}$') } | Select-Object -Unique)) {
        Remove-NetRoute -DestinationPrefix ($nip + '/32') -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
        Remove-NetRoute -DestinationPrefix ($nip + '/32') -PolicyStore PersistentStore -Confirm:$false -ErrorAction SilentlyContinue
        Log ('removed node host route: ' + $nip + '/32')
    }
} catch { }

# ------------------------------------------------------------------ 9. Archive baseline & state files
$bf = Join-Path $BackupDir 'baseline.json'
if (Test-Path -LiteralPath $bf) {
    if ($rollbackErrors.Count -eq 0) {
        $archived = Join-Path $BackupDir ('baseline-rolledback-' + $stamp + '.json')
        Move-Item -LiteralPath $bf -Destination $archived -Force -ErrorAction SilentlyContinue
        Log ('archived baseline.json -> ' + (Split-Path -Leaf $archived))
    }
    else {
        Log 'WARNING: preserving baseline.json because rollback encountered errors (re-run rollback once fixed)'
    }
}

$pf = Join-Path $BackupDir 'guard-policy.json'
if (Test-Path -LiteralPath $pf) {
    if ($rollbackErrors.Count -eq 0) {
        $archivedPol = Join-Path $BackupDir ('guard-policy-rolledback-' + $stamp + '.json')
        Move-Item -LiteralPath $pf -Destination $archivedPol -Force -ErrorAction SilentlyContinue
        Log ('archived guard-policy.json -> ' + (Split-Path -Leaf $archivedPol))
    }
    else {
        Log 'WARNING: preserving guard-policy.json because rollback encountered errors'
    }
}

# Remove dynamic metadata files only when rollback succeeded cleanly (#06)
if ($rollbackErrors.Count -eq 0) {
    foreach ($metaFile in @('mode-state.json', 'node-sync.meta', 'node-routes.meta', 'candidate-nodes.json', 'foreign-block.meta', 'cn-rule.sig', 'cn-file.meta', 'auto-disabled-outbound-allow.json', 'hotplug-ipv6.json', 'b1-guard.meta', 'guard-policy.last-good.json', 'protected-lock.flag', 'v54-migrated.flag')) {
        $mf = Join-Path $BackupDir $metaFile
        if (Test-Path -LiteralPath $mf) {
            Remove-Item -LiteralPath $mf -Force -ErrorAction SilentlyContinue
            Log ('cleaned up metadata: ' + $metaFile)
        }
    }
}
else {
    Log 'WARNING: preserving recovery metadata files because rollback encountered errors'
}

} # end destructive rollback steps (-not $abortDestructiveRollback)

# Unregister deferred self-trigger tasks after restoration completes (#04)
foreach ($dt in $deferredSelfTasks) {
    try {
        Unregister-ScheduledTask -TaskName $dt -Confirm:$false -ErrorAction Stop
        $stillDt = Get-ScheduledTask -TaskName $dt -ErrorAction SilentlyContinue
        if ($stillDt) {
            throw ('scheduled task still present after deferred Unregister-ScheduledTask: ' + $dt)
        }
        Log ('removed deferred self-trigger task: ' + $dt)
    }
    catch {
        $msg = 'failed removing deferred task ' + $dt + ': ' + $_.Exception.Message
        $rollbackErrors.Add($msg)
        Log ('ERROR: ' + $msg)
    }
}

# ------------------------------------------------------------------ 10. Restore directory ACL
# Security invariant (#05): NEVER unlock ACL while rollback had errors or any AI-Guard* task still exists.
$remainingAiTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like 'AI-Guard*' })
if ($KeepAclLocked -or $abortDestructiveRollback -or ($rollbackErrors.Count -gt 0) -or ($remainingAiTasks.Count -gt 0)) {
    Log ('preserving locked install ACL (KeepAclLocked=' + [bool]$KeepAclLocked + ', aborted=' + [bool]$abortDestructiveRollback + ', errors=' + $rollbackErrors.Count + ', remainingTasks=' + $remainingAiTasks.Count + ')')
}
elseif ($Root.Length -gt 3 -and $Root -notmatch '(?i)^[A-Z]:\\(Windows|Program Files|Program Files \(x86\)|Users|ProgramData)(\\|$)') {
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

$rbExit = 0
if ($rollbackErrors.Count -gt 0) {
    $rbExit = 1
    Log ('rollback finished WITH ERRORS (' + $rollbackErrors.Count + '): ' + ($rollbackErrors -join '; '))
}
elseif ($hasRoutingBk) {
    Log 'rollback finished: Windows guard state restored; manual v2rayN routing step listed above'
}
else {
    Log 'rollback finished: 100% SUCCESS'
}
Write-Host ('rollback log: ' + $Log) -ForegroundColor $(if ($rbExit -eq 0) { 'Green' } else { 'Red' })
}
finally {
    if (Get-Command Exit-GuardWriteLock -ErrorAction SilentlyContinue) {
        Exit-GuardWriteLock $rbWriteLock
    }
}
exit $rbExit
