<#
.SYNOPSIS
    AI-Net-Guard v5.4 - rollback: restore tasks, firewall, DNS, NRPT, IPv6, prefix policy, NTP, LLMNR, SMHNR, NetBIOS.

.DESCRIPTION
    Restores the FIRST baseline captured by 01-dns-hardening.ps1 / 02-killswitch.ps1
    (recorded in <Root>\backup\baseline.json).

    v5.1 improvements:
      * Stops and unregisters AI-Guard-Mode-Watcher, AI-Guard-Mode-Fallback, and
        AI-Guard-Boot-Guard FIRST, and terminates any running watchdog.ps1
        process so it cannot re-lock the firewall 5 minutes after rollback.
      * Restores IPv6 bindings on both baseline adapters and any hot-plugged
        adapters recorded in backup\hotplug-ipv6.json.
      * Restores IPv4/IPv6 prefix policy (::ffff:0:0/96 precedence) and
        Tcpip6\Parameters\DisabledComponents, plus W32Time NtpServer if changed.
      * Cleans v5 runtime state files (cn-rule.sig, legacy-rules-cleaned.flag,
        mode-state.json) and archives baseline.json on clean rollback so future
        installs are not blocked.

    Safety: only unregisters AI-Guard-Test-Rollback when postconditions hold.
    On failure it writes rollback-FAILED-*.txt and re-arms the task for +5 min.
#>

[CmdletBinding()]
param(
    [string]$Root = $(if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\AI-Net-Guard' }),
    [string]$DohServer = '1.1.1.1',
    [switch]$Auto,
    [switch]$Force
)

$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogDir = Join-Path $Root 'logs'
$BackupDir = Join-Path $Root 'backup'
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$Log = Join-Path $LogDir ('rollback-' + $stamp + '.txt')
$script:ok = $true

function Log($msg) {
    $line = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '  ' + $msg
    Write-Host $line
    Add-Content -LiteralPath $Log -Value $line -Encoding UTF8
}
function Mark-Fail($msg) {
    $script:ok = $false
    Log ('FAIL: ' + $msg)
}

# ------------------------------------------------------------------ admin
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'ERROR: rollback must run elevated (the SYSTEM task is elevated automatically).' -ForegroundColor Red
    exit 1
}

Log 'AI-Net-Guard v5.4 rollback started'
Log ('user: ' + $id.Name)
if ($Auto) { Log 'mode: automatic (scheduled task)' }

# ------------------------------------------------------------------ 0. stop watchdog & background tasks FIRST
$dynModeTasks = @(Get-ScheduledTask -TaskName 'AI-Guard-Mode-*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty TaskName)
foreach ($tn in (@('AI-Guard-Mode-Event', 'AI-Guard-Mode-Watcher', 'AI-Guard-Mode-Fallback', 'AI-Guard-Mode-Watchdog', 'AI-Guard-Boot-Guard') + $dynModeTasks | Select-Object -Unique)) {
    try {
        $t = Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
        if ($t) {
            Stop-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction Stop
            Log ('removed scheduled task: ' + $tn)
        }
    }
    catch { Mark-Fail ('removing task ' + $tn + ': ' + $_.Exception.Message) }
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

# ------------------------------------------------------------------ baseline
function Get-Baseline {
    $b = $null
    $bf = Join-Path $BackupDir 'baseline.json'
    if (Test-Path -LiteralPath $bf) {
        try { $b = Get-Content -LiteralPath $bf -Raw | ConvertFrom-Json } catch { Log ('ERROR reading baseline.json: ' + $_.Exception.Message) }
    }
    if (-not $b) {
        Log 'baseline.json missing, falling back to the OLDEST backup files'
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

# ------------------------------------------------------------------ 1. firewall
if ($baseline.Firewall -and (Test-Path -LiteralPath $baseline.Firewall)) {
    Log ('importing firewall backup: ' + $baseline.Firewall)
    $out = netsh advfirewall import "$($baseline.Firewall)" 2>&1
    Log ($out -join ' ')
    if ($LASTEXITCODE -ne 0) {
        Mark-Fail 'netsh advfirewall import returned non-zero'
        Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultOutboundAction Allow
        Log 'fallback: DefaultOutboundAction set to Allow'
    }
}
else {
    Mark-Fail 'firewall baseline not found'
    Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultOutboundAction Allow
    Log 'fallback: DefaultOutboundAction set to Allow'
}

if ($baseline.AllowRules -and (Test-Path -LiteralPath $baseline.AllowRules)) {
    Log ('re-enabling outbound allow rules from ' + (Split-Path -Leaf $baseline.AllowRules))
    try {
        $items = @(Get-Content -LiteralPath $baseline.AllowRules -Raw | ConvertFrom-Json)
        $n = 0
        foreach ($i in $items) {
            try { Enable-NetFirewallRule -Name $i.Name -ErrorAction Stop; $n++ }
            catch { }
        }
        Log ('re-enabled: ' + $n + ' / ' + $items.Count)
    }
    catch { Mark-Fail ('reading allow-rule list: ' + $_.Exception.Message) }
}
else {
    Log 'no allow-rule baseline (skipped)'
}

$autoQuarantine = Join-Path $BackupDir 'auto-disabled-outbound-allow.json'
if (Test-Path -LiteralPath $autoQuarantine) {
    try {
        $qItems = @(Get-Content -LiteralPath $autoQuarantine -Raw | ConvertFrom-Json)
        $qn = 0
        foreach ($qi in $qItems) {
            try { Enable-NetFirewallRule -Name $qi.Name -ErrorAction Stop; $qn++ }
            catch { }
        }
        Log ('re-enabled auto-quarantined rules: ' + $qn + ' / ' + $qItems.Count)
    }
    catch { }
}

try {
    $ai = @(Get-NetFirewallRule -DisplayName 'AI-Guard-*' -ErrorAction SilentlyContinue) +
          @(Get-NetFirewallRule -Name 'AI-Guard-*' -ErrorAction SilentlyContinue) |
          Select-Object -Unique
    if ($ai.Count -gt 0) {
        $ai | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Log ('removed AI-Guard rules: ' + $ai.Count)
    }
}
catch { Mark-Fail ('removing AI-Guard rules: ' + $_.Exception.Message) }

# ------------------------------------------------------------------ 2. NRPT + DoH + DNS + IPv6 + PrefixPolicy + NTP
try {
    $nrpt = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -like 'AI-Guard*' })
    if ($nrpt.Count -gt 0) {
        $nrpt | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue
        Log ('removed NRPT rules: ' + $nrpt.Count)
    }
}
catch { Mark-Fail ('removing NRPT: ' + $_.Exception.Message) }

$dnsBackup = $null
if ($baseline.Dns -and (Test-Path -LiteralPath $baseline.Dns)) {
    Log ('restoring DNS from ' + (Split-Path -Leaf $baseline.Dns))
    try { $dnsBackup = Get-Content -LiteralPath $baseline.Dns -Raw | ConvertFrom-Json }
    catch { Mark-Fail ('reading DNS backup: ' + $_.Exception.Message) }
}
else {
    Mark-Fail 'DNS baseline not found'
}

if ($dnsBackup) {
    $dohTargets = @($DohServer, '1.1.1.1', '223.5.5.5')
    if ($dnsBackup.DohServer) { $dohTargets += [string]$dnsBackup.DohServer }
    $dohTargets = @($dohTargets | Where-Object { $_ } | Select-Object -Unique)

    foreach ($srv in $dohTargets) {
        try {
            $orig = @($dnsBackup.Doh) | Where-Object { $_.ServerAddress -eq $srv } | Select-Object -First 1
            $cur = Get-DnsClientDohServerAddress -ServerAddress $srv -ErrorAction SilentlyContinue
            if ($orig -and $cur) {
                Set-DnsClientDohServerAddress -ServerAddress $srv -DohTemplate $orig.DohTemplate -AllowFallbackToUdp ([bool]$orig.AllowFallbackToUdp) -AutoUpgrade ([bool]$orig.AutoUpgrade) -ErrorAction Stop
                Log ('restored DoH flags for ' + $srv)
            }
            elseif (-not $orig -and $cur) {
                Remove-DnsClientDohServerAddress -ServerAddress $srv -ErrorAction SilentlyContinue
                Log ('removed DoH registration for ' + $srv + ' (was not present before)')
            }
        }
        catch { Mark-Fail ('restoring DoH for ' + $srv + ': ' + $_.Exception.Message) }
    }

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
        catch { Mark-Fail ('restoring DNS for ' + $d.Name + ': ' + $_.Exception.Message) }

        try {
            if ($d.Ipv6Binding -eq $true) {
                $b = Get-NetAdapterBinding -Name $d.Name -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue
                if ($b -and -not $b.Enabled) {
                    Enable-NetAdapterBinding -Name $d.Name -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue
                    Log ('IPv6 re-enabled: ' + $d.Name)
                }
            }
        }
        catch { Mark-Fail ('IPv6 restore ' + $d.Name + ': ' + $_.Exception.Message) }
    }

    # Also restore IPv6 on any hot-plugged adapters hardened by 07-mode.ps1
    $hotplugFile = Join-Path $BackupDir 'hotplug-ipv6.json'
    if (Test-Path -LiteralPath $hotplugFile) {
        try {
            $hpNames = @(Get-Content -LiteralPath $hotplugFile -Raw | ConvertFrom-Json)
            foreach ($hn in $hpNames) {
                $b = Get-NetAdapterBinding -Name $hn -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue
                if ($b -and -not $b.Enabled) {
                    Enable-NetAdapterBinding -Name $hn -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue
                    Log ('IPv6 re-enabled (hot-plugged NIC): ' + $hn)
                }
            }
        }
        catch { }
    }

    # Restore Tcpip6 DisabledComponents and live IPv4 prefix policy
    try {
        $tcpip6Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
        if ($dnsBackup.PSObject.Properties.Name -contains 'Tcpip6DisabledComponents') {
            if ($null -eq $dnsBackup.Tcpip6DisabledComponents) {
                Remove-ItemProperty -Path $tcpip6Key -Name 'DisabledComponents' -ErrorAction SilentlyContinue
                Log 'Tcpip6 DisabledComponents removed (as before)'
            }
            else {
                New-ItemProperty -Path $tcpip6Key -Name 'DisabledComponents' -Value ([int]$dnsBackup.Tcpip6DisabledComponents) -PropertyType DWord -Force | Out-Null
                Log ('Tcpip6 DisabledComponents restored: ' + $dnsBackup.Tcpip6DisabledComponents)
            }
        }
        $wantPrec = 35; $wantLbl = 4
        if ($dnsBackup.PSObject.Properties.Name -contains 'Ipv4PrefixPolicy' -and $dnsBackup.Ipv4PrefixPolicy) {
            $wantPrec = [int]$dnsBackup.Ipv4PrefixPolicy.Precedence
            $wantLbl = [int]$dnsBackup.Ipv4PrefixPolicy.Label
        }
        netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 $wantPrec $wantLbl | Out-Null
        Log ('IPv4 prefix policy restored: ::ffff:0:0/96 precedence=' + $wantPrec + ' label=' + $wantLbl)
    }
    catch { Mark-Fail ('IPv4 prefix policy restore: ' + $_.Exception.Message) }

    # Restore NTP server if backed up
    try {
        if ($dnsBackup.PSObject.Properties.Name -contains 'NtpServer' -and $null -ne $dnsBackup.NtpServer) {
            $w32TimeKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
            if (Test-Path -LiteralPath $w32TimeKey) {
                $curNtp = (Get-ItemProperty -LiteralPath $w32TimeKey -ErrorAction SilentlyContinue).NtpServer
                if ($curNtp -ne $dnsBackup.NtpServer) {
                    New-ItemProperty -Path $w32TimeKey -Name 'NtpServer' -Value ([string]$dnsBackup.NtpServer) -PropertyType String -Force | Out-Null
                    $w32svc = Get-Service -Name w32time -ErrorAction SilentlyContinue
                    if ($w32svc -and $w32svc.Status -eq 'Running') { w32tm /config /update 2>$null | Out-Null }
                    Log ('NTP server restored: ' + $dnsBackup.NtpServer)
                }
            }
        }
    }
    catch { Mark-Fail ('NTP restore: ' + $_.Exception.Message) }

    try {
        $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        if ($null -eq $dnsBackup.Llmnr) {
            Remove-ItemProperty -Path $key -Name 'EnableMulticast' -ErrorAction SilentlyContinue
            Log 'LLMNR policy value removed (as before)'
        }
        else {
            New-ItemProperty -Path $key -Name 'EnableMulticast' -Value ([int]$dnsBackup.Llmnr) -PropertyType DWord -Force | Out-Null
            Log ('LLMNR restored: ' + $dnsBackup.Llmnr)
        }

        if ($dnsBackup.PSObject.Properties.Name -contains 'SmartNameResolutionPolicy') {
            if ($null -eq $dnsBackup.SmartNameResolutionPolicy) {
                Remove-ItemProperty -Path $key -Name 'DisableSmartNameResolution' -ErrorAction SilentlyContinue
                Log 'SMHNR policy value removed (as before)'
            }
            else {
                New-ItemProperty -Path $key -Name 'DisableSmartNameResolution' -Value ([int]$dnsBackup.SmartNameResolutionPolicy) -PropertyType DWord -Force | Out-Null
                Log ('SMHNR policy restored: ' + $dnsBackup.SmartNameResolutionPolicy)
            }
        }

        $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
        if ($dnsBackup.PSObject.Properties.Name -contains 'SmartNameResolutionService' -and (Test-Path -LiteralPath $svcKey)) {
            if ($null -eq $dnsBackup.SmartNameResolutionService) {
                Remove-ItemProperty -Path $svcKey -Name 'DisableSmartNameResolution' -ErrorAction SilentlyContinue
            }
            else {
                New-ItemProperty -Path $svcKey -Name 'DisableSmartNameResolution' -Value ([int]$dnsBackup.SmartNameResolutionService) -PropertyType DWord -Force | Out-Null
            }
        }
    }
    catch { Mark-Fail ('LLMNR/SMHNR restore: ' + $_.Exception.Message) }

    try {
        foreach ($nb in @($dnsBackup.Netbios)) {
            $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\' + $nb.Key
            if (Test-Path -LiteralPath $k) {
                if ($null -eq $nb.NetbiosOptions) {
                    Remove-ItemProperty -Path $k -Name 'NetbiosOptions' -ErrorAction SilentlyContinue
                }
                else {
                    New-ItemProperty -Path $k -Name 'NetbiosOptions' -Value ([int]$nb.NetbiosOptions) -PropertyType DWord -Force | Out-Null
                }
            }
        }
        Log 'NetBIOS options restored'
    }
    catch { Mark-Fail ('NetBIOS restore: ' + $_.Exception.Message) }
}

# Clean up v5/v5.4 runtime markers
foreach ($mf in @('cn-rule.sig', 'cn-file.meta', 'node-sync.meta', 'v54-migrated.flag', 'auto-disabled-outbound-allow.json', 'legacy-rules-cleaned.flag', 'legacy-rules-cleaned-v51.flag', 'mode-state.json', 'hotplug-ipv6.json', 'boot-guard.json')) {
    $mp = Join-Path $BackupDir $mf
    if (Test-Path -LiteralPath $mp) {
        Remove-Item -LiteralPath $mp -Force -ErrorAction SilentlyContinue
    }
}

# ------------------------------------------------------------------ postconditions
try {
    $leftTasks = @(Get-ScheduledTask -TaskName 'AI-Guard-Mode-*' -ErrorAction SilentlyContinue)
    if ($leftTasks.Count -gt 0) { Mark-Fail ('AI-Guard-Mode-* tasks still registered: ' + $leftTasks.Count) }
    else { Log 'postcondition OK: no AI-Guard-Mode-* tasks' }
}
catch { }

try {
    $left = @(Get-NetFirewallRule -DisplayName 'AI-Guard-*' -ErrorAction SilentlyContinue) +
            @(Get-NetFirewallRule -Name 'AI-Guard-*' -ErrorAction SilentlyContinue) |
            Select-Object -Unique
    if ($left.Count -gt 0) { Mark-Fail ('AI-Guard rules still present: ' + $left.Count) }
    else { Log 'postcondition OK: no AI-Guard rules' }
}
catch { Mark-Fail ('postcondition check: ' + $_.Exception.Message) }

try {
    $nrptLeft = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -like 'AI-Guard*' })
    if ($nrptLeft.Count -gt 0) { Mark-Fail ('AI-Guard NRPT rules still present: ' + $nrptLeft.Count) }
    else { Log 'postcondition OK: no AI-Guard NRPT rules' }
}
catch { }

if ($dnsBackup) {
    $mismatch = @()
    foreach ($d in @($dnsBackup.Dns)) {
        if (-not ($d.WasStatic -and @($d.Ipv4Servers).Count -gt 0)) { continue }
        try {
            $exists = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $d.Name }
            if (-not $exists) { continue }
            $cur = @((Get-DnsClientServerAddress -InterfaceAlias $d.Name -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses)
            if ((($cur | Sort-Object) -join ',') -ne ((@($d.Ipv4Servers) | Sort-Object) -join ',')) {
                $mismatch += ($d.Name + ': now=' + ($cur -join ',') + ' want=' + (@($d.Ipv4Servers) -join ','))
            }
        }
        catch { }
    }
    if ($mismatch.Count -gt 0) { Mark-Fail ('DNS mismatch after restore: ' + ($mismatch -join '; ')) }
    else { Log 'postcondition OK: static DNS matches baseline' }

    $v6bad = @()
    foreach ($d in @($dnsBackup.Dns)) {
        if ($d.Ipv6Binding -ne $true) { continue }
        try {
            $b = Get-NetAdapterBinding -Name $d.Name -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue
            if ($b -and -not $b.Enabled) { $v6bad += $d.Name }
        }
        catch { }
    }
    if ($v6bad.Count -gt 0) { Mark-Fail ('IPv6 still disabled on: ' + ($v6bad -join ',')) }
    else { Log 'postcondition OK: IPv6 bindings restored' }

    try {
        $polProps = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
        $cur = if ($polProps) { $polProps.EnableMulticast } else { $null }
        if ($null -eq $dnsBackup.Llmnr -and $null -ne $cur) { Mark-Fail ('LLMNR EnableMulticast still set: ' + $cur) }
        elseif ($null -ne $dnsBackup.Llmnr -and $cur -ne $dnsBackup.Llmnr) { Mark-Fail ('LLMNR mismatch: now=' + $cur + ' want=' + $dnsBackup.Llmnr) }
        else { Log 'postcondition OK: LLMNR restored' }

        if ($dnsBackup.PSObject.Properties.Name -contains 'SmartNameResolutionPolicy') {
            $curSm = if ($polProps) { $polProps.DisableSmartNameResolution } else { $null }
            if ($null -eq $dnsBackup.SmartNameResolutionPolicy -and $null -ne $curSm) { Mark-Fail ('SMHNR DisableSmartNameResolution still set: ' + $curSm) }
            elseif ($null -ne $dnsBackup.SmartNameResolutionPolicy -and $curSm -ne $dnsBackup.SmartNameResolutionPolicy) { Mark-Fail ('SMHNR mismatch: now=' + $curSm + ' want=' + $dnsBackup.SmartNameResolutionPolicy) }
            else { Log 'postcondition OK: SMHNR restored' }
        }
    }
    catch { }
}

try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch { }
ipconfig /flushdns | Out-Null

# ------------------------------------------------------------------ task & baseline archive
$task = Get-ScheduledTask -TaskName 'AI-Guard-Test-Rollback' -ErrorAction SilentlyContinue
if ($script:ok) {
    if ($task) {
        Unregister-ScheduledTask -TaskName 'AI-Guard-Test-Rollback' -Confirm:$false
        Log 'auto-rollback task removed'
    }
    $bf = Join-Path $BackupDir 'baseline.json'
    if (Test-Path -LiteralPath $bf) {
        $archived = Join-Path $BackupDir ('baseline-rolledback-' + $stamp + '.json')
        Move-Item -LiteralPath $bf -Destination $archived -Force -ErrorAction SilentlyContinue
        Log ('archived baseline.json -> ' + (Split-Path -Leaf $archived))
    }
    Log 'rollback finished: SUCCESS'
    Write-Host ('rollback log: ' + $Log) -ForegroundColor Green
}
else {
    Log 'rollback finished with ERRORS'
    $failLog = Join-Path $LogDir ('rollback-FAILED-' + $stamp + '.txt')
    Copy-Item -LiteralPath $Log -Destination $failLog -Force
    Write-Host ('ROLLBACK INCOMPLETE - see ' + $failLog) -ForegroundColor Red
    if ($task) {
        try {
            $t = Get-ScheduledTask -TaskName 'AI-Guard-Test-Rollback'
            $t.Triggers | ForEach-Object { $_.StartBoundary = (Get-Date).AddMinutes(5).ToString('s') }
            Set-ScheduledTask -TaskName 'AI-Guard-Test-Rollback' -Trigger $t.Triggers | Out-Null
            Log 're-armed the auto-rollback task for +5 minutes'
        }
        catch { Log ('could not re-arm task: ' + $_.Exception.Message) }
    }
    exit 1
}
