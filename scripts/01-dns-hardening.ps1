<#
.SYNOPSIS
    AI-Net-Guard v5.7.4 - step 1: DNS, IPv6/IPv4-precedence, SMHNR, and NTP hardening.

.DESCRIPTION
    Prepares Windows networking for the v5.1 static guard:

      1. sets every physical adapter's IPv4 DNS to 223.5.5.5 (default v5.1 static
         resolver: routes into Xray's DoH pipeline when TUN is up; works directly
         under AI-Guard-Allow-CN when TUN is off so DHCP cannot inject random ISP
         resolvers),
      2. disables IPv6 binding (ms_tcpip6) on physical adapters (no v6 / AAAA leak),
      3. sets IPv4 precedence above IPv6 (::ffff:0:0/96 precedence 50 > ::/0 40
         immediately via netsh + DisabledComponents=0x20 across reboots), fixing
         multi-second AAAA stalls in Python urllib / CLI tools,
      4. turns off LLMNR and NetBIOS name resolution,
      5. ensures Windows NTP uses domestic servers (ntp.aliyun.com / ntp.tencent.com)
         if currently set only to foreign time.windows.com, preventing VLESS+REALITY
         clock-skew deadlocks after sleep/reboot while TUN is off,
      6. flushes the resolver cache and verifies resolution.

    Optional, opt-in with -UseNrpt:
      7. registers DoH-only resolver (no UDP fallback) and adds a "." NRPT rule.

    Nothing here touches the firewall. 02-killswitch.ps1 does that.

.NOTES
    Windows 11 24H2 / PowerShell 5.1 or 7.x. Must be elevated.
    Undo with 09-rollback.ps1 (restores the JSON backup written here).
#>

[CmdletBinding()]
param(
    [string]$Root = $(if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\AI-Net-Guard' }),
    [Alias('DohServer')]
    [string]$DnsServer = '223.5.5.5',
    [string]$DohTemplate = '',
    [string]$TunName = 'xray_tun',
    [switch]$SkipIpv6Disable,
    [switch]$SkipIpv4Prefer,
    [switch]$SkipLlmnrNetbios,
    [switch]$SkipSmhnr,
    [switch]$SkipNtp,
    [switch]$UseNrpt,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'ERROR: run this script in an elevated PowerShell (Run as administrator).' -ForegroundColor Red
        exit 1
    }
}

function Write-Step($text) { Write-Host ('[+] ' + $text) -ForegroundColor Cyan }

Assert-Admin

if ($UseNrpt -and -not $PSBoundParameters.ContainsKey('DnsServer')) {
    $DnsServer = '1.1.1.1'
}
if (-not $DohTemplate) {
    $DohTemplate = if ($DnsServer -eq '223.5.5.5') { 'https://223.5.5.5/dns-query' } else { 'https://cloudflare-dns.com/dns-query' }
}

# ------------------------------------------------------------------ guards
# 1) When using 1.1.1.1 or NRPT DoH-only, DNS fails closed without the tunnel.
#    With v5.1 static 223.5.5.5 (no NRPT), DNS works both with and without TUN.
$tun = Get-NetAdapter -Name $TunName -ErrorAction SilentlyContinue
$tunUp = ($tun -and $tun.Status -eq 'Up')
if (($UseNrpt -or $DnsServer -notin @('223.5.5.5', '223.6.6.6')) -and -not $tunUp) {
    if (-not $Force) {
        Write-Host ('ERROR: TUN adapter "' + $TunName + '" is not up, and ' + $DnsServer + ' requires the tunnel. Start v2rayN TUN first (or pass -Force).') -ForegroundColor Red
        exit 1
    }
    Write-Host 'WARNING: TUN not up, -Force given; foreign resolver will be unreachable until TUN starts.' -ForegroundColor Yellow
}

# 2) Never overwrite the first baseline: a second run must not make rollback
#    restore the hardened state instead of the original one.
$BackupDir = Join-Path $Root 'backup'
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
$BaselineFile = Join-Path $BackupDir 'baseline.json'
$baseline = $null
if (Test-Path -LiteralPath $BaselineFile) {
    try { $baseline = Get-Content -LiteralPath $BaselineFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
}
if ($baseline -and $baseline.Dns -and -not $Force) {
    Write-Host 'ERROR: a DNS baseline already exists (AI-Guard was applied before).' -ForegroundColor Red
    Write-Host ('       ' + $BaselineFile) -ForegroundColor DarkGray
    Write-Host '       Run 09-rollback.ps1 first, or pass -Force to re-apply without touching the baseline.' -ForegroundColor Red
    exit 1
}

$BackupFile = Join-Path $BackupDir ('dns-' + $stamp + '.json')

# ------------------------------------------------------------------ backup
Write-Step 'backing up current DNS / IPv6 / prefix-policy / NTP / name-resolution state'

$dnsBackup = @()
foreach ($a in (Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue)) {
    $servers = @()
    $wasStatic = $false
    try {
        $d = Get-DnsClientServerAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction Stop
        $servers = @($d.ServerAddresses)
    } catch { }
    try {
        $guid = $a.InterfaceGuid
        if ($guid) {
            $reg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" -ErrorAction SilentlyContinue
            if ($reg -and $reg.NameServer) { $wasStatic = $true }
        }
    } catch { }
    $dnsBackup += [pscustomobject]@{
        Name          = $a.Name
        InterfaceGuid = $a.InterfaceGuid
        Description   = $a.InterfaceDescription
        Ipv4Servers   = $servers
        WasStatic     = $wasStatic
        Ipv6Binding   = ((Get-NetAdapterBinding -Name $a.Name -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue).Enabled)
    }
}

$nrptBackup = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Select-Object Name, Namespace, NameServers, Comment)
$dohBackup = @(Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | Select-Object ServerAddress, DohTemplate, AllowFallbackToUdp, AutoUpgrade)

$policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
$dnscacheParamKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
$multicast = $null
$smhnrPol = $null
$smhnrSvc = $null
if (Test-Path -LiteralPath $policyKey) {
    $polProps = Get-ItemProperty -LiteralPath $policyKey -ErrorAction SilentlyContinue
    if ($polProps) {
        $multicast = $polProps.EnableMulticast
        $smhnrPol = $polProps.DisableSmartNameResolution
    }
}
if (Test-Path -LiteralPath $dnscacheParamKey) {
    $smhnrSvc = (Get-ItemProperty -LiteralPath $dnscacheParamKey -ErrorAction SilentlyContinue).DisableSmartNameResolution
}

$netbiosBackup = @()
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue | ForEach-Object {
    $v = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).NetbiosOptions
    $netbiosBackup += [pscustomobject]@{ Key = $_.PSChildName; NetbiosOptions = $v }
}

$tcpip6Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
$disabledComp = $null
if (Test-Path -LiteralPath $tcpip6Key) {
    $disabledComp = (Get-ItemProperty -LiteralPath $tcpip6Key -ErrorAction SilentlyContinue).DisabledComponents
}

$v4PrefixBackup = $null
try {
    $pol = Get-NetPrefixPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Prefix -eq '::ffff:0:0/96' } | Select-Object -First 1
    if ($pol) {
        $v4PrefixBackup = [pscustomobject]@{ Precedence = [int]$pol.Precedence; Label = [int]$pol.Label }
    }
} catch { }

$w32TimeKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
$ntpOrig = $null
if (Test-Path -LiteralPath $w32TimeKey) {
    $ntpOrig = (Get-ItemProperty -LiteralPath $w32TimeKey -ErrorAction SilentlyContinue).NtpServer
}

$backup = [pscustomobject]@{
    Version                    = '5.4'
    Created                    = (Get-Date).ToString('o')
    Dns                        = $dnsBackup
    Nrpt                       = $nrptBackup
    Doh                        = $dohBackup
    Llmnr                      = $multicast
    SmartNameResolutionPolicy  = $smhnrPol
    SmartNameResolutionService = $smhnrSvc
    Netbios                    = $netbiosBackup
    DohServer                  = $DnsServer
    Tcpip6DisabledComponents   = $disabledComp
    Ipv4PrefixPolicy           = $v4PrefixBackup
    NtpServer                  = $ntpOrig
}
$backup | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $BackupFile -Encoding UTF8
Write-Host ('    backup: ' + $BackupFile) -ForegroundColor DarkGray

# first baseline wins; later -Force re-runs keep the original rollback target
if (-not $baseline) {
    [pscustomobject]@{
        Created = (Get-Date).ToString('o')
        Dns     = $BackupFile
    } | ConvertTo-Json | Set-Content -LiteralPath $BaselineFile -Encoding UTF8
    Write-Host ('    baseline: ' + $BaselineFile) -ForegroundColor DarkGray
}
elseif (-not $baseline.Dns) {
    $baseline | Add-Member -NotePropertyName Dns -NotePropertyValue $BackupFile -Force
    $baseline | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $BaselineFile -Encoding UTF8
}

# ------------------------------------------------------------------ 1. DoH / NRPT (opt-in)
if ($UseNrpt) {
    Write-Step ('registering DoH resolver ' + $DnsServer + ' (no plaintext fallback)')

    if (-not (Get-Command Add-DnsClientDohServerAddress -ErrorAction SilentlyContinue)) {
        throw 'This Windows build does not provide Add-DnsClientDohServerAddress (needs Windows 11 / Server 2022+).'
    }

    $existing = Get-DnsClientDohServerAddress -ServerAddress $DnsServer -ErrorAction SilentlyContinue
    if ($existing) {
        Set-DnsClientDohServerAddress -ServerAddress $DnsServer -DohTemplate $DohTemplate -AllowFallbackToUdp $false -AutoUpgrade $true
    }
    else {
        Add-DnsClientDohServerAddress -ServerAddress $DnsServer -DohTemplate $DohTemplate -AllowFallbackToUdp $false -AutoUpgrade $true
    }

    Write-Step 'creating NRPT rule: every name -> DoH, no per-adapter resolver'
    Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
        Where-Object { $_.Comment -like 'AI-Guard*' } |
        Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue

    Add-DnsClientNrptRule -Namespace '.' -NameServers $DnsServer -Comment 'AI-Guard: DoH-only DNS' | Out-Null
}
else {
    Write-Step ('NRPT not requested: using v5.1 static adapter DNS (' + $DnsServer + ')')
}

# ------------------------------------------------------------------ 2. adapters
Write-Step ('setting physical adapter IPv4 DNS -> ' + $DnsServer)

$physical = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
    Where-Object {
        $_.InterfaceDescription -notmatch '(?i)Wintun|sing-tun|Mihomo|Virtual|Miniport|Kernel' -and
        $_.Name -ne $TunName -and
        $_.Name -notmatch '(?i)Loopback|\*' -and
        $_.Status -ne 'Not Present'
    })

foreach ($a in $physical) {
    try {
        Set-DnsClientServerAddress -InterfaceAlias $a.Name -ServerAddresses $DnsServer -ErrorAction Stop
        Write-Host ('    ' + $a.Name + ' -> ' + $DnsServer)
    }
    catch {
        Write-Host ('    ' + $a.Name + ' : ' + $_.Exception.Message) -ForegroundColor Yellow
    }
}

# ------------------------------------------------------------------ 3. IPv6 binding
if (-not $SkipIpv6Disable) {
    Write-Step 'disabling IPv6 binding on physical adapters (no v6 default route / AAAA leak)'
    foreach ($a in $physical) {
        try {
            $b = Get-NetAdapterBinding -Name $a.Name -ComponentID 'ms_tcpip6' -ErrorAction Stop
            if ($b -and $b.Enabled) {
                Disable-NetAdapterBinding -Name $a.Name -ComponentID 'ms_tcpip6' -ErrorAction Stop
                Write-Host ('    ' + $a.Name + ' : ms_tcpip6 disabled')
            }
        }
        catch {
            Write-Host ('    ' + $a.Name + ' : ' + $_.Exception.Message) -ForegroundColor Yellow
        }
    }
}

# ------------------------------------------------------------------ 4. Prefer IPv4 over IPv6
if (-not $SkipIpv4Prefer) {
    Write-Step 'setting IPv4 precedence above IPv6 (fixes Python urllib / CLI AAAA timeout stalls)'
    try {
        $newVal = 0x20
        if ($null -ne $disabledComp) { $newVal = ([int]$disabledComp -bor 0x20) }
        if (-not (Test-Path -LiteralPath $tcpip6Key)) { New-Item -Path $tcpip6Key -Force | Out-Null }
        New-ItemProperty -Path $tcpip6Key -Name 'DisabledComponents' -Value $newVal -PropertyType DWord -Force | Out-Null
        netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 50 4 | Out-Null
        Write-Host '    ::ffff:0:0/96 precedence=50 (> ::/0=40), DisabledComponents|=0x20'
    }
    catch {
        Write-Host ('    IPv4 precedence warning: ' + $_.Exception.Message) -ForegroundColor Yellow
    }
}

# ------------------------------------------------------------------ 5. LLMNR / NetBIOS / SMHNR
if (-not $SkipLlmnrNetbios) {
    Write-Step 'disabling LLMNR and NetBIOS name resolution'
    if (-not (Test-Path -LiteralPath $policyKey)) { New-Item -Path $policyKey -Force | Out-Null }
    New-ItemProperty -Path $policyKey -Name 'EnableMulticast' -Value 0 -PropertyType DWord -Force | Out-Null
    foreach ($a in $physical) {
        if (-not $a.InterfaceGuid) { continue }
        $nbKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_' + $a.InterfaceGuid
        if (Test-Path -LiteralPath $nbKey) {
            New-ItemProperty -Path $nbKey -Name 'NetbiosOptions' -Value 2 -PropertyType DWord -Force | Out-Null
        }
    }
}

if (-not $SkipSmhnr) {
    Write-Step 'disabling Windows Smart Multi-Homed Name Resolution (SMHNR)'
    if (-not (Test-Path -LiteralPath $policyKey)) { New-Item -Path $policyKey -Force | Out-Null }
    New-ItemProperty -Path $policyKey -Name 'DisableSmartNameResolution' -Value 1 -PropertyType DWord -Force | Out-Null
    if (Test-Path -LiteralPath $dnscacheParamKey) {
        New-ItemProperty -Path $dnscacheParamKey -Name 'DisableSmartNameResolution' -Value 1 -PropertyType DWord -Force | Out-Null
    }
}

# ------------------------------------------------------------------ 6. Domestic NTP (for VLESS+REALITY clock accuracy)
if (-not $SkipNtp) {
    Write-Step 'checking Windows NTP peer list (prevents VLESS+REALITY clock-skew deadlock when TUN is off)'
    try {
        $curNtp = [string]$ntpOrig
        # A peer list counts as healthy only if it names a known-working domestic peer.
        # www.time.ac.cn no longer answers NTP (0x800705B4 timeout), so a list that still
        # carries it is migrated even when it also contains a working peer.
        if ($curNtp -match '(?i)(aliyun|tencent|ntsc\.ac\.cn|203\.107\.6\.88)' -and $curNtp -notmatch '(?i)www\.time\.ac\.cn') {
            Write-Host ('    NTP already domestic-capable: ' + $curNtp)
        }
        else {
            $newNtp = 'ntp.aliyun.com,0x9 ntp.tencent.com,0x9 ntp.ntsc.ac.cn,0x9'
            New-ItemProperty -Path $w32TimeKey -Name 'NtpServer' -Value $newNtp -PropertyType String -Force | Out-Null
            $w32svc = Get-Service -Name w32time -ErrorAction SilentlyContinue
            if ($w32svc -and $w32svc.Status -eq 'Running') {
                w32tm /config /update 2>$null | Out-Null
                w32tm /resync /nowait 2>$null | Out-Null
            }
            Write-Host ('    NTP updated: ' + $newNtp)
        }
    }
    catch {
        Write-Host ('    NTP check warning: ' + $_.Exception.Message) -ForegroundColor Yellow
    }
}

# ------------------------------------------------------------------ 7. flush + verify
Write-Step 'flushing resolver cache and verifying'
Clear-DnsClientCache -ErrorAction SilentlyContinue
ipconfig /flushdns | Out-Null

Write-Host ''
Write-Host '--- verification ---' -ForegroundColor Cyan
Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize

$probeHost = if ($tunUp) { 'www.google.com' } else { 'www.baidu.com' }
$ok = $false
try {
    $r = Resolve-DnsName -Name $probeHost -Type A -ErrorAction Stop | Where-Object { $_.IPAddress }
    if ($r) {
        $ok = $true
        Write-Host ('DNS resolution works: ' + $probeHost + ' -> ' + (($r.IPAddress) -join ', ')) -ForegroundColor Green
    }
}
catch {
    Write-Host ('DNS resolution FAILED for ' + $probeHost + ': ' + $_.Exception.Message) -ForegroundColor Red
}

Write-Host ''
if ($ok) { Write-Host 'STEP 1 OK. Next: 02-killswitch.ps1' -ForegroundColor Green }
else { Write-Host 'STEP 1 finished with DNS warning. Check connectivity/TUN, then proceed to 02-killswitch.ps1.' -ForegroundColor Yellow }
Write-Host ('Backup for rollback: ' + $BackupFile) -ForegroundColor DarkGray
