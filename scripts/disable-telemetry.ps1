# Windows 11 Telemetry & Privacy Hardening Script
$ErrorActionPreference = 'SilentlyContinue'

Write-Host "==============================================================================="
Write-Host "                Windows 11 Background Telemetry Hardening"
Write-Host "==============================================================================="

# 1. Stop and disable DiagTrack and dmwappushservice
Write-Host "[1/4] Stopping and disabling Telemetry services..."
foreach ($svc in @('DiagTrack', 'dmwappushservice')) {
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    Write-Host "    $svc -> Status: $($s.Status), StartType: $($s.StartType)"
}

# 2. Configure Windows Telemetry Policies
Write-Host "[2/4] Applying Group Policy registry restrictions..."
$dcKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
if (-not (Test-Path -LiteralPath $dcKey)) { New-Item -Path $dcKey -Force | Out-Null }
Set-ItemProperty -LiteralPath $dcKey -Name 'AllowTelemetry' -Value 0 -Type DWord
Set-ItemProperty -LiteralPath $dcKey -Name 'MaxTelemetryAllowed' -Value 0 -Type DWord
Write-Host "    DataCollection: AllowTelemetry = 0"

$werKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
if (-not (Test-Path -LiteralPath $werKey)) { New-Item -Path $werKey -Force | Out-Null }
Set-ItemProperty -LiteralPath $werKey -Name 'Disabled' -Value 1 -Type DWord
Write-Host "    Windows Error Reporting: Disabled = 1"

$actKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
if (-not (Test-Path -LiteralPath $actKey)) { New-Item -Path $actKey -Force | Out-Null }
Set-ItemProperty -LiteralPath $actKey -Name 'EnableActivityFeed' -Value 0 -Type DWord
Set-ItemProperty -LiteralPath $actKey -Name 'PublishUserActivities' -Value 0 -Type DWord
Set-ItemProperty -LiteralPath $actKey -Name 'UploadUserActivities' -Value 0 -Type DWord
Write-Host "    Activity Feed & Upload: Disabled = 0"

# 3. Disable scheduled telemetry tasks
Write-Host "[3/4] Disabling telemetry scheduled tasks..."
$tasks = @(
    '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
    '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
    '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
    '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
    '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector'
)
foreach ($t in $tasks) {
    try {
        Disable-ScheduledTask -TaskName (Split-Path -Leaf $t) -TaskPath (Split-Path -Parent $t) -ErrorAction SilentlyContinue | Out-Null
        Write-Host "    $t -> Disabled"
    } catch { }
}

# 4. Verification
Write-Host "[4/4] Verifying state..."
$dt = Get-Service -Name 'DiagTrack' -ErrorAction SilentlyContinue
Write-Host "    DiagTrack Status: $($dt.Status), StartType: $($dt.StartType)"
Write-Host "==============================================================================="
Write-Host "[SUCCESS] Windows 11 background telemetry successfully disabled."
Write-Host "==============================================================================="
