# Restore Windows 11 Default Telemetry Services
$ErrorActionPreference = 'SilentlyContinue'

Write-Host "==============================================================================="
Write-Host "                Restoring Windows 11 Telemetry Services"
Write-Host "==============================================================================="

# 1. Restore Telemetry services
Write-Host "[1/3] Restoring Telemetry services..."
foreach ($svc in @('DiagTrack', 'dmwappushservice')) {
    Set-Service -Name $svc -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name $svc -ErrorAction SilentlyContinue
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    Write-Host "    $svc -> Status: $($s.Status), StartType: $($s.StartType)"
}

# 2. Remove Group Policy registry restrictions
Write-Host "[2/3] Removing Group Policy registry restrictions..."
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -ErrorAction SilentlyContinue
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'MaxTelemetryAllowed' -ErrorAction SilentlyContinue
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -ErrorAction SilentlyContinue
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -ErrorAction SilentlyContinue
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'PublishUserActivities' -ErrorAction SilentlyContinue
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'UploadUserActivities' -ErrorAction SilentlyContinue
Write-Host "    Registry policies reverted"

# 3. Enable scheduled telemetry tasks
Write-Host "[3/3] Enabling telemetry scheduled tasks..."
$tasks = @(
    '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
    '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
    '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
    '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip'
)
foreach ($t in $tasks) {
    try {
        Enable-ScheduledTask -TaskName (Split-Path -Leaf $t) -TaskPath (Split-Path -Parent $t) -ErrorAction SilentlyContinue | Out-Null
        Write-Host "    $t -> Enabled"
    } catch { }
}

Write-Host "==============================================================================="
Write-Host "[RESTORED] Windows 11 default telemetry settings restored."
Write-Host "==============================================================================="
