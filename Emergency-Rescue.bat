@echo off
setlocal EnableDelayedExpansion
title AI-Net-Guard ?????????? (Emergency Rescue)

:: 1. ???????????? (UAC Elevation)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] ????????????????...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

color 0A
echo ===============================================================================
echo                AI-Net-Guard ????????????????
echo ===============================================================================
echo.
echo ???????????????????????? Windows ????...
echo.

:: 2. ???????????????
echo [1/8] ???????????????...
schtasks /Delete /TN "AI-Guard-Mode-Event" /F >nul 2>&1
schtasks /Delete /TN "AI-Guard-Mode-Watcher" /F >nul 2>&1
schtasks /Delete /TN "AI-Guard-Mode-Fallback" /F >nul 2>&1
schtasks /Delete /TN "AI-Guard-Test-Rollback" /F >nul 2>&1
schtasks /Delete /TN "AI-Guard-Boot-Guard" /F >nul 2>&1
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*watchdog.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>&1

:: 3. ???? Windows ????????? (Allow)
echo [2/8] ?? Windows ???????? (Default Outbound: Allow)...
netsh advfirewall firewall delete rule name="AI-Guard-Allow-TUN-Xray" >nul 2>&1
netsh advfirewall set allprofiles state off >nul 2>&1
netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound >nul 2>&1
netsh advfirewall set allprofiles state on >nul 2>&1

:: 4. ???? AI-Guard ?????? NRPT ??
echo [3/8] ???? AI-Guard ???????? NRPT ??...
powershell -NoProfile -Command "Get-NetFirewallRule -DisplayName '*AI-Guard*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue" >nul 2>&1
powershell -NoProfile -Command "Get-NetFirewallRule -Name '*AI-Guard*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue" >nul 2>&1
powershell -NoProfile -Command "Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -like '*AI-Guard*' -or $_.Namespace -eq '.' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue" >nul 2>&1

:: 5. ????????? DHCP ???? DNS ????? IPv6
echo [4/8] ???? DNS ????? (DHCP) ????? IPv6...
powershell -NoProfile -Command "Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -notmatch '(?i)Wintun|sing-tun' } | ForEach-Object { try { Set-DnsClientServerAddress -InterfaceAlias $_.Name -ResetServerAddresses -ErrorAction SilentlyContinue } catch {}; try { Enable-NetAdapterBinding -Name $_.Name -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue } catch {} }" >nul 2>&1

:: 6. ???????? (LLMNR / SMHNR / Tcpip6 / NTP / WinINET Proxy)
echo [5/8] ?????????????????????...
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" /v NtpServer /t REG_SZ /d "time.windows.com,0x9" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1
netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 35 4 >nul 2>&1

:: 7. ????????????????? ACL
echo [6/8] ???????????????...
if exist "C:\AI-Net-Guard\backup\guard-policy.json" del /f /q "C:\AI-Net-Guard\backup\guard-policy.json" >nul 2>&1
if exist "C:\AI-Net-Guard\backup\mode-state.json" del /f /q "C:\AI-Net-Guard\backup\mode-state.json" >nul 2>&1
if exist "C:\AI-Net-Guard\backup\node-sync.meta" del /f /q "C:\AI-Net-Guard\backup\node-sync.meta" >nul 2>&1
if exist "C:\AI-Net-Guard\backup\cn-rule.sig" del /f /q "C:\AI-Net-Guard\backup\cn-rule.sig" >nul 2>&1
if exist "C:\AI-Net-Guard" icacls "C:\AI-Net-Guard" /reset /T /C /Q >nul 2>&1

:: 8. ?? Winsock ? DNS ??
echo [7/8] ?? Windows DNS ??? Winsock ???...
ipconfig /flushdns >nul 2>&1
netsh winsock reset >nul 2>&1

echo [8/8] ?????????...
echo.
echo ===============================================================================
echo [SUCCESS] ??????????????????????????????
echo ===============================================================================
echo.
echo ???????????????????????? AI-Net-Guard ?????
echo.
pause
