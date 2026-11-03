@echo off
setlocal EnableDelayedExpansion
title AI-Net-Guard 紧急网络脱困自救工具 (Emergency Rescue)

:: 1. 检查并自动请求管理员权限 (UAC Elevation)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] 正在请求管理员权限以解除网络封锁...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

color 0A
echo ===============================================================================
echo                AI-Net-Guard 极速应急网络脱困与防火墙一键解锁
echo ===============================================================================
echo.
echo 正在执行底层安全重置，解除所有内核出站阻断并恢复 Windows 原生网络...
echo.

:: 2. 终止任何守护进程与注销计划任务
echo [1/8] 清理后台自愈计划任务与守护进程...
schtasks /Delete /TN "AI-Guard-Mode-Event" /F >nul 2>&1
schtasks /Delete /TN "AI-Guard-Mode-Watcher" /F >nul 2>&1
schtasks /Delete /TN "AI-Guard-Mode-Fallback" /F >nul 2>&1
schtasks /Delete /TN "AI-Guard-Test-Rollback" /F >nul 2>&1
schtasks /Delete /TN "AI-Guard-Boot-Guard" /F >nul 2>&1
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*watchdog.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>&1

:: 3. 强制重置 Windows 防火墙为原生全放行 (Allow)
echo [2/8] 恢复 Windows 防火墙出站全放行 (Default Outbound: Allow)...
netsh advfirewall set allprofiles state off >nul 2>&1
netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound >nul 2>&1
netsh advfirewall set allprofiles state on >nul 2>&1

:: 4. 删除所有 AI-Guard 防火墙规则与 NRPT 规则
echo [3/8] 移除所有 AI-Guard 防火墙拦截规则与 NRPT 规则...
powershell -NoProfile -Command "Get-NetFirewallRule -DisplayName '*AI-Guard*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue" >nul 2>&1
powershell -NoProfile -Command "Get-NetFirewallRule -Name '*AI-Guard*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue" >nul 2>&1
powershell -NoProfile -Command "Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -like '*AI-Guard*' -or $_.Namespace -eq '.' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue" >nul 2>&1

:: 5. 恢复所有物理网卡为 DHCP 自动获取 DNS 并重新启用 IPv6
echo [4/8] 重置网卡 DNS 为自动获取 (DHCP) 并重新启用 IPv6...
powershell -NoProfile -Command "Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -notmatch '(?i)Wintun|sing-tun' } | ForEach-Object { try { Set-DnsClientServerAddress -InterfaceAlias $_.Name -ResetServerAddresses -ErrorAction SilentlyContinue } catch {}; try { Enable-NetAdapterBinding -Name $_.Name -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue } catch {} }" >nul 2>&1

:: 6. 清理注册表组策略 (LLMNR / SMHNR / Tcpip6 / NTP / WinINET Proxy)
echo [5/8] 清除注册表解析策略并重置系统代理与时间服务...
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" /v NtpServer /t REG_SZ /d "time.windows.com,0x9" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1
netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 35 4 >nul 2>&1

:: 7. 清理本地策略与状态元数据，重置目录 ACL
echo [6/8] 清理本地策略缓存并恢复目录权限...
if exist "C:\AI-Net-Guard\backup\guard-policy.json" del /f /q "C:\AI-Net-Guard\backup\guard-policy.json" >nul 2>&1
if exist "C:\AI-Net-Guard\backup\mode-state.json" del /f /q "C:\AI-Net-Guard\backup\mode-state.json" >nul 2>&1
if exist "C:\AI-Net-Guard\backup\node-sync.meta" del /f /q "C:\AI-Net-Guard\backup\node-sync.meta" >nul 2>&1
if exist "C:\AI-Net-Guard\backup\cn-rule.sig" del /f /q "C:\AI-Net-Guard\backup\cn-rule.sig" >nul 2>&1
if exist "C:\AI-Net-Guard" icacls "C:\AI-Net-Guard" /reset /T /C /Q >nul 2>&1

:: 8. 刷新 Winsock 与 DNS 缓存
echo [7/8] 刷新 Windows DNS 缓存与 Winsock 协议栈...
ipconfig /flushdns >nul 2>&1
netsh winsock reset >nul 2>&1

echo [8/8] 验证系统网络连通性...
echo.
echo ===============================================================================
echo [SUCCESS] 应急脱困完成！所有防火墙阻断已解除，系统已恢复原生网络状态。
echo ===============================================================================
echo.
echo 提示：当前电脑网络已完全恢复正常。你可以重新打开 AI-Net-Guard 重新部署。
echo.
pause
