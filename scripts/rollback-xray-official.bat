@echo off
title Rollback Xray to Official
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERROR: Administrative privileges required.
    echo [!] Please RIGHT CLICK rollback-xray-official.bat and select [Run as administrator].
    pause
    exit /b 1
)

echo [1/3] Stopping proxy processes...
taskkill /f /im v2rayN.exe >nul 2>&1
taskkill /f /im xray.exe >nul 2>&1
taskkill /f /im sing-box.exe >nul 2>&1
timeout /t 2 /nobreak >nul

echo [2/3] Restoring official xray.exe from backup...
cd /d "D:\v2rayN-windows-64-desktop\v2rayN-windows-64\bin\xray"
if exist "xray.exe.orig" (
    copy /y "xray.exe.orig" "xray.exe" >nul
    echo Restored official xray.exe successfully.
) else (
    echo Warning: xray.exe.orig not found!
)

echo [3/3] Restoring firewall rules...
netsh advfirewall firewall delete rule name="AI-Guard-Allow-TUN-Xray" >nul 2>&1
if exist "C:\AI-Net-Guard\07-mode.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "C:\AI-Net-Guard\07-mode.ps1" -Root "C:\AI-Net-Guard" -V2rayNRoot "D:\v2rayN-windows-64-desktop\v2rayN-windows-64" -Quiet
)

echo.
echo Rollback completed!
pause
