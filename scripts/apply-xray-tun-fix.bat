@echo off
title Apply Xray TUN Production Fix to v2rayN
cd /d "%~dp0"

echo ===============================================================================
echo            Applying Xray TUN Production Fix to v2rayN
echo ===============================================================================
echo.

:: Check Administrator Privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERROR: Administrative privileges required.
    echo [!] Please RIGHT CLICK apply-xray-tun-fix.bat and select [Run as administrator].
    echo.
    pause
    exit /b 1
)

echo [1/3] Stopping existing proxy processes (v2rayN, Xray, sing-box)...
taskkill /f /im v2rayN.exe >nul 2>&1
taskkill /f /im xray.exe >nul 2>&1
taskkill /f /im xray-patched.exe >nul 2>&1
taskkill /f /im sing-box.exe >nul 2>&1
timeout /t 2 /nobreak >nul

echo [2/3] Replacing xray.exe with xray-patched.exe...
cd /d "D:\v2rayN-windows-64-desktop\v2rayN-windows-64\bin\xray"
if not exist "xray.exe.orig" copy /y "xray.exe" "xray.exe.orig" >nul
copy /y "xray-patched.exe" "xray.exe" >nul
echo       xray.exe has been updated with the patched core! (Backup saved as xray.exe.orig)

echo [3/3] Updating firewall rules and synchronizing AI-Net-Guard...
:: Remove dangerous blanket allow rule if previously created
netsh advfirewall firewall delete rule name="AI-Guard-Allow-TUN-Xray" >nul 2>&1

:: Trigger AI-Net-Guard to auto-register xray_tun under AI-Guard-Allow-TUN-Alt safely
if exist "C:\AI-Net-Guard\07-mode.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "C:\AI-Net-Guard\07-mode.ps1" -Root "C:\AI-Net-Guard" -V2rayNRoot "D:\v2rayN-windows-64-desktop\v2rayN-windows-64" -Quiet
)

echo.
echo ===============================================================================
echo                     DEPLOYMENT COMPLETED!
echo ===============================================================================
echo 1. xray.exe has been successfully updated with the fixed binary.
echo 2. AI-Net-Guard firewall rules have been synchronized (xray_tun protected).
echo 3. Dangerous blanket allow rule (if present) has been purged.
echo 4. You can now launch v2rayN and start TUN mode.
echo.
pause
