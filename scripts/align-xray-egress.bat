@echo off
setlocal EnableDelayedExpansion
title AI-Net-Guard - Align Xray Physical Egress Route

:: Request Administrator Privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Requesting Administrator Privileges...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

color 0A
set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%align-xray-egress.ps1"

if not exist "%PS_SCRIPT%" (
    set "PS_SCRIPT=C:\Users\86198\Documents\deepseek-harness\default-workspace\AI-Net-Guard\scripts\align-xray-egress.ps1"
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%"

echo.
echo ===============================================================================
echo [DONE] Route alignment applied.
echo.
echo Would you like to restart the Xray process now to re-bind existing sockets
echo immediately to your physical WLAN adapter?
echo.
echo   [1] Yes, terminate current Xray core (v2rayN will auto-restart with new route)
echo   [2] No, keep running (sockets will rollover naturally)
echo ===============================================================================
set /p RESTART_CHOICE="Enter 1 or 2 (default 1): "

if "%RESTART_CHOICE%"=="" set "RESTART_CHOICE=1"

if "%RESTART_CHOICE%"=="1" (
    echo.
    echo Stopping xray.exe...
    taskkill /F /IM xray.exe >nul 2>&1
    timeout /t 2 /nobreak >nul
    echo [+] Xray stopped. If v2rayN does not reconnect automatically,
    echo     right click the v2rayN icon and click "Restart Service" or toggle TUN.
)

echo.
echo Press any key to exit...
pause >nul
