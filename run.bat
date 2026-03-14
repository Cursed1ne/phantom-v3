@echo off
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::  PHANTOM AI v3 -- One-command Windows launcher
::  Usage: run.bat  (double-click or run from cmd)
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

title Phantom AI v3 Launcher
color 0B

echo.
echo  ==========================================
echo    ^^|  PHANTOM AI v3 -- Windows Launcher
echo  ==========================================
echo.

:: ── Check PowerShell availability ────────────────────────────────────────────
where powershell >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] PowerShell not found. Please install PowerShell.
    pause
    exit /b 1
)

:: ── Delegate to PowerShell setup script ──────────────────────────────────────
echo  [INFO] Launching setup and start via PowerShell...
echo  [INFO] If prompted about execution policy, type Y and press Enter.
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1"

if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Setup failed. Check the output above for details.
    echo  [HINT]  Try running setup.ps1 as Administrator.
    pause
    exit /b 1
)

pause
