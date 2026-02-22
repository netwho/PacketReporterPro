@echo off
:: PacketReporter Pro — Installer Launcher
:: Launches the PowerShell installer with the correct execution policy.
:: Double-click this file or run from a command prompt.

title PacketReporter Pro — Installer

:: Check if PowerShell is available
where powershell >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: PowerShell is not available on this system.
    echo Please install PowerShell or run install.ps1 manually.
    pause
    exit /b 1
)

:: Launch the installer
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*

:: Keep the window open so the user can read the output
echo.
pause
