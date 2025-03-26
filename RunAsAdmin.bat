@echo off
title Jeremy's All In One Utility - Launcher
echo Starting Jeremy's All In One Utility with admin privileges...
echo.

:: Check if PowerShell script exists
if not exist "CombinedScript.ps1" (
    echo ERROR: CombinedScript.ps1 not found in the current directory.
    echo Please make sure this batch file is in the same directory as CombinedScript.ps1
    echo.
    pause
    exit /b 1
)

:: Launch PowerShell with elevated privileges
echo Requesting administrator privileges...
powershell -Command "Start-Process -FilePath PowerShell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%~dp0CombinedScript.ps1\"' -Verb RunAs"

:: Exit the batch file
exit /b 0
