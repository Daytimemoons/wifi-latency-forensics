@echo off
chcp 65001 >nul 2>&1
title NetWatch - forensics
echo NetWatch FORENSICS mode: replay last 6 hours of events + snapshot + 3 minutes capture.
echo.
powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%~dp0scripts\Forensics.ps1" %*
echo.
echo ---------------------------------------------------------------
echo Finished. This window will close automatically in 30 seconds.
echo ---------------------------------------------------------------
timeout /t 30 >nul
