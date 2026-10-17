@echo off
chcp 65001 >nul 2>&1
title NetWatch - long session
echo Starting NetWatch LONG session (40 minutes)...
echo.
powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%~dp0scripts\NetWatch.ps1" -Minutes 40 -Label long %*
echo.
echo ---------------------------------------------------------------
echo Finished. This window will close automatically in 30 seconds.
echo ---------------------------------------------------------------
timeout /t 30 >nul
