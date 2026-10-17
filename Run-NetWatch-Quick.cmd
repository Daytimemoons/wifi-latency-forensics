@echo off
chcp 65001 >nul 2>&1
title NetWatch - quick self test
echo Starting NetWatch QUICK self test (5 minutes)...
echo.
powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%~dp0scripts\NetWatch.ps1" -Quick -Label selfcheck %*
echo.
echo ---------------------------------------------------------------
echo Finished. This window will close automatically in 30 seconds.
echo ---------------------------------------------------------------
timeout /t 30 >nul
