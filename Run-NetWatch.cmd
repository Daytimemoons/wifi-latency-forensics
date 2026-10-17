@echo off
chcp 65001 >nul 2>&1
title NetWatch - collecting
echo Starting NetWatch (default session length comes from config.json)...
echo.
powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%~dp0scripts\NetWatch.ps1" %*
echo.
echo ---------------------------------------------------------------
echo Finished. This window will close automatically in 30 seconds.
echo (Press any key to close it now.)
echo ---------------------------------------------------------------
timeout /t 30 >nul
