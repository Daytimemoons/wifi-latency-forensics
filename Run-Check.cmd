@echo off
chcp 65001 >nul 2>&1
title NetWatch - environment check
powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%~dp0scripts\NetWatch.ps1" -CheckOnly
echo.
timeout /t 30 >nul
