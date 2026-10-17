@echo off
chcp 65001 >nul 2>&1
title WiFi - prefer 5GHz
echo Applying: Preferred Band = 5GHz, Roaming Aggressiveness = Medium-High
echo.
powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%~dp0scripts\Set-WifiBand.ps1"
echo.
timeout /t 20 >nul
