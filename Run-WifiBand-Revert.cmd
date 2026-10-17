@echo off
chcp 65001 >nul 2>&1
title WiFi - revert band settings
echo Reverting to factory defaults: Preferred Band = none, Roaming Aggressiveness = Medium
echo.
powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%~dp0scripts\Set-WifiBand.ps1" -Revert
echo.
timeout /t 20 >nul
