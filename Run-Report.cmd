@echo off
chcp 65001 >nul 2>&1
title NetWatch - rebuild report
echo Rebuilding the report for the newest session...
echo.
powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%~dp0scripts\Report-Only.ps1" -Open %*
echo.
timeout /t 30 >nul
