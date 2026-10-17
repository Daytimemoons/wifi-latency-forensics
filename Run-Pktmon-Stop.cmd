@echo off
chcp 65001 >nul 2>&1
title NetWatch - stop pktmon
echo Stopping any leftover pktmon capture started by NetWatch and converting it to pcapng...
echo.
powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%~dp0scripts\NetWatch.ps1" -StopPktmon
echo.
timeout /t 20 >nul
