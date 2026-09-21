@echo off
title CyberNode Live Wireless Dashboard
cd /d "%~dp0"
echo =======================================================
echo    Starting CyberNode Live Cybersecurity Dashboard
echo =======================================================
echo.
echo Scanning local Wi-Fi environment and launching dashboard...
echo URL: http://localhost:5050
echo.
python runner.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Python was not found or encountered an error.
    pause
)
