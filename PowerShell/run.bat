@echo off
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -STA -File "%~dp0UssdApp.ps1"
pause
