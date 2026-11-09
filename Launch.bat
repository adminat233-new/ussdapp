@echo off
chcp 65001 >nul
title USSD Manager Pro
echo.
echo  ============================================
echo   USSD Manager Pro - Launcher
echo  ============================================
echo.
echo  [1] C# WPF App (Recommended - native Windows exe)
echo  [2] PowerShell WPF GUI
echo  [3] Python GUI
echo  [4] Python COM Port Scanner
echo  [5] Build C# App
echo.
set /p choice="Select option (1-5): "
if "%choice%"=="1" goto cs
if "%choice%"=="2" goto ps
if "%choice%"=="3" goto py
if "%choice%"=="4" goto scan
if "%choice%"=="5" goto build
goto :eof

:cs
if not exist "%~dp0Csharp\UssdApp.exe" call "%~dp0Csharp\build.bat"
start "" "%~dp0Csharp\UssdApp.exe"
goto :eof

:ps
powershell -ExecutionPolicy Bypass -STA -File "%~dp0PowerShell\UssdApp.ps1"
goto :eof

:py
cd /d "%~dp0Python"
python ussd_app.py
goto :eof

:scan
cd /d "%~dp0Python"
python detect_ports.py
pause
goto :eof

:build
call "%~dp0Csharp\build.bat"
pause
goto :eof
