@echo off
cd /d "%~dp0"
if not exist UssdApp.exe call build.bat
start "" "%~dp0UssdApp.exe"
