@echo off
cd /d "%~dp0"
python ussd_app.py
if errorlevel 1 (
    echo.
    echo Installing dependencies...
    pip install -r requirements.txt
    python ussd_app.py
)
pause
