@echo off
setlocal
title SheeKryptor Setup

where py >nul 2>nul
if errorlevel 1 (
    echo Python was not found.
    echo Install Python 3.10 or newer from https://www.python.org/downloads/
    echo Then run this setup again.
    pause
    exit /b 1
)

echo Creating a private project environment...
py -3 -m venv .venv
if errorlevel 1 goto :failed

call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
if errorlevel 1 goto :failed

python -m pip install -r requirements.txt
if errorlevel 1 goto :failed

echo.
echo Setup complete. Starting SheeKryptor...
python SheeKryptor.py
exit /b %errorlevel%

:failed
echo.
echo Setup failed. Review the error above; no system-wide packages were installed.
pause
exit /b 1
