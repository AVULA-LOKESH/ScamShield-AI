@echo off
setlocal
cd /d "%~dp0"
title ScamShield AI Setup

echo ==========================================
echo       ScamShield AI - Setup and Run
echo ==========================================
echo.

where py >nul 2>nul
if errorlevel 1 (
    echo Python launcher 'py' was not found.
    echo Install Python 3.10 or newer and select "Add Python to PATH".
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 (
        echo Could not create virtual environment.
        pause
        exit /b 1
    )
)

echo Installing required packages. This may take a few minutes...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto install_error
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto install_error

echo.
echo Starting backend terminal...
start "ScamShield AI Backend" /D "%~dp0" cmd /k ""%~dp0.venv\Scripts\python.exe" -m uvicorn backend.main:app --reload"

echo Starting frontend terminal...
start "ScamShield AI Frontend" /D "%~dp0frontend" cmd /k ""%~dp0.venv\Scripts\python.exe" -m http.server 5500"

timeout /t 3 /nobreak >nul
start "" "http://127.0.0.1:5500"
echo.
echo ScamShield AI is starting. Keep both terminal windows open.
pause
exit /b 0

:install_error
echo.
echo Package installation failed. Check internet connection and Python installation.
pause
exit /b 1
