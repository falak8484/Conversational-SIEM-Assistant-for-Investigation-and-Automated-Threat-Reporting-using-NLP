@echo off
REM ──────────────────────────────────────────────────────────────────────────
REM  SIEM Assistant — Windows launcher
REM  Double-click or run: run.bat
REM ──────────────────────────────────────────────────────────────────────────

echo.
echo  ███████╗██╗███████╗███╗   ███╗     █████╗ ██╗
echo  ██╔════╝██║██╔════╝████╗ ████║    ██╔══██╗██║
echo  ███████╗██║█████╗  ██╔████╔██║    ███████║██║
echo  ╚════██║██║██╔══╝  ██║╚██╔╝██║    ██╔══██║██║
echo  ███████║██║███████╗██║   ╚═╝ ██║    ██║  ██║██║
echo  ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝
echo.
echo  Conversational SIEM Assistant - Threat Intelligence Console
echo.

cd /d "%~dp0"

echo [1/4] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.9+ from https://python.org
    pause
    exit /b 1
)
python --version

echo [2/4] Preparing directories...
if not exist "data" mkdir data
echo       data\ ready

echo [3/4] Setting up virtual environment...
if not exist ".venv" (
    python -m venv .venv
    echo       Virtual environment created
) else (
    echo       Virtual environment found
)

call .venv\Scripts\activate.bat

echo [4/4] Installing dependencies...
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo       Dependencies installed

echo.
echo   SIEM Assistant starting...
echo.
echo   Open in browser:  http://127.0.0.1:8000
echo.
echo   Press Ctrl+C to stop.
echo.

cd backend
python -m uvicorn server:app --host 127.0.0.1 --port 8000 --reload
pause
