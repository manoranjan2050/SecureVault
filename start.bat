@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

:: Set window title
title SECUREVAULT (ELITE EDITION)

:: Simple fallback colors using the 'color' command for the header
color 0B
cls

echo =================================================================
echo.
echo    SECUREVAULT (ELITE EDITION) v2.0.0
echo    Advanced Local Encryption ^& Digital Asset Management
echo    By MANORANJAN2050
echo.
echo =================================================================
echo.

echo [1/3] Detecting Python environment...
set "PYTHON_CMD="
where py >nul 2>nul
if !errorlevel!==0 (
    set "PYTHON_CMD=py"
    echo -- Found Python Launcher (py)
) else (
    where python >nul 2>nul
    if !errorlevel!==0 (
        set "PYTHON_CMD=python"
        echo -- Found Standard Python executable
    )
)

if "!PYTHON_CMD!"=="" (
    color 0C
    echo [X] CRITICAL: Python not found on this system.
    echo Please install Python from python.org and add it to your PATH.
    pause
    exit /b
)

echo.
echo [2/3] Validating Virtual Environment...
if not exist ".venv\Scripts\activate.bat" (
    echo [!] Venv is missing activation scripts or corrupted.
    echo [!] Initializing clean Elite environment...
    if exist ".venv" rmdir /s /q ".venv"
    !PYTHON_CMD! -m venv .venv
    if !errorlevel! neq 0 (
        color 0C
        echo [X] Failed to create virtual environment.
        pause
        exit /b
    )
    echo -- Virtual environment created successfully.
) else (
    echo -- Virtual environment verified.
)

echo.
echo [3/3] Processing requirements and system checks...
call "%~dp0.venv\Scripts\activate.bat"

if !errorlevel! neq 0 (
    color 0E
    echo [!] Activation failed. Attempting to proceed anyway...
)

echo -- Verifying system dependencies...
python -m pip install --upgrade pip
:: Removed -q and --progress-bar off to see what is failing
python -m pip install -r requirements.txt

echo.
echo SUCCESS: System is now ARMED and SECURE.
echo -- Decryption Gateway: http://127.0.0.1:5000
echo.

echo Launching Secure Browser...
start "" "http://127.0.0.1:5000"

echo Server Status: RUNNING
echo [Press CTRL+C to Shutdown Vault]
echo.

:: Change color to a standard neutral green for the server log
color 0A
python app.py

if !errorlevel! neq 0 (
    echo.
    color 0C
    echo =================================================================
    echo # [CRITICAL ERROR] Application failed to start.               #
    echo =================================================================
    pause
)
