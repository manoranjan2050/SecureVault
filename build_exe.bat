@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

:: Set window title
title SECUREVAULT BINARY COMPILER (ELITE EDITION)

:: Simple colors
color 0B
cls

echo =================================================================
echo.
echo    SECUREVAULT BINARY COMPILER v2.2.0
echo    Preparing Standalone Portable Executable...
echo.
echo =================================================================
echo.

:: 1. Setup Environment
echo [1/4] Activating Elite Environment...
if not exist ".venv\Scripts\activate.bat" (
    echo [!] Virtual environment not found. Please run start.bat first.
    pause
    exit /b
)
call ".venv\Scripts\activate.bat"

:: 2. Install PyInstaller
echo [2/4] Verifying Compilation Tools...
python -m pip install pyinstaller -q
if !errorlevel! neq 0 (
    echo [X] Failed to install PyInstaller.
    pause
    exit /b
)

:: 3. Compilation
echo [3/4] Executing Master Compilation (This may take 2-3 minutes)...
echo -- Shuttling assets: static, templates
echo -- Hardening binary: AES-256-GCM + Argon2id
echo.

:: --noconsole hides the black box when running the EXE
:: --add-data bundles your UI folders
:: --icon would go here if you have one (e.g., --icon=app.ico)
pyinstaller --noconsole --onefile ^
    --add-data "templates;templates" ^
    --add-data "static;static" ^
    --name "SecureVault" ^
    --hidden-import "cv2" ^
    --hidden-import "numpy" ^
    --hidden-import "PIL" ^
    --hidden-import "protobuf" ^
    app.py

if !errorlevel! neq 0 (
    color 0C
    echo [X] COMPILATION FAILED.
    pause
    exit /b
)

:: 4. Finalization
echo.
echo [4/4] Finalizing Elite Binary...
if exist "dist\SecureVault.exe" (
    echo.
    color 0A
    echo =================================================================
    echo    SUCCESS: Portable Binary generated.
    echo    Location: dist\SecureVault.exe
    echo =================================================================
    echo.
    echo -- Portability Tip: Copy 'SecureVault.exe' to your USB drive.
    echo -- Note: The first time you run it, it will create its 'data' 
    echo    folder in the same location as the EXE.
    echo.
) else (
    color 0C
    echo [!] Binary created but not found in 'dist' folder.
)

pause
