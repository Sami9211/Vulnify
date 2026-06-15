@echo off
REM ===========================================================================
REM  Vulnify one-click launcher for Windows.
REM    run.bat            set up everything and start backend + frontend
REM    run.bat --sample   force offline sample data (no network needed)
REM  Double-click this file in Explorer, or run it from a terminal.
REM ===========================================================================
setlocal enableextensions
cd /d "%~dp0"
title Vulnify launcher

set "SAMPLE_FLAG="
if /I "%~1"=="--sample" set "SAMPLE_FLAG=--sample"
if /I "%~1"=="sample"   set "SAMPLE_FLAG=--sample"

REM ---- locate a Python interpreter ----
set "PY="
where python >nul 2>&1 && set "PY=python"
if not defined PY where py >nul 2>&1 && set "PY=py"
if not defined PY (
  echo ERROR: Python 3 was not found. Install it from https://python.org and re-run.
  pause
  exit /b 1
)

where node >nul 2>&1
if errorlevel 1 (
  echo ERROR: Node.js was not found. Install it from https://nodejs.org and re-run.
  pause
  exit /b 1
)

echo ==^> Setting up backend ^(Python venv + dependencies^)...
if not exist "backend\.venv\Scripts\activate.bat" (
  %PY% -m venv backend\.venv
)
call "backend\.venv\Scripts\activate.bat"
python -m pip install -q --upgrade pip >nul 2>&1
python -m pip install -q -r backend\requirements.txt
if errorlevel 1 (
  echo ERROR: backend dependency install failed.
  pause
  exit /b 1
)

echo ==^> Ensuring vulnerability feeds are available...
python scripts\ensure_data.py %SAMPLE_FLAG%

if not exist "frontend\node_modules" (
  echo ==^> Installing frontend dependencies ^(first run only^)...
  pushd frontend
  call npm install
  popd
)

echo ==^> Starting Vulnify...
REM Both child windows inherit this directory, so relative paths are safe even
REM when the project path contains spaces.
start "Vulnify Backend" cmd /k "call backend\.venv\Scripts\activate.bat && cd backend && python app.py"
start "Vulnify Frontend" cmd /k "cd frontend && npm run dev"

REM give the dev server a moment to boot, then open the dashboard
timeout /t 5 /nobreak >nul
start "" http://localhost:5173

echo.
echo   Vulnify is starting in two new windows:
echo     Frontend : http://localhost:5173
echo     Backend  : http://127.0.0.1:5001
echo.
echo   Close those two windows to stop Vulnify.
echo.
pause
