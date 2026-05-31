@echo off
setlocal

cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Missing virtual environment interpreter: .venv\Scripts\python.exe
  echo Create or restore the virtual environment first.
  pause
  exit /b 1
)

if not "%JOBBOARD_HOST%"=="" goto run
set JOBBOARD_HOST=127.0.0.1

:run
if not "%JOBBOARD_PORT%"=="" goto start
set JOBBOARD_PORT=5000

:start
echo Starting JobBoard AI on http://%JOBBOARD_HOST%:%JOBBOARD_PORT%/
echo Press Ctrl+C in this window to stop the server.
echo.
".venv\Scripts\python.exe" app.py

endlocal
