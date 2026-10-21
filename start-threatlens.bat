@echo off
setlocal
cd /d "%~dp0"

if not exist "backend\.venv\Scripts\python.exe" (
  echo Creating the Python virtual environment...
  py -3 -m venv backend\.venv
  if errorlevel 1 (
    echo Python 3 was not available as py -3.
    exit /b 1
  )
  backend\.venv\Scripts\python.exe -m pip install --upgrade pip
  backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
)

if not exist "backend\.env" (
  copy /Y "backend\.env.example" "backend\.env" >nul
)

if not exist "frontend\node_modules" (
  echo Installing frontend dependencies...
  pushd frontend
  call npm install
  if errorlevel 1 (
    popd
    exit /b 1
  )
  popd
)

start "ThreatLens API" /D "%~dp0backend" cmd /k ".venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000"
start "ThreatLens UI" /D "%~dp0frontend" cmd /k "npm run dev -- --host 127.0.0.1 --port 5173"

echo.
echo ThreatLens is opening in two windows.
echo API docs: http://127.0.0.1:8000/docs
echo Dashboard: http://127.0.0.1:5173
echo.
echo If Windows blocks the script, use the PowerShell commands in README.md instead.
