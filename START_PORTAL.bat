@echo off
setlocal
cd /d "%~dp0"
echo ========================================
echo       AITRC Portal - Start
 echo ========================================
where py >nul 2>&1
if %errorlevel%==0 (set "PY=py -3") else (set "PY=python")
%PY% --version >nul 2>&1
if errorlevel 1 (
 echo ERROR: Python not found. Install Python and enable Add Python to PATH.
 pause
 exit /b 1
)
%PY% -c "import flask" >nul 2>&1
if errorlevel 1 (
 echo Installing required packages...
 %PY% -m pip install -r requirements.txt
 if errorlevel 1 (
  echo ERROR: Package installation failed. Check internet connection and pip.
  pause
  exit /b 1
 )
)
echo.
echo Open http://127.0.0.1:5000 in your browser.
echo Keep this window open. Press Ctrl+C to stop.
echo.
%PY% app.py
if errorlevel 1 echo ERROR: Portal stopped with an error. Copy the messages above for troubleshooting.
pause
