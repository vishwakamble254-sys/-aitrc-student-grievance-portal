@echo off
setlocal
cd /d "%~dp0"
echo ========================================
echo AITRC Portal - Install and Test
echo ========================================
python -m pip install -r requirements.txt
if errorlevel 1 goto failed
python -m unittest -v
if errorlevel 1 goto failed
python -m pip install playwright
if errorlevel 1 goto failed
python -m playwright install chromium
if errorlevel 1 goto failed
python e2e_test.py
if errorlevel 1 goto failed
echo.
echo ALL AUTOMATED TESTS PASSED.
pause
exit /b 0
:failed
echo.
echo TEST/INSTALL STEP FAILED. Read the error above and share it for troubleshooting.
pause
exit /b 1
