@echo off
REM ============================================================
REM  Cerberus Collector - double-click launcher (Windows)
REM  Asks 3 questions, then runs the full scan and builds the
REM  dashboard package. No commands to type.
REM ============================================================
setlocal
cd /d "%~dp0"
title Cerberus Collector

echo.
echo   CERBERUS COLLECTOR - Active Directory security scan
echo   ---------------------------------------------------
echo.

python --version >nul 2>&1
if errorlevel 1 goto :nopython

echo Preparing libraries (first run only)...
python -m pip install -q ldap3 2>nul

echo.
set /p DC="1) Domain Controller IP or name (e.g. 192.168.1.10): "
set /p USR="2) Domain user (e.g. DOMAIN\user): "
echo 3) The password is asked next - it will NOT be shown or stored.
echo.
set /p REMOTE="Include per-machine session data? Slower, needs impacket (Y/N, Enter = No): "
set FLAGS=
if /i "%REMOTE%"=="Y" goto :remote
set FLAGS=--skip-remote
goto :run
:remote
python -m pip install -q impacket 2>nul

:run
echo.
echo Scanning - this can take a few minutes...
python cerberus.py --dc %DC% --user %USR% %FLAGS%
echo.
echo Done. Upload the CerberusScan-*.json file in the dashboard:
echo Clients - Add Scan.
echo.
pause
exit /b 0

:nopython
echo.
echo Python was not found on this machine.
echo Install Python from python.org and tick "Add python.exe to PATH",
echo then double-click this file again.
echo.
pause
exit /b 1
