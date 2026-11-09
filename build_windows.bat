@echo off
REM ============================================================
REM  Builds CerberusCollector.exe (one file, no Python needed
REM  on the machine that runs the scan).
REM
REM  Run this once on any Windows machine that has Python 3.10+
REM  installed. The .exe appears in the "dist" folder.
REM ============================================================
setlocal
cd /d "%~dp0"

echo [1/3] Installing build tools and libraries...
python -m pip install --upgrade pyinstaller ldap3 impacket
if errorlevel 1 goto :fail

echo [2/3] Building CerberusCollector.exe ...
python -m PyInstaller --onefile --name CerberusCollector ^
  --add-data "collector.py;." ^
  --add-data "checks.py;." ^
  --add-data "paths.py;." ^
  cerberus.py
if errorlevel 1 goto :fail

echo [3/3] Done.
echo.
echo Your collector is ready:  dist\CerberusCollector.exe
echo Copy that ONE file anywhere and run it like:
echo   CerberusCollector.exe --dc 192.168.1.10 --user "DOMAIN\user"
echo.
pause
exit /b 0

:fail
echo.
echo BUILD FAILED - read the error above. Common cause: Python is not
echo installed, or "python" is not on the PATH. Install Python from
echo python.org and tick "Add python.exe to PATH", then run this again.
pause
exit /b 1
