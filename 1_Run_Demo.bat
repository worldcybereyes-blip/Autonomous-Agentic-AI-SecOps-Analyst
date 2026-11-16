@echo off
title Agentic AI SecOps - Demo
pushd "%~dp0"
call "%~dp0_python.bat"
if not defined PY goto nopy
echo.
%PY% -m secops_agent --demo --open
echo.
echo Done. Reports are in the "reports\latest" folder.
pause
exit /b 0
:nopy
echo.
echo  Python 3.7 or newer was not found on this PC.
echo  1. Install it from https://www.python.org/downloads/windows/
echo     and tick "Add python.exe to PATH" in the installer.
echo     Or in a terminal run:  winget install Python.Python.3.12
echo  2. Then double-click this file again.
echo.
pause
exit /b 1
