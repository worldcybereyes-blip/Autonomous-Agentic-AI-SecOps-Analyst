@echo off
rem Internal helper: finds a usable Python 3.7+ and stores the command in %PY%.
rem Works with the py launcher, python.exe and python3.exe. Ignores the Microsoft Store stub.
set "PY="
py -3 -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3,7) else 1)" >nul 2>nul
if not errorlevel 1 set "PY=py -3"
if defined PY goto :eof
python -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3,7) else 1)" >nul 2>nul
if not errorlevel 1 set "PY=python"
if defined PY goto :eof
python3 -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3,7) else 1)" >nul 2>nul
if not errorlevel 1 set "PY=python3"
goto :eof
