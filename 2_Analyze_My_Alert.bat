@echo off
title Agentic AI SecOps - Analyze alert file
pushd "%~dp0"
call "%~dp0_python.bat"
if not defined PY goto nopy
if not "%~1"=="" goto run
echo.
echo  Tip: you can also DRAG AND DROP an alert file onto this .bat file.
echo.
set "ALERT="
set /p "ALERT=Enter the full path of an alert file (.json / .log / .txt) or a folder: "
if not defined ALERT goto none
set "ALERT=%ALERT:"=%"
echo.
%PY% -m secops_agent "%ALERT%" --open
goto end
:run
echo.
%PY% -m secops_agent %* --open
goto end
:none
echo No path entered.
:end
echo.
pause
exit /b 0
:nopy
echo.
echo  Python 3.7 or newer was not found. See HOW_TO_RUN.txt, section 2.
echo.
pause
exit /b 1
