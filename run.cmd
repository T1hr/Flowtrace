@echo off
setlocal
if not "%~1"=="" goto explicit
where py.exe >nul 2>nul
if not errorlevel 1 (
  py -3 -B "%~dp0app.py"
  goto result
)
where python.exe >nul 2>nul
if not errorlevel 1 (
  python -B "%~dp0app.py"
  goto result
)
set "FLOWSCOPE_PY=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if exist "%FLOWSCOPE_PY%" (
  goto bundled
)
echo Python 3.11 or newer with Tcl/Tk is required.
pause
exit /b 1
:bundled
for %%I in ("%FLOWSCOPE_PY%") do pushd "%%~dpI"
if errorlevel 1 goto result
set "TCL_LIBRARY=tcl/tcl8.6"
set "TK_LIBRARY=tcl/tk8.6"
"%FLOWSCOPE_PY%" -B "%~dp0app.py"
set "FLOWSCOPE_STATUS=%ERRORLEVEL%"
popd
if "%FLOWSCOPE_STATUS%"=="0" exit /b 0
pause
exit /b 1
:explicit
"%~1" -B "%~dp0app.py"
:result
if not errorlevel 1 exit /b 0
pause
exit /b 1

