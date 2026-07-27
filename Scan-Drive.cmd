@echo off
REM ---------------------------------------------------------------------------
REM  Argus Drive Scanner launcher
REM
REM  Double-clicking a .ps1 opens Notepad, which is not helpful. This runs it
REM  properly instead: asks for administrator rights (needed for the Defender
REM  scan), sets a single-threaded apartment so the window can be created, and
REM  bypasses the execution policy for this one launch only.
REM
REM  Keep this file next to ArgusDriveScanner.ps1.
REM ---------------------------------------------------------------------------

setlocal
set "SCRIPT=%~dp0ArgusDriveScanner.ps1"

if not exist "%SCRIPT%" (
    echo.
    echo   ERROR: ArgusDriveScanner.ps1 was not found next to this launcher.
    echo   Keep both files in the same folder.
    echo.
    pause
    exit /b 1
)

REM Already elevated? Launch directly. Otherwise ask, then launch elevated.
net session >nul 2>&1
if %errorlevel%==0 (
    powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "%SCRIPT%" %*
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile','-STA','-ExecutionPolicy','Bypass','-File','\"%SCRIPT%\"'"
)

endlocal
