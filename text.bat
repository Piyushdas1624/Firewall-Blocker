@echo off
setlocal EnableDelayedExpansion
REM STREAMING_CHUNK:Configuring script environment and console settings...
title Windows Firewall - Recursive Folder Blocker
color 0F
:: Ensure script runs from its own directory
cd /d "%~dp0"
set "TARGET_DIR=%~dp0"
REM STREAMING_CHUNK:Checking for administrative privileges and requesting elevation...
:: Verify whether the script is currently running with Administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
echo ==============================================================================
echo  [!] Administrator privileges required.
echo  [!] Requesting User Account Control (UAC) elevation...
echo ==============================================================================
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b
)
REM STREAMING_CHUNK:Rendering the main interactive menu interface...
:MENU
cls
echo ==============================================================================
echo               RECURSIVE FIREWALL BLOCKER FOR WINDOWS 10 / 11
echo ==============================================================================
echo  Current Target Root Folder:
echo  "%TARGET_DIR%"
echo ==============================================================================
echo.
echo  [1] BLOCK all .exe files recursively (Inbound + Outbound)
echo  [2] UNBLOCK all .exe files recursively (Remove created rules)
echo  [3] SCAN / LIST all .exe files without modifying firewall
echo  [4] Exit
echo.
echo ==============================================================================
set /p "CHOICE=Select an option [1-4]: "
if "%CHOICE%""1" goto BLOCK_EXES
if "%CHOICE%""2" goto UNBLOCK_EXES
if "%CHOICE%""3" goto SCAN_EXES
if "%CHOICE%""4" goto QUIT
goto MENU
REM STREAMING_CHUNK:Scanning directory tree and counting executable files...
:SCAN_EXES
cls
echo ==============================================================================
echo  SCANNING: Executable files in "%TARGET_DIR%"
echo ==============================================================================
echo.
set /a "SCAN_COUNT=0"
for /r "%TARGET_DIR%" %%F in (*.exe) do (
set /a "SCAN_COUNT+=1"
echo  [!SCAN_COUNT!] %%~nxF
echo      Path: "%%~fF"
)
echo.
echo ------------------------------------------------------------------------------
echo  Total executable files discovered: !SCAN_COUNT!
echo ------------------------------------------------------------------------------
echo.
pause
goto MENU
REM STREAMING_CHUNK:Applying inbound and outbound firewall block rules recursively...
:BLOCK_EXES
cls
echo ==============================================================================
echo  BLOCKING: Applying Inbound and Outbound Firewall Rules
echo ==============================================================================
echo  Target: "%TARGET_DIR%"
echo ------------------------------------------------------------------------------
echo.
set /a "BLOCK_COUNT=0"
set /a "RULE_COUNT=0"
for /r "%TARGET_DIR%" %%F in (*.exe) do (
set /a "BLOCK_COUNT+=1"
set "EXE_NAME=%%~nxF"
set "EXE_PATH=%%~fF"
echo [+] Processing: !EXE_NAME!
:: Remove existing matching rules first to prevent duplicate entries
netsh advfirewall firewall delete rule name="[FolderBlock-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
netsh advfirewall firewall delete rule name="[FolderBlock-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
:: Create Inbound Block Rule
netsh advfirewall firewall add rule name="[FolderBlock-IN] !EXE_NAME!" dir=in action=block program="!EXE_PATH!" enable=yes profile=any >nul 2>&1
if !errorlevel! equ 0 (
set /a "RULE_COUNT+=1"
)
:: Create Outbound Block Rule
netsh advfirewall firewall add rule name="[FolderBlock-OUT] !EXE_NAME!" dir=out action=block program="!EXE_PATH!" enable=yes profile=any >nul 2>&1
if !errorlevel! equ 0 (
set /a "RULE_COUNT+=1"
)
echo     -^> Blocked IN and OUT: "!EXE_PATH!"
)
REM STREAMING_CHUNK:Displaying summary statistics and completion details...
echo.
echo ==============================================================================
echo  FIREWALL BLOCK COMPLETE
echo ==============================================================================
echo  Executables Processed : !BLOCK_COUNT!
echo  Firewall Rules Created: !RULE_COUNT! (Inbound + Outbound)
echo ==============================================================================
echo.
pause
goto MENU
REM STREAMING_CHUNK:Removing previously created firewall rules from target executables...
:UNBLOCK_EXES
cls
echo ==============================================================================
echo  UNBLOCKING: Removing Firewall Block Rules for this directory tree
echo ==============================================================================
echo  Target: "%TARGET_DIR%"
echo ------------------------------------------------------------------------------
echo.
set /a "UNBLOCK_COUNT=0"
for /r "%TARGET_DIR%" %%F in (*.exe) do (
set /a "UNBLOCK_COUNT+=1"
set "EXE_NAME=%%~nxF"
set "EXE_PATH=%%~fF"
echo [-] Removing rules for: !EXE_NAME!
netsh advfirewall firewall delete rule name="[FolderBlock-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
netsh advfirewall firewall delete rule name="[FolderBlock-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
)
echo.
echo ==============================================================================
echo  FIREWALL UNBLOCK COMPLETE
echo ==============================================================================
echo  Executables Cleaned: !UNBLOCK_COUNT!
echo ==============================================================================
echo.
pause
goto MENU
:QUIT
cls
echo Exiting...
exit /b 0