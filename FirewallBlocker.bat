@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul 2>&1
title FirewallBlocker - Windows Firewall Manager (Win 7 - 11)

:: -----------------------------------------------------------------------------
:: Resolve script location
:: -----------------------------------------------------------------------------
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

:: -----------------------------------------------------------------------------
:: Primary Execution: PowerShell Engine (Universal Win 7-11, Color-Coded)
:: -----------------------------------------------------------------------------
where powershell.exe >nul 2>&1
if %errorlevel% equ 0 (
    if exist "%SCRIPT_DIR%\FirewallBlocker.ps1" (
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%\FirewallBlocker.ps1" -InitialDir "%SCRIPT_DIR%" %*
        exit /b %errorlevel%
    )
    if exist "%SCRIPT_DIR%\run.ps1" (
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%\run.ps1" -InitialDir "%SCRIPT_DIR%" %*
        exit /b %errorlevel%
    )
)

:: -----------------------------------------------------------------------------
:: Fallback Engine: Pure Batch Implementation (When PowerShell is Restricted)
:: -----------------------------------------------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ==============================================================================
    echo  [!] Administrator privileges required to manage Windows Firewall rules.
    echo  [*] Please right-click this file and select 'Run as administrator'.
    echo ==============================================================================
    pause
    exit /b 1
)

set "TARGET_DIR=%SCRIPT_DIR%"
if not "%~1"=="" if exist "%~1" set "TARGET_DIR=%~f1"

:MENU
cls
echo ==============================================================================
echo        FIREWALL BLOCKER - NATIVE BATCH FALLBACK ENGINE (WIN 7 - 11)           
echo ==============================================================================
echo  Current Target Root Folder:
echo  "%TARGET_DIR%"
echo ==============================================================================
echo.
echo  [1] BLOCK all .exe files (Inbound + Outbound)
echo  [2] BLOCK all .exe files (Outbound Only)
echo  [3] BLOCK all .exe files (Inbound Only)
echo  [4] UNBLOCK all .exe files (Remove created rules)
echo  [5] SCAN / LIST all .exe files in target folder
echo  [6] CHANGE target folder
echo  [7] Open Windows Firewall GUI (wf.msc)
echo  [8] Exit
echo.
echo ==============================================================================
set "CHOICE="
set /p "CHOICE=Select an option [1-8]: "

if "%CHOICE%"=="1" goto BLOCK_BOTH
if "%CHOICE%"=="2" goto BLOCK_OUT
if "%CHOICE%"=="3" goto BLOCK_IN
if "%CHOICE%"=="4" goto UNBLOCK_EXES
if "%CHOICE%"=="5" goto SCAN_EXES
if "%CHOICE%"=="6" goto CHANGE_DIR
if "%CHOICE%"=="7" goto OPEN_WF
if "%CHOICE%"=="8" goto QUIT
goto MENU

:CHANGE_DIR
cls
echo ==============================================================================
echo  CHANGE TARGET DIRECTORY
echo ==============================================================================
echo.
set "NEW_DIR="
set /p "NEW_DIR=Enter folder path (or press Enter to cancel): "
if "%NEW_DIR%"=="" goto MENU
set "NEW_DIR=%NEW_DIR:"=%"
if exist "%NEW_DIR%" (
    set "TARGET_DIR=%NEW_DIR%"
    echo  [OK] Target directory updated.
) else (
    echo  [!] Directory not found: "%NEW_DIR%"
    timeout /t 2 >nul 2>&1
)
goto MENU

:OPEN_WF
start wf.msc
goto MENU

:SCAN_EXES
cls
echo ==============================================================================
echo  SCANNING: Executable files in "%TARGET_DIR%"
echo ==============================================================================
echo.
setlocal EnableDelayedExpansion
set /a "SCAN_COUNT=0"
for /r "%TARGET_DIR%" %%F in (*.exe) do (
    set /a "SCAN_COUNT+=1"
    echo  [!SCAN_COUNT!] %%~nxF
    echo        Path: "%%~fF"
)
echo.
echo ------------------------------------------------------------------------------
echo  Total executable files discovered: !SCAN_COUNT!
echo ------------------------------------------------------------------------------
endlocal
echo.
pause
goto MENU

:BLOCK_BOTH
set "BLOCK_MODE=BOTH"
goto DO_BLOCK

:BLOCK_OUT
set "BLOCK_MODE=OUT"
goto DO_BLOCK

:BLOCK_IN
set "BLOCK_MODE=IN"
goto DO_BLOCK

:DO_BLOCK
cls
echo ==============================================================================
echo  BLOCKING: Applying Windows Firewall Block Rules (Mode: %BLOCK_MODE%)
echo ==============================================================================
echo  Target: "%TARGET_DIR%"
echo ------------------------------------------------------------------------------
echo.

setlocal EnableDelayedExpansion
set /a "BLOCK_COUNT=0"
set /a "RULE_COUNT=0"
set /a "FAIL_COUNT=0"

for /r "%TARGET_DIR%" %%F in (*.exe) do (
    set /a "BLOCK_COUNT+=1"
    set "EXE_NAME=%%~nxF"
    set "EXE_PATH=%%~fF"
    echo [+] Processing: !EXE_NAME!

    if "%BLOCK_MODE%"=="BOTH" (
        netsh advfirewall firewall delete rule name="[FWB-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
        netsh advfirewall firewall delete rule name="[FWB-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
        netsh advfirewall firewall delete rule name="[FolderBlock-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
        netsh advfirewall firewall delete rule name="[FolderBlock-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1

        netsh advfirewall firewall add rule name="[FWB-IN] !EXE_NAME!" dir=in action=block program="!EXE_PATH!" enable=yes profile=any >nul 2>&1
        if !errorlevel! equ 0 (
            set /a "RULE_COUNT+=1"
            echo       [OK] Inbound Block Added
        ) else (
            set /a "FAIL_COUNT+=1"
            echo       [FAIL] Inbound Block Failed
        )

        netsh advfirewall firewall add rule name="[FWB-OUT] !EXE_NAME!" dir=out action=block program="!EXE_PATH!" enable=yes profile=any >nul 2>&1
        if !errorlevel! equ 0 (
            set /a "RULE_COUNT+=1"
            echo       [OK] Outbound Block Added
        ) else (
            set /a "FAIL_COUNT+=1"
            echo       [FAIL] Outbound Block Failed
        )
    )

    if "%BLOCK_MODE%"=="OUT" (
        netsh advfirewall firewall delete rule name="[FWB-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
        netsh advfirewall firewall delete rule name="[FolderBlock-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1

        netsh advfirewall firewall add rule name="[FWB-OUT] !EXE_NAME!" dir=out action=block program="!EXE_PATH!" enable=yes profile=any >nul 2>&1
        if !errorlevel! equ 0 (
            set /a "RULE_COUNT+=1"
            echo       [OK] Outbound Block Added
        ) else (
            set /a "FAIL_COUNT+=1"
            echo       [FAIL] Outbound Block Failed
        )
    )

    if "%BLOCK_MODE%"=="IN" (
        netsh advfirewall firewall delete rule name="[FWB-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
        netsh advfirewall firewall delete rule name="[FolderBlock-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1

        netsh advfirewall firewall add rule name="[FWB-IN] !EXE_NAME!" dir=in action=block program="!EXE_PATH!" enable=yes profile=any >nul 2>&1
        if !errorlevel! equ 0 (
            set /a "RULE_COUNT+=1"
            echo       [OK] Inbound Block Added
        ) else (
            set /a "FAIL_COUNT+=1"
            echo       [FAIL] Inbound Block Failed
        )
    )
)

echo.
echo ==============================================================================
echo  FIREWALL BLOCK COMPLETE
echo ==============================================================================
echo  Executables Processed : !BLOCK_COUNT!
echo  Rules Created [OK]    : !RULE_COUNT!
echo  Rules Failed  [FAIL]  : !FAIL_COUNT!
echo ==============================================================================
endlocal
echo.
pause
goto MENU

:UNBLOCK_EXES
cls
echo ==============================================================================
echo  UNBLOCKING: Removing Firewall Block Rules for this directory tree
echo ==============================================================================
echo  Target: "%TARGET_DIR%"
echo ------------------------------------------------------------------------------
echo.

setlocal EnableDelayedExpansion
set /a "UNBLOCK_COUNT=0"

for /r "%TARGET_DIR%" %%F in (*.exe) do (
    set /a "UNBLOCK_COUNT+=1"
    set "EXE_NAME=%%~nxF"
    set "EXE_PATH=%%~fF"
    echo [-] Cleaning rules for: !EXE_NAME!
    netsh advfirewall firewall delete rule name="[FWB-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
    netsh advfirewall firewall delete rule name="[FWB-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
    netsh advfirewall firewall delete rule name="[FolderBlock-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
    netsh advfirewall firewall delete rule name="[FolderBlock-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
    netsh advfirewall firewall delete rule name=all program="!EXE_PATH!" >nul 2>&1
)

echo.
echo ==============================================================================
echo  FIREWALL UNBLOCK COMPLETE
echo ==============================================================================
echo  Executables Cleaned: !UNBLOCK_COUNT!
echo ==============================================================================
endlocal
echo.
pause
goto MENU

:QUIT
cls
echo Exiting FirewallBlocker...
exit /b 0
