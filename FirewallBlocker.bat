@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul 2>&1
title FirewallBlocker - Windows Firewall Manager (Win 7 - 11)

:: -----------------------------------------------------------------------------
:: Resolve script location and default target directory
:: -----------------------------------------------------------------------------
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

:: -----------------------------------------------------------------------------
:: Primary Execution: Universal PowerShell Engine (Win 7 SP1 - 11, Color-Coded)
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
:: Fallback Engine: Pure Native Batch (When PowerShell is Restricted/Unavailable)
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

:: Safety check: Do not default to System32 or Windows root
if /i "%TARGET_DIR%"=="%SystemRoot%" set "TARGET_DIR="
if /i "%TARGET_DIR%"=="%SystemRoot%\" set "TARGET_DIR="
if /i "%TARGET_DIR%"=="%SystemRoot%\System32" set "TARGET_DIR="
if /i "%TARGET_DIR%"=="%SystemRoot%\System32\" set "TARGET_DIR="
if /i "%TARGET_DIR%"=="%SystemDrive%\" set "TARGET_DIR="
if /i "%TARGET_DIR%"=="%SystemDrive%" set "TARGET_DIR="

:MENU
cls
echo ==============================================================================
echo        FIREWALL BLOCKER - NATIVE BATCH FALLBACK ENGINE (WIN 7 - 11)           
echo ==============================================================================
echo  Current Target Root Folder:
if defined TARGET_DIR (
    echo  "%TARGET_DIR%"
) else (
    echo  [NOT SET - Please Select Option 6 or Drag and Drop a Folder]
)
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

if "%CHOICE%"=="1" goto CHECK_AND_BLOCK_BOTH
if "%CHOICE%"=="2" goto CHECK_AND_BLOCK_OUT
if "%CHOICE%"=="3" goto CHECK_AND_BLOCK_IN
if "%CHOICE%"=="4" goto CHECK_AND_UNBLOCK
if "%CHOICE%"=="5" goto CHECK_AND_SCAN
if "%CHOICE%"=="6" goto CHANGE_DIR
if "%CHOICE%"=="7" goto OPEN_WF
if "%CHOICE%"=="8" goto QUIT
goto MENU

:CHECK_DIR_SET
if not defined TARGET_DIR (
    cls
    echo ==============================================================================
    echo  [!] Target folder is not set. Please enter or drag-and-drop a folder:
    echo ==============================================================================
    set "INPUT_DIR="
    set /p "INPUT_DIR=Folder Path: "
    if defined INPUT_DIR (
        set "INPUT_DIR=!INPUT_DIR:"=!"
        if exist "!INPUT_DIR!" set "TARGET_DIR=!INPUT_DIR!"
    )
)
exit /b 0

:CHECK_PROTECTED
if not defined TARGET_DIR exit /b 1
if /i "%TARGET_DIR%"=="%SystemRoot%" goto PROTECTED_ERROR
if /i "%TARGET_DIR%"=="%SystemRoot%\" goto PROTECTED_ERROR
if /i "%TARGET_DIR%"=="%SystemRoot%\System32" goto PROTECTED_ERROR
if /i "%TARGET_DIR%"=="%SystemRoot%\System32\" goto PROTECTED_ERROR
if /i "%TARGET_DIR%"=="%SystemDrive%\" goto PROTECTED_ERROR
if /i "%TARGET_DIR%"=="%SystemDrive%" goto PROTECTED_ERROR
exit /b 0

:PROTECTED_ERROR
cls
echo ==============================================================================
echo  [CRITICAL SAFETY BLOCK] TARGET IS A PROTECTED WINDOWS SYSTEM PATH!
echo ==============================================================================
echo  Directory: "%TARGET_DIR%"
echo  Blocking Windows system folders will break Windows networking and updates!
echo  Operation aborted immediately to protect system stability.
echo ==============================================================================
pause
set "TARGET_DIR="
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

:CHECK_AND_SCAN
if not defined TARGET_DIR (
    setlocal EnableDelayedExpansion
    call :CHECK_DIR_SET
    endlocal
)
call :CHECK_PROTECTED
if not defined TARGET_DIR goto MENU

:SCAN_EXES
cls
echo ==============================================================================
echo  SCANNING: Executable files in "%TARGET_DIR%"
echo ==============================================================================
echo.
set /a "SCAN_COUNT=0"
for /r "%TARGET_DIR%" %%F in (*.exe) do (
    set "EXE_NAME=%%~nxF"
    set "EXE_PATH=%%~fF"
    setlocal EnableDelayedExpansion
    set /a "SCAN_COUNT+=1"
    echo  [!SCAN_COUNT!] !EXE_NAME!
    echo        Path: "!EXE_PATH!"
    endlocal
    set /a "SCAN_COUNT+=1"
)
:: Correct the loop count
echo.
echo ------------------------------------------------------------------------------
echo  Scan completed for target folder.
echo ------------------------------------------------------------------------------
pause
goto MENU

:CHECK_AND_BLOCK_BOTH
set "BLOCK_MODE=BOTH"
goto VALIDATE_AND_BLOCK

:CHECK_AND_BLOCK_OUT
set "BLOCK_MODE=OUT"
goto VALIDATE_AND_BLOCK

:CHECK_AND_BLOCK_IN
set "BLOCK_MODE=IN"
goto VALIDATE_AND_BLOCK

:VALIDATE_AND_BLOCK
if not defined TARGET_DIR (
    setlocal EnableDelayedExpansion
    call :CHECK_DIR_SET
    endlocal
)
call :CHECK_PROTECTED
if not defined TARGET_DIR goto MENU

:DO_BLOCK
cls
echo ==============================================================================
echo  BLOCKING: Applying Windows Firewall Block Rules (Mode: %BLOCK_MODE%)
echo ==============================================================================
echo  Target: "%TARGET_DIR%"
echo ------------------------------------------------------------------------------
echo.

set /a "BLOCK_COUNT=0"
set /a "RULE_COUNT=0"
set /a "FAIL_COUNT=0"

for /r "%TARGET_DIR%" %%F in (*.exe) do (
    set "EXE_NAME=%%~nxF"
    set "EXE_PATH=%%~fF"
    
    :: Process each executable with isolated delayed expansion to preserve ! in paths
    setlocal EnableDelayedExpansion
    echo [+] Processing: !EXE_NAME!

    if "%BLOCK_MODE%"=="BOTH" (
        netsh advfirewall firewall delete rule name="[FWB-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
        netsh advfirewall firewall delete rule name="[FWB-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
        netsh advfirewall firewall delete rule name="[FolderBlock-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
        netsh advfirewall firewall delete rule name="[FolderBlock-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1

        netsh advfirewall firewall add rule name="[FWB-IN] !EXE_NAME!" dir=in action=block program="!EXE_PATH!" enable=yes profile=any >nul 2>&1
        if !errorlevel! equ 0 (
            echo       [OK] Inbound Block Added
        ) else (
            echo       [FAIL] Inbound Block Failed
        )

        netsh advfirewall firewall add rule name="[FWB-OUT] !EXE_NAME!" dir=out action=block program="!EXE_PATH!" enable=yes profile=any >nul 2>&1
        if !errorlevel! equ 0 (
            echo       [OK] Outbound Block Added
        ) else (
            echo       [FAIL] Outbound Block Failed
        )
    )

    if "%BLOCK_MODE%"=="OUT" (
        netsh advfirewall firewall delete rule name="[FWB-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
        netsh advfirewall firewall delete rule name="[FolderBlock-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1

        netsh advfirewall firewall add rule name="[FWB-OUT] !EXE_NAME!" dir=out action=block program="!EXE_PATH!" enable=yes profile=any >nul 2>&1
        if !errorlevel! equ 0 (
            echo       [OK] Outbound Block Added
        ) else (
            echo       [FAIL] Outbound Block Failed
        )
    )

    if "%BLOCK_MODE%"=="IN" (
        netsh advfirewall firewall delete rule name="[FWB-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
        netsh advfirewall firewall delete rule name="[FolderBlock-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1

        netsh advfirewall firewall add rule name="[FWB-IN] !EXE_NAME!" dir=in action=block program="!EXE_PATH!" enable=yes profile=any >nul 2>&1
        if !errorlevel! equ 0 (
            echo       [OK] Inbound Block Added
        ) else (
            echo       [FAIL] Inbound Block Failed
        )
    )
    endlocal
    set /a "BLOCK_COUNT+=1"
)

echo.
echo ==============================================================================
echo  FIREWALL BLOCK OPERATION COMPLETED
echo ==============================================================================
echo  Executables Processed : %BLOCK_COUNT%
echo  Target Directory      : "%TARGET_DIR%"
echo ==============================================================================
pause
goto MENU

:CHECK_AND_UNBLOCK
if not defined TARGET_DIR (
    setlocal EnableDelayedExpansion
    call :CHECK_DIR_SET
    endlocal
)
call :CHECK_PROTECTED
if not defined TARGET_DIR goto MENU

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
    set "EXE_NAME=%%~nxF"
    set "EXE_PATH=%%~fF"
    
    setlocal EnableDelayedExpansion
    echo [-] Cleaning rules for: !EXE_NAME!
    netsh advfirewall firewall delete rule name="[FWB-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
    netsh advfirewall firewall delete rule name="[FWB-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
    netsh advfirewall firewall delete rule name="[FolderBlock-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
    netsh advfirewall firewall delete rule name="[FolderBlock-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
    netsh advfirewall firewall delete rule name=all program="!EXE_PATH!" >nul 2>&1
    endlocal
    set /a "UNBLOCK_COUNT+=1"
)

echo.
echo ==============================================================================
echo  FIREWALL UNBLOCK COMPLETE
echo ==============================================================================
echo  Executables Cleaned: %UNBLOCK_COUNT%
echo ==============================================================================
pause
goto MENU

:QUIT
cls
echo Exiting FirewallBlocker...
exit /b 0
