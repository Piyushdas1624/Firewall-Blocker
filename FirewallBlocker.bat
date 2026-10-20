@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul 2>&1
title FirewallBlocker - Windows Firewall Manager (Win 7 - 11) v2.4

:: -----------------------------------------------------------------------------
:: Resolve script location and default target directory
:: -----------------------------------------------------------------------------
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

:: -----------------------------------------------------------------------------
:: Primary Execution: Universal PowerShell Engine (Win 7 SP1 - 11, Color-Coded)
:: -----------------------------------------------------------------------------
set "PS_SCRIPT="
if exist "%SCRIPT_DIR%\FirewallBlocker.ps1" set "PS_SCRIPT=%SCRIPT_DIR%\FirewallBlocker.ps1"
if not defined PS_SCRIPT if exist "%SCRIPT_DIR%\run.ps1" set "PS_SCRIPT=%SCRIPT_DIR%\run.ps1"

if defined PS_SCRIPT (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if ((Get-ExecutionPolicy) -eq 'Restricted' -or $ExecutionContext.SessionState.LanguageMode -eq 'ConstrainedLanguage') { exit 1 }; exit 0" >nul 2>&1
    if not errorlevel 1 goto RUN_POWERSHELL
)
goto RUN_BATCH

:RUN_POWERSHELL
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -InitialDir "%SCRIPT_DIR%" %*
exit /b %errorlevel%

:RUN_BATCH
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
if not "%~1"=="" if exist "%~1" (
    for %%I in ("%~1") do set "TARGET_DIR=%%~fI"
)

:: Safety check: Do not default to System32 or Windows root
call :CHECK_PROTECTED
if not defined TARGET_DIR (
    set "TARGET_DIR="
)

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

if not defined CHOICE goto MENU
if /i "%CHOICE:"=%"=="1" goto CHECK_AND_BLOCK_BOTH
if /i "%CHOICE:"=%"=="2" goto CHECK_AND_BLOCK_OUT
if /i "%CHOICE:"=%"=="3" goto CHECK_AND_BLOCK_IN
if /i "%CHOICE:"=%"=="4" goto CHECK_AND_UNBLOCK
if /i "%CHOICE:"=%"=="5" goto CHECK_AND_SCAN
if /i "%CHOICE:"=%"=="6" goto CHANGE_DIR
if /i "%CHOICE:"=%"=="7" goto OPEN_WF
if /i "%CHOICE:"=%"=="8" goto QUIT
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
        for %%I in ("%INPUT_DIR:"=%") do (
            if exist "%%~fI" (
                set "TARGET_DIR=%%~fI"
            ) else (
                echo  [!] Directory not found: "%%~fI"
                timeout /t 2 >nul 2>&1
            )
        )
    )
)
exit /b 0

:CHECK_PROTECTED
if not defined TARGET_DIR exit /b 1

:: Normalize trailing slash and extended path prefix
set "CHK_DIR=%TARGET_DIR%"
if "%CHK_DIR:~0,4%"=="\\?\" set "CHK_DIR=%CHK_DIR:~4%"
if "%CHK_DIR:~-1%"=="\" set "CHK_DIR=%CHK_DIR:~0,-1%"

:: Check root drive (e.g. C: or C:\)
if "%CHK_DIR:~1,2%"==":\" if "%CHK_DIR:~3%"=="" goto PROTECTED_ERROR
if "%CHK_DIR:~1,1%"==":" if "%CHK_DIR:~2%"=="" goto PROTECTED_ERROR

:: Check Windows directory or any subdirectory (System32, SysWOW64, WinSxS, etc.)
set "TD_SLASH=%CHK_DIR%\"
call set "TD_SUB=%%TD_SLASH:%SystemRoot%\=%%"
if not "%TD_SUB%"=="%TD_SLASH%" goto PROTECTED_ERROR
if /i "%CHK_DIR%"=="%SystemRoot%" goto PROTECTED_ERROR

:: Check Program Files & Program Files (x86) root directory directly
if /i "%CHK_DIR%"=="%ProgramFiles%" goto PROTECTED_ERROR
if defined ProgramFiles(x86) (
    if /i "%CHK_DIR%"=="%ProgramFiles(x86)%" goto PROTECTED_ERROR
)

:: Check ProgramData root directory directly and Defender folders
if defined ProgramData (
    if /i "%CHK_DIR%"=="%ProgramData%" goto PROTECTED_ERROR
    call set "TD_DEF_DATA=%%TD_SLASH:%ProgramData%\Microsoft\Windows Defender\=%%"
    if not "%TD_DEF_DATA%"=="%TD_SLASH%" goto PROTECTED_ERROR
    call set "TD_DEF_DATA2=%%TD_SLASH:%ProgramData%\Microsoft\Windows Defender Advanced Threat Protection\=%%"
    if not "%TD_DEF_DATA2%"=="%TD_SLASH%" goto PROTECTED_ERROR
)

:: Check Defender in Program Files / Program Files (x86)
call set "TD_DEF_PF=%%TD_SLASH:%ProgramFiles%\Windows Defender\=%%"
if not "%TD_DEF_PF%"=="%TD_SLASH%" goto PROTECTED_ERROR
if defined ProgramFiles(x86) (
    call set "TD_DEF_PF86=%%TD_SLASH:%ProgramFiles(x86)%\Windows Defender\=%%"
    if not "%TD_DEF_PF86%"=="%TD_SLASH%" goto PROTECTED_ERROR
)

:: Check LocalAppData Microsoft\WindowsApps (Windows Store execution aliases)
if defined LOCALAPPDATA (
    call set "TD_WINAPPS=%%TD_SLASH:%LOCALAPPDATA%\Microsoft\WindowsApps\=%%"
    if not "%TD_WINAPPS%"=="%TD_SLASH%" goto PROTECTED_ERROR
    if /i "%CHK_DIR%"=="%LOCALAPPDATA%\Microsoft\WindowsApps" goto PROTECTED_ERROR
)
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
exit /b 1

:CHANGE_DIR
cls
echo ==============================================================================
echo  CHANGE TARGET DIRECTORY
echo ==============================================================================
echo.
set "NEW_DIR="
set /p "NEW_DIR=Enter folder path (or press Enter to cancel): "
if not defined NEW_DIR goto MENU
for %%I in ("%NEW_DIR:"=%") do (
    if exist "%%~fI" (
        set "TARGET_DIR=%%~fI"
        call :CHECK_PROTECTED
        if defined TARGET_DIR (
            echo  [OK] Target directory updated to: "%%~fI"
            timeout /t 1 >nul 2>&1
        )
    ) else (
        echo  [!] Directory not found: "%%~fI"
        timeout /t 2 >nul 2>&1
    )
)
goto MENU

:OPEN_WF
start wf.msc
goto MENU

:CHECK_AND_SCAN
if not defined TARGET_DIR call :CHECK_DIR_SET
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
    if not exist "%%~fF\*" (
        set /a "SCAN_COUNT+=1"
        set "EXE_NAME=%%~nxF"
        set "EXE_PATH=%%~fF"
        setlocal EnableDelayedExpansion
        echo  [!SCAN_COUNT!] !EXE_NAME!
        echo        Path: "!EXE_PATH!"
        endlocal
    )
)
echo.
echo ------------------------------------------------------------------------------
echo  Scan completed. Total executables found: %SCAN_COUNT%
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
if not defined TARGET_DIR call :CHECK_DIR_SET
call :CHECK_PROTECTED
if not defined TARGET_DIR goto MENU

:: Check if target is User Profile root or large directory (> 100 exes)
set "IS_SENSITIVE=0"
set "CHK_SENS=%TARGET_DIR%"
if "%CHK_SENS:~0,4%"=="\\?\" set "CHK_SENS=%CHK_SENS:~4%"
if "%CHK_SENS:~-1%"=="\" set "CHK_SENS=%CHK_SENS:~0,-1%"
if defined USERPROFILE if /i "%CHK_SENS%"=="%USERPROFILE%" set "IS_SENSITIVE=1"
if /i "%CHK_SENS%"=="%SystemDrive%\Users" set "IS_SENSITIVE=1"
if defined PUBLIC if /i "%CHK_SENS%"=="%PUBLIC%" set "IS_SENSITIVE=1"
for /f "delims=" %%U in ("%CHK_SENS%") do (
    if /i "%%~dpU"=="%SystemDrive%\Users\" set "IS_SENSITIVE=1"
)

set /a "PRE_COUNT=0"
for /r "%TARGET_DIR%" %%F in (*.exe) do (
    if not exist "%%~fF\*" set /a "PRE_COUNT+=1"
)
if %PRE_COUNT% gtr 100 set "IS_SENSITIVE=1"

if "%IS_SENSITIVE%"=="1" (
    cls
    echo ==============================================================================
    echo  [CONFIRMATION REQUIRED] POTENTIALLY SENSITIVE OR LARGE TARGET!
    echo ==============================================================================
    echo  Directory: "%TARGET_DIR%"
    echo  Discovered executables: %PRE_COUNT%
    if defined USERPROFILE if /i "%TARGET_DIR%"=="%USERPROFILE%" (
        echo  [!] Warning: Target is a User Profile directory.
        echo      Blocking this will affect AppData, Local, and Desktop applications.
    )
    if %PRE_COUNT% gtr 100 (
        echo  [!] Warning: Target contains over 100 executables.
    )
    echo ==============================================================================
    echo.
    set "CONFIRM="
    set /p "CONFIRM=Are you SURE you want to block all %PRE_COUNT% executable(s)? [Y/N]: "
    if not defined CONFIRM goto CANCEL_BLOCK
    if /i not "%CONFIRM:"=%"=="Y" goto CANCEL_BLOCK
)
goto DO_BLOCK

:CANCEL_BLOCK
echo  [CANCEL] Block operation cancelled by user.
timeout /t 2 >nul 2>&1
goto MENU

:DO_BLOCK
cls
echo ==============================================================================
echo  BLOCKING: Applying Windows Firewall Block Rules (Mode: %BLOCK_MODE%)
echo ==============================================================================
echo  Target: "%TARGET_DIR%"
echo ------------------------------------------------------------------------------
echo.

set /a "BLOCK_COUNT=0"
set /a "SUCCESS_COUNT=0"
set /a "FAIL_COUNT=0"

for /r "%TARGET_DIR%" %%F in (*.exe) do (
    if not exist "%%~fF\*" (
        set /a "BLOCK_COUNT+=1"
        set "EXE_NAME=%%~nxF"
        set "EXE_PATH=%%~fF"
        
        :: Compute 8-char SHA256 path hash via certutil (case-insensitive by lowercasing path)
        set "RULE_HASH="
        setlocal EnableDelayedExpansion
        set "LOWER_PATH=!EXE_PATH!"
        for %%A in (a b c d e f g h i j k l m n o p q r s t u v w x y z) do (
            set "LOWER_PATH=!LOWER_PATH:%%A=%%A!"
        )
        set "TMP_H=%TEMP%\_fwb_%RANDOM%_%RANDOM%.tmp"
        <nul set /p="!LOWER_PATH!">"!TMP_H!" 2>nul
        for /f "skip=1 delims=" %%H in ('certutil -hashfile "!TMP_H!" SHA256 2^>nul') do (
            if not defined RULE_HASH (
                set "H=%%H"
                set "H=!H: =!"
                set "RULE_HASH=!H:~0,8!"
            )
        )
        if exist "!TMP_H!" del "!TMP_H!" >nul 2>&1
        if defined RULE_HASH (
            for %%A in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
                set "RULE_HASH=!RULE_HASH:%%A=%%A!"
            )
            set "IN_RULE=[FWB-IN] !EXE_NAME! (!RULE_HASH!)"
            set "OUT_RULE=[FWB-OUT] !EXE_NAME! (!RULE_HASH!)"
        ) else (
            set "IN_RULE=[FWB-IN] !EXE_NAME!"
            set "OUT_RULE=[FWB-OUT] !EXE_NAME!"
        )

        echo [+] Processing: !EXE_NAME!

        if "%BLOCK_MODE%"=="BOTH" (
            netsh advfirewall firewall delete rule name="!IN_RULE!" >nul 2>&1
            netsh advfirewall firewall delete rule name="!OUT_RULE!" >nul 2>&1
            netsh advfirewall firewall delete rule name="[FWB-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
            netsh advfirewall firewall delete rule name="[FWB-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
            netsh advfirewall firewall delete rule name="[FolderBlock-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
            netsh advfirewall firewall delete rule name="[FolderBlock-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1

            netsh advfirewall firewall add rule name="!IN_RULE!" dir=in action=block program="!EXE_PATH!" enable=yes profile=any description="Blocked by FirewallBlocker | !EXE_PATH!" >nul 2>&1
            if !errorlevel! equ 0 (
                echo       [OK] Inbound Block Added
            ) else (
                echo       [FAIL] Inbound Block Failed
            )

            netsh advfirewall firewall add rule name="!OUT_RULE!" dir=out action=block program="!EXE_PATH!" enable=yes profile=any description="Blocked by FirewallBlocker | !EXE_PATH!" >nul 2>&1
            if !errorlevel! equ 0 (
                echo       [OK] Outbound Block Added
            ) else (
                echo       [FAIL] Outbound Block Failed
            )
        )

        if "%BLOCK_MODE%"=="OUT" (
            netsh advfirewall firewall delete rule name="!OUT_RULE!" >nul 2>&1
            netsh advfirewall firewall delete rule name="[FWB-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
            netsh advfirewall firewall delete rule name="[FolderBlock-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1

            netsh advfirewall firewall add rule name="!OUT_RULE!" dir=out action=block program="!EXE_PATH!" enable=yes profile=any description="Blocked by FirewallBlocker | !EXE_PATH!" >nul 2>&1
            if !errorlevel! equ 0 (
                echo       [OK] Outbound Block Added
            ) else (
                echo       [FAIL] Outbound Block Failed
            )
        )

        if "%BLOCK_MODE%"=="IN" (
            netsh advfirewall firewall delete rule name="!IN_RULE!" >nul 2>&1
            netsh advfirewall firewall delete rule name="[FWB-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
            netsh advfirewall firewall delete rule name="[FolderBlock-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1

            netsh advfirewall firewall add rule name="!IN_RULE!" dir=in action=block program="!EXE_PATH!" enable=yes profile=any description="Blocked by FirewallBlocker | !EXE_PATH!" >nul 2>&1
            if !errorlevel! equ 0 (
                echo       [OK] Inbound Block Added
            ) else (
                echo       [FAIL] Inbound Block Failed
            )
        )
        endlocal
    )
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
if not defined TARGET_DIR call :CHECK_DIR_SET
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
    if not exist "%%~fF\*" (
        set /a "UNBLOCK_COUNT+=1"
        set "EXE_NAME=%%~nxF"
        set "EXE_PATH=%%~fF"
        
        :: Compute 8-char SHA256 path hash via certutil (case-insensitive by lowercasing path)
        set "RULE_HASH="
        setlocal EnableDelayedExpansion
        set "LOWER_PATH=!EXE_PATH!"
        for %%A in (a b c d e f g h i j k l m n o p q r s t u v w x y z) do (
            set "LOWER_PATH=!LOWER_PATH:%%A=%%A!"
        )
        set "TMP_H=%TEMP%\_fwb_%RANDOM%_%RANDOM%.tmp"
        <nul set /p="!LOWER_PATH!">"!TMP_H!" 2>nul
        for /f "skip=1 delims=" %%H in ('certutil -hashfile "!TMP_H!" SHA256 2^>nul') do (
            if not defined RULE_HASH (
                set "H=%%H"
                set "H=!H: =!"
                set "RULE_HASH=!H:~0,8!"
            )
        )
        if exist "!TMP_H!" del "!TMP_H!" >nul 2>&1
        if defined RULE_HASH (
            for %%A in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
                set "RULE_HASH=!RULE_HASH:%%A=%%A!"
            )
        )

        echo [-] Cleaning rules for: !EXE_NAME!
        if defined RULE_HASH (
            netsh advfirewall firewall delete rule name="[FWB-IN] !EXE_NAME! (!RULE_HASH!)" >nul 2>&1
            netsh advfirewall firewall delete rule name="[FWB-OUT] !EXE_NAME! (!RULE_HASH!)" >nul 2>&1
        )
        netsh advfirewall firewall delete rule name="[FWB-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
        netsh advfirewall firewall delete rule name="[FWB-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
        netsh advfirewall firewall delete rule name="[FolderBlock-IN] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
        netsh advfirewall firewall delete rule name="[FolderBlock-OUT] !EXE_NAME!" program="!EXE_PATH!" >nul 2>&1
        endlocal
    )
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
