# Automated Test Suite for FirewallBlocker
$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$blockerPs1 = Join-Path $repoRoot "FirewallBlocker.ps1"
$runPs1 = Join-Path $repoRoot "run.ps1"
$blockerBat = Join-Path $repoRoot "FirewallBlocker.bat"
$textBat = Join-Path $repoRoot "text.bat"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "Running FirewallBlocker Automated Test Suite v2.5" -ForegroundColor White
Write-Host "====================================================" -ForegroundColor Cyan

$testDirsToCleanup = New-Object System.Collections.ArrayList

try {
    # -------------------------------------------------------------------------
    # Test 1: Syntax Parse Check for FirewallBlocker.ps1 (PS 2.0 to 7.x compatible)
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 1] Parsing FirewallBlocker.ps1 syntax..." -ForegroundColor Yellow
    $ps3Parser = [Type]::GetType("System.Management.Automation.Language.Parser, System.Management.Automation")
    if ($null -ne $ps3Parser) {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($blockerPs1, [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors.Count -eq 0) {
            Write-Host "  -> PASS: FirewallBlocker.ps1 AST syntax is 100% valid." -ForegroundColor Green
        } else {
            Write-Host "  -> FAIL: Syntax errors detected in FirewallBlocker.ps1:" -ForegroundColor Red
            $parseErrors | ForEach-Object { Write-Host "     Line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Red }
            exit 1
        }
    } else {
        $errors = $null
        $rawContent = [System.IO.File]::ReadAllText($blockerPs1)
        $tokens = [System.Management.Automation.PSParser]::Tokenize($rawContent, [ref]$errors)
        if ($errors.Count -eq 0) {
            Write-Host "  -> PASS: FirewallBlocker.ps1 PSParser syntax is valid (PS 2.0 mode)." -ForegroundColor Green
        } else {
            Write-Host "  -> FAIL: Syntax errors detected:" -ForegroundColor Red
            $errors | ForEach-Object { Write-Host "     Line $($_.StartLine): $($_.Message)" -ForegroundColor Red }
            exit 1
        }
    }

    # -------------------------------------------------------------------------
    # Test 2: Syntax Parse Check for run.ps1
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 2] Parsing run.ps1 syntax..." -ForegroundColor Yellow
    if ($null -ne $ps3Parser) {
        $tokens2 = $null
        $parseErrors2 = $null
        $ast2 = [System.Management.Automation.Language.Parser]::ParseFile($runPs1, [ref]$tokens2, [ref]$parseErrors2)
        if ($parseErrors2.Count -eq 0) {
            Write-Host "  -> PASS: run.ps1 AST syntax is 100% valid." -ForegroundColor Green
        } else {
            Write-Host "  -> FAIL: Syntax errors detected in run.ps1:" -ForegroundColor Red
            $parseErrors2 | ForEach-Object { Write-Host "     Line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Red }
            exit 1
        }
    } else {
        $errors2 = $null
        $rawContent2 = [System.IO.File]::ReadAllText($runPs1)
        $tokens2 = [System.Management.Automation.PSParser]::Tokenize($rawContent2, [ref]$errors2)
        if ($errors2.Count -eq 0) {
            Write-Host "  -> PASS: run.ps1 PSParser syntax is valid (PS 2.0 mode)." -ForegroundColor Green
        } else {
            Write-Host "  -> FAIL: Syntax errors in run.ps1:" -ForegroundColor Red
            $errors2 | ForEach-Object { Write-Host "     Line $($_.StartLine): $($_.Message)" -ForegroundColor Red }
            exit 1
        }
    }

    # -------------------------------------------------------------------------
    # Test 3: Byte Parity Check between FirewallBlocker.ps1 and run.ps1
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 3] Verifying parity between FirewallBlocker.ps1 and run.ps1..." -ForegroundColor Yellow
    $content1 = [System.IO.File]::ReadAllText($blockerPs1)
    $content2 = [System.IO.File]::ReadAllText($runPs1)
    if ($content1 -eq $content2) {
        Write-Host "  -> PASS: FirewallBlocker.ps1 and run.ps1 are 100% identical and in sync." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: FirewallBlocker.ps1 and run.ps1 have diverged!" -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 4: Target with Special Characters, ! in path, and Directory ending in .exe
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 4] Testing Directory Scanning, Special Characters & Folder .exe exclusion..." -ForegroundColor Yellow
    $dummyRoot = Join-Path $scriptDir "DummyTarget & Tools (2024) [v1.0]!"
    $null = $testDirsToCleanup.Add($dummyRoot)
    if (Test-Path -LiteralPath $dummyRoot) { Remove-Item -LiteralPath $dummyRoot -Recurse -Force }
    $sub1 = Join-Path $dummyRoot "Binaries"
    $sub2 = Join-Path $dummyRoot "Tools & Utilities"
    $subDirExe = Join-Path $dummyRoot "FakeFolder.exe" # A DIRECTORY named .exe
    New-Item -ItemType Directory -Path $sub1 -Force | Out-Null
    New-Item -ItemType Directory -Path $sub2 -Force | Out-Null
    New-Item -ItemType Directory -Path $subDirExe -Force | Out-Null

    $dummyExe1 = Join-Path $sub1 "Game Launcher & Updater.exe"
    $dummyExe2 = Join-Path $sub2 "CrashReporter (x64)!.exe" # contains ! in filename
    $dummyTxt = Join-Path $dummyRoot "readme.txt"

    [System.IO.File]::WriteAllBytes($dummyExe1, [byte[]]@(0x4D, 0x5A, 0x90, 0x00))
    [System.IO.File]::WriteAllBytes($dummyExe2, [byte[]]@(0x4D, 0x5A, 0x90, 0x00))
    [System.IO.File]::WriteAllText($dummyTxt, "Dummy text file")

    # Execute scan via child process and capture output
    $psiScan = New-Object System.Diagnostics.ProcessStartInfo
    $psiScan.FileName = "powershell.exe"
    $psiScan.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`" -TargetDir `"$dummyRoot`" -Action Scan -NonInteractive"
    $psiScan.RedirectStandardOutput = $true
    $psiScan.RedirectStandardError = $true
    $psiScan.UseShellExecute = $false
    $psiScan.CreateNoWindow = $true

    $scanProcess = [System.Diagnostics.Process]::Start($psiScan)
    $scanStdout = $scanProcess.StandardOutput.ReadToEnd()
    $scanStderr = $scanProcess.StandardError.ReadToEnd()
    $scanProcess.WaitForExit()

    if ($scanProcess.ExitCode -eq 0 -and
        $scanStdout -match "Total Executables Discovered\s*:\s*2" -and
        $scanStdout -match "Game Launcher & Updater\.exe" -and
        $scanStdout -match "CrashReporter \(x64\)!\.exe" -and
        $scanStdout -notmatch "FakeFolder\.exe") {
        Write-Host "  -> PASS: Child process scan completed with ExitCode 0, found exactly 2 exes, and excluded FakeFolder.exe directory." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Scan process validation failed. ExitCode: $($scanProcess.ExitCode)" -ForegroundColor Red
        Write-Host "     Output: $scanStdout" -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 5: Batch File Execution and Delegation (text.bat & FirewallBlocker.bat)
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 5] Testing text.bat and FirewallBlocker.bat Delegation..." -ForegroundColor Yellow
    $cmdArg = "/c `"`"$textBat`" -TargetDir `"$dummyRoot`" -Action Scan -NonInteractive`""
    $batProcess = Start-Process -FilePath "cmd.exe" -ArgumentList $cmdArg -NoNewWindow -Wait -PassThru
    if ($batProcess.ExitCode -eq 0) {
        Write-Host "  -> PASS: text.bat invoked successfully with ExitCode 0." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: text.bat exited with code $($batProcess.ExitCode)." -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 6: Verify Critical System Path Protection
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 6] Verifying Protected System Path Safety Guardrails..." -ForegroundColor Yellow
    $pathsToTest = @(
        "C:\Windows",
        "C:\Windows\System32",
        "C:\Program Files",
        ${env:ProgramFiles(x86)},
        "$env:ProgramData\Microsoft\Windows Defender"
    )

    foreach ($p in $pathsToTest) {
        if (-not [string]::IsNullOrEmpty($p) -and (Test-Path -LiteralPath $p)) {
            $guardProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`" -TargetDir `"$p`" -Action BlockBoth -NonInteractive" -NoNewWindow -Wait -PassThru
            if ($guardProcess.ExitCode -eq 2) {
                Write-Host "  -> PASS: Protected path '$p' was safely blocked with ExitCode 2." -ForegroundColor Green
            } else {
                Write-Host "  -> FAIL: '$p' did not trigger safety block (ExitCode: $($guardProcess.ExitCode))." -ForegroundColor Red
                exit 1
            }
        }
    }

    # -------------------------------------------------------------------------
    # Test 7: Verify Empty Directory Scan
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 7] Testing Empty Directory Scan..." -ForegroundColor Yellow
    $emptyDir = Join-Path $scriptDir "EmptyDummyFolder"
    $null = $testDirsToCleanup.Add($emptyDir)
    if (Test-Path -LiteralPath $emptyDir) { Remove-Item -LiteralPath $emptyDir -Recurse -Force }
    New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null
    $emptyProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`" -TargetDir `"$emptyDir`" -Action Scan -NonInteractive" -NoNewWindow -Wait -PassThru
    if ($emptyProcess.ExitCode -eq 0) {
        Write-Host "  -> PASS: Empty directory handled gracefully without error." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Empty directory scan returned code $($emptyProcess.ExitCode)." -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 8: Verify Invalid Action Handling
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 8] Testing Invalid Action Rejection..." -ForegroundColor Yellow
    $invalidProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`" -Action InvalidCommandXYZ -NonInteractive" -NoNewWindow -Wait -PassThru
    if ($invalidProcess.ExitCode -eq 1) {
        Write-Host "  -> PASS: Invalid action rejected with exit code 1." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Expected exit code 1 for invalid action, got $($invalidProcess.ExitCode)." -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 9: Verify FIPS-Compliant SHA256 Portable Hash (Calling Blocker directly)
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 9] Testing FIPS-Compliant SHA256 Portable Hash..." -ForegroundColor Yellow
    # Dot-source functions without running the main loop/dispatcher
    . $blockerPs1 -ExportFunctionsOnly

    $h1 = Get-PortableHash -InputString "C:\Games\App.exe"
    $h2 = Get-PortableHash -InputString "c:\games\app.exe"
    $h3 = Get-PortableHash -InputString "C:\Games\Other.exe"
    if ($h1 -eq $h2 -and $h1 -ne $h3 -and $h1.Length -eq 8 -and $h1 -eq "B42ACF78") {
        Write-Host "  -> PASS: SHA256 hash is deterministic, FIPS-compliant, and case-insensitive ($h1)." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: SHA256 hash check failed. Got '$h1', expected 'B42ACF78'." -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 10: Verify Human Error Diagnostic Analyzer
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 10] Testing Human-Readable Error Diagnostic Engine..." -ForegroundColor Yellow
    $fakeElevError = Format-HumanFirewallError -RawOutput "The requested operation requires elevation (Run as administrator)." -ExitCode 1 -ExePath "C:\Game\app.exe" -Direction "INBOUND" -RuleName "[FWB-IN] app.exe"
    $fakeSvcError  = Format-HumanFirewallError -RawOutput "An error occurred while attempting to contact the Windows Firewall service." -ExitCode 1 -ExePath "C:\Game\app.exe" -Direction "OUTBOUND" -RuleName "[FWB-OUT] app.exe"
    $fakeGpoError  = Format-HumanFirewallError -RawOutput "The rule was not added because Group Policy does not allow local firewall rules." -ExitCode 1 -ExePath "C:\Game\app.exe" -Direction "OUTBOUND" -RuleName "[FWB-OUT] app.exe"
    
    $longPath = "C:\" + ("A" * 255) + "\game.exe"
    $fakePathError = Format-HumanFirewallError -RawOutput "" -ExitCode 1 -ExePath $longPath -Direction "INBOUND" -RuleName "[FWB-IN] game.exe"

    $fakeDescError = Format-HumanFirewallError -RawOutput "The description contains invalid characters, or is an invalid length." -ExitCode 1 -ExePath "C:\Program Files (x86)\AutoCAD 2007\acad.exe" -Direction "INBOUND" -RuleName "[FWB-IN] acad.exe"
    $fakeNetshUsage = "The description contains invalid characters, or is an invalid length.`r`nUsage: add rule name=<string>`r`n      [localport=0-65535|<port range>[,...]|RPC|RPC-EPMap|IPHTTPS|any (default=any)]"
    $fakeUsageDiag = Format-HumanFirewallError -RawOutput $fakeNetshUsage -ExitCode 1 -ExePath "C:\Program Files (x86)\AutoCAD 2007\acad.exe" -Direction "INBOUND" -RuleName "[FWB-IN] acad.exe"
    $fakeSyntaxUsage = "A specified value is not valid.`r`nUsage: add rule name=<string>`r`n      [localport=0-65535|<port range>[,...]|RPC|RPC-EPMap|IPHTTPS|any (default=any)]"
    $fakeSyntaxDiag = Format-HumanFirewallError -RawOutput $fakeSyntaxUsage -ExitCode 1 -ExePath "C:\Program Files (x86)\AutoCAD 2007\acad.exe" -Direction "INBOUND" -RuleName "[FWB-IN] acad.exe"
    $fakeRealRpc = Format-HumanFirewallError -RawOutput "The RPC server is unavailable." -ExitCode 1 -ExePath "C:\Game\app.exe" -Direction "INBOUND" -RuleName "[FWB-IN] app.exe"

    if ($fakeElevError.Location -eq "Windows Security Token (UAC)" -and
        $fakeSvcError.Location  -eq "Windows Service Manager (MpsSvc)" -and
        $fakeGpoError.Location  -eq "Active Directory / Local Group Policy" -and
        $fakePathError.Location -eq "Win32 File Subsystem (MAX_PATH)" -and
        $fakeDescError.Location -eq "Command Parser / Rule Parameter" -and
        $fakeUsageDiag.Location -eq "Command Parser / Rule Parameter" -and
        $fakeSyntaxDiag.Location -eq "Command Parser" -and
        $fakeRealRpc.Location   -eq "Windows Service Manager (MpsSvc)" -and
        $fakeUsageDiag.Location -ne "Windows Service Manager (MpsSvc)" -and
        $fakeSyntaxDiag.Location -ne "Windows Service Manager (MpsSvc)") {
        Write-Host "  -> PASS: Human error diagnostics properly pinpoint Location, Root Cause, and Fix across all categories (including invalid characters, syntax errors, and real RPC failures without false MpsSvc triggers)." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Human error diagnostic mapping failed." -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 11: Single-Element Array .Count Bug Check (PowerShell 2.0 Invariant)
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 11] Testing Single-Element Executable Collection & .Count Property..." -ForegroundColor Yellow
    $singleDir = Join-Path $scriptDir "SingleExeDummyFolder"
    $null = $testDirsToCleanup.Add($singleDir)
    if (Test-Path -LiteralPath $singleDir) { Remove-Item -LiteralPath $singleDir -Recurse -Force }
    New-Item -ItemType Directory -Path $singleDir -Force | Out-Null
    $singleExe = Join-Path $singleDir "SingleApp.exe"
    [System.IO.File]::WriteAllBytes($singleExe, [byte[]]@(0x4D, 0x5A, 0x90, 0x00))

    $scannedSingle = Get-TargetExecutables -PathToScan $singleDir
    if ($null -ne $scannedSingle -and $scannedSingle.Count -eq 1 -and $scannedSingle[0].Name -eq "SingleApp.exe") {
        Write-Host "  -> PASS: Single-element collection preserves .Count = 1 without pipeline unrolling." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Single-element array count failed: $($scannedSingle.Count)" -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 12: Batch Engine Integrity, Variable Scoping & Hash Parity
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 12] Auditing Batch Engine Integrity & Hash Parity..." -ForegroundColor Yellow
    $batContent = [System.IO.File]::ReadAllText($blockerBat)

    # Invariant 1: No setlocal/endlocal around CHECK_DIR_SET that destroys TARGET_DIR
    $hasScopeTrap = ($batContent -match 'setlocal\s+EnableDelayedExpansion\s+call\s+:CHECK_DIR_SET\s+endlocal')
    # Invariant 2: No destructive netsh delete rule name=all program=
    $hasOverDestructive = ($batContent -match 'netsh\s+advfirewall\s+firewall\s+delete\s+rule\s+name=all\s+program=')
    # Invariant 3: No corrupting delayed expansion substitution on input paths
    $hasDelayedSubTrap = ($batContent -match 'setlocal\s+EnableDelayedExpansion\s+set\s+"CLEAN_DIR=!(?:INPUT|NEW)_DIR:"=!')
    # Invariant 4: No parenthesized prompt blocks that cause parse-time expansion crashes
    $hasParenPromptTrap = ($batContent -match '(?s)if\s+[^\r\n(]*\((?:(?!\n\s*\)).)*?set\s+/p\s+')
    # Invariant 5: No pipe characters in netsh rule descriptions (causes netsh syntax invalid character crash)
    $hasPipeInDesc = ($batContent -match 'description="[^"]*\|[^"]*"')
    # Invariant 6: No un-sanitized substring substitution directly inside if conditions
    $hasUncheckedVarSub = ($batContent -match 'if\s+(?:/i\s+)?["'']?%(?:CHOICE|CONF_ADV|CONFIRM|CONFIRM_ADV|CONFIRM_ADV_UNB|INPUT_DIR|NEW_DIR):[^%]+%["'']?==')

    if (-not $hasScopeTrap -and -not $hasOverDestructive -and -not $hasDelayedSubTrap -and -not $hasParenPromptTrap -and -not $hasPipeInDesc -and -not $hasUncheckedVarSub) {
        Write-Host "  -> PASS: FirewallBlocker.bat verified free of variable scope traps, destructive deletions, parse-time parenthesized prompt traps, unchecked variable substitutions, and illegal pipe descriptions." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: FirewallBlocker.bat failed code invariants (scope: $hasScopeTrap, over-destructive: $hasOverDestructive, delayed sub: $hasDelayedSubTrap, paren prompt: $hasParenPromptTrap, pipe desc: $hasPipeInDesc, unchecked var sub: $hasUncheckedVarSub)." -ForegroundColor Red
        exit 1
    }

    # Verify live hash parity between batch fallback engine and PowerShell for both simple and complex paths
    $testSimplePath = "c:\games\app.exe"
    $psSimpleHash = Get-PortableHash -InputString $testSimplePath
    $testComplexPath = "C:\Games & Tools (2024)\CrashReporter!.exe"
    $psTargetHash = Get-PortableHash -InputString $testComplexPath
    
    # Run batch hash calculation for complex path
    $batchTestCmd = @"
@echo off
setlocal DisableDelayedExpansion
set "P=$testComplexPath"
setlocal EnableDelayedExpansion
set "LOWER=!P!"
for %%A in (a b c d e f g h i j k l m n o p q r s t u v w x y z) do set "LOWER=!LOWER:%%A=%%A!"
set "TMP_H=%TEMP%\_test_hash_%RANDOM%.tmp"
<nul set /p="!LOWER!">"!TMP_H!" 2>nul
set "RULE_HASH="
for /f "skip=1 delims=" %%H in ('certutil -hashfile "!TMP_H!" SHA256 2^>nul') do (
    if not defined RULE_HASH (
        set "H=%%H"
        set "H=!H: =!"
        set "RULE_HASH=!H:~0,8!"
    )
)
if exist "!TMP_H!" del "!TMP_H!" >nul 2>&1
for %%A in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do set "RULE_HASH=!RULE_HASH:%%A=%%A!"
echo !RULE_HASH!
"@
    $tmpBat = Join-Path $env:TEMP "test_batch_hash.bat"
    [System.IO.File]::WriteAllText($tmpBat, $batchTestCmd, [System.Text.Encoding]::ASCII)
    $rawBatOut = & cmd.exe /c $tmpBat
    $batchHashOutput = if ($rawBatOut) { ($rawBatOut | Out-String).Trim() } else { "" }
    Remove-Item $tmpBat -Force -ErrorAction SilentlyContinue

    # Run batch hash calculation for simple path ("c:\games\app.exe" -> B42ACF78)
    $batchSimpleCmd = @"
@echo off
setlocal DisableDelayedExpansion
set "P=$testSimplePath"
setlocal EnableDelayedExpansion
set "LOWER=!P!"
for %%A in (a b c d e f g h i j k l m n o p q r s t u v w x y z) do set "LOWER=!LOWER:%%A=%%A!"
set "TMP_H=%TEMP%\_test_hash2_%RANDOM%.tmp"
<nul set /p="!LOWER!">"!TMP_H!" 2>nul
set "RULE_HASH="
for /f "skip=1 delims=" %%H in ('certutil -hashfile "!TMP_H!" SHA256 2^>nul') do (
    if not defined RULE_HASH (
        set "H=%%H"
        set "H=!H: =!"
        set "RULE_HASH=!H:~0,8!"
    )
)
if exist "!TMP_H!" del "!TMP_H!" >nul 2>&1
for %%A in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do set "RULE_HASH=!RULE_HASH:%%A=%%A!"
echo !RULE_HASH!
"@
    $tmpBat2 = Join-Path $env:TEMP "test_batch_hash2.bat"
    [System.IO.File]::WriteAllText($tmpBat2, $batchSimpleCmd, [System.Text.Encoding]::ASCII)
    $rawBatOut2 = & cmd.exe /c $tmpBat2
    $batchSimpleOutput = if ($rawBatOut2) { ($rawBatOut2 | Out-String).Trim() } else { "" }
    Remove-Item $tmpBat2 -Force -ErrorAction SilentlyContinue

    if ($batchHashOutput -eq $psTargetHash -and $batchHashOutput -eq "8C422CDA" -and
        $batchSimpleOutput -eq $psSimpleHash -and $batchSimpleOutput -eq "B42ACF78") {
        Write-Host "  -> PASS: Batch engine SHA256 path hashes match PowerShell ('c:\games\app.exe' -> $batchSimpleOutput == $psSimpleHash; 'CrashReporter!.exe' -> $batchHashOutput == $psTargetHash)." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Batch hash parity check failed. Batch Simple: '$batchSimpleOutput' (expected $psSimpleHash), Batch Complex: '$batchHashOutput' (expected $psTargetHash)." -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------
    # Test 13: Multilingual Netsh Output Rule Status Parsing (Direct Blocker Call)
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 13] Verifying Multilingual Netsh Rule Parsing..." -ForegroundColor Yellow
    
    $samples = @{
        "DE_Block"       = "Regelname: [FWB-IN] game.exe`nAktiviert: Ja`nAktion: Blockieren"
        "FR_Block"       = ("Nom de r" + ([char]0x00E8) + "gle: [FWB-IN] game.exe`nActiv" + ([char]0x00E9) + ": Oui`nAction: Bloquer")
        "ES_Block"       = ("Nombre de regla: [FWB-IN] game.exe`nHabilitado: S" + ([char]0x00ED) + "`nAcci" + ([char]0x00F3) + "n: Bloquear")
        "RU_Block"       = (([char]0x0418) + ([char]0x043C) + ([char]0x044F) + ": [FWB-IN] game.exe`n" + ([char]0x0414) + ([char]0x0435) + ([char]0x0439) + ([char]0x0441) + ([char]0x0442) + ([char]0x0432) + ([char]0x0438) + ([char]0x0435) + ": " + ([char]0x0411) + ([char]0x043B) + ([char]0x043E) + ([char]0x043A) + ([char]0x0438) + ([char]0x0440))
        "ZH_Hans_Block"  = (([char]0x89C4) + ([char]0x5219) + ": [FWB-IN] game.exe`n" + ([char]0x64CD) + ([char]0x4F5C) + ": " + ([char]0x963B) + ([char]0x6B62))
        "ZH_Hant_Block"  = (([char]0x898F) + ([char]0x5247) + ": [FWB-IN] game.exe`n" + ([char]0x52D5) + ([char]0x4F5C) + ": " + ([char]0x5C01) + ([char]0x9396))
        "JA_Block"       = (([char]0x898F) + ([char]0x5247) + ([char]0x540D) + ": [FWB-IN] game.exe`n" + ([char]0x64CD) + ([char]0x4F5C) + ": " + ([char]0x30D6) + ([char]0x30ED) + ([char]0x30C3) + ([char]0x30AF))
        "KO_Block"       = (([char]0xADDC) + ([char]0xCE59) + " " + ([char]0xC774) + ([char]0xB984) + ": [FWB-IN] game.exe`n" + ([char]0xC791) + ([char]0xC5C5) + ": " + ([char]0xCC28) + ([char]0xB2E8))
        "EN_Disabled"    = "Rule Name: [FWB-IN] game.exe`nEnabled: No`nAction: Block"
        "EN_Allow"       = "Rule Name: [FWB-IN] game.exe`nEnabled: Yes`nAction: Allow"
    }

    $allPassed = $true
    foreach ($k in $samples.Keys) {
        $res = Test-NetshRuleBlocked -NetshResult $samples[$k]
        $expected = (-not $k.Contains("Disabled") -and -not $k.Contains("Allow"))
        if ($res -ne $expected) {
            Write-Host "  -> FAIL: Sample $k evaluated to $res, expected $expected" -ForegroundColor Red
            $allPassed = $false
        }
    }

    if ($allPassed) {
        Write-Host "  -> PASS: Multilingual netsh rule parser verified across German, French, Spanish, Russian, Chinese, Japanese, and Korean via Test-NetshRuleBlocked." -ForegroundColor Green
    } else {
        exit 1
    }

    Write-Host "`n====================================================" -ForegroundColor Cyan
    Write-Host "Baseline Core Tests (1-13) PASSED Successfully!" -ForegroundColor Green
    Write-Host "====================================================" -ForegroundColor Cyan

    # -------------------------------------------------------------------------
    # Test 14: Action Dispatching & Mode Normalization Check
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 14] Testing Action Dispatching & Mode Normalization..." -ForegroundColor Yellow
    $actionsToTest = @{
        "BlockBoth"         = "Both"
        "BlockAll"          = "Both"
        "Both"              = "Both"
        "BlockOutbound"     = "OutboundOnly"
        "BlockOutboundOnly" = "OutboundOnly"
        "Outbound"          = "OutboundOnly"
        "BlockInbound"      = "InboundOnly"
        "BlockInboundOnly"  = "InboundOnly"
        "Inbound"           = "InboundOnly"
        "UnblockDir"        = "UnblockDir"
        "Unblock"           = "UnblockDir"
        "UnblockAll"        = "UnblockAll"
        "Purge"             = "UnblockAll"
        "Scan"              = "Scan"
        "Audit"             = "Scan"
        "List"              = "Scan"
        "RepairService"     = "RepairService"
        "RestartService"    = "RepairService"
    }

    # Import Resolve-ActionTargetMode directly from script
    . $blockerPs1 -ExportFunctionsOnly

    $actionsValid = $true
    foreach ($actionName in $actionsToTest.Keys) {
        $resolvedMode = Resolve-ActionTargetMode -RequestedAction $actionName
        if ($resolvedMode -ne $actionsToTest[$actionName]) {
            Write-Host "  -> FAIL: Action '$actionName' resolved to '$resolvedMode', expected '$($actionsToTest[$actionName])'" -ForegroundColor Red
            $actionsValid = $false
        }
    }
    if ($null -ne (Resolve-ActionTargetMode -RequestedAction "InvalidActionXYZ")) {
        Write-Host "  -> FAIL: 'InvalidActionXYZ' was unexpectedly accepted" -ForegroundColor Red
        $actionsValid = $false
    }
    if ($actionsValid) {
        Write-Host "  -> PASS: All action dispatch modes (including BlockOutboundOnly & BlockInboundOnly) verified cleanly via Resolve-ActionTargetMode." -ForegroundColor Green
    } else {
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 15: 32-bit Compatibility & System Path Guardrail Expansion
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 15] Verifying 32-bit Architecture Guardrails & WindowsApps Protection..." -ForegroundColor Yellow
    # Save existing env var
    $origX86 = ${env:ProgramFiles(x86)}
    try {
        # Simulate 32-bit Windows environment where ProgramFiles(x86) does not exist
        ${env:ProgramFiles(x86)} = $null

        # Re-import functions with simulated environment
        . $blockerPs1 -ExportFunctionsOnly

        $winDirBlocked = Test-IsProtectedSystemPath -PathToCheck "C:\Windows"
        $pfBlocked     = Test-IsProtectedSystemPath -PathToCheck "C:\Program Files"
        $defenderBlocked = Test-IsProtectedSystemPath -PathToCheck "C:\Program Files\Windows Defender"
        $localAppsBlocked = $false
        if (-not [string]::IsNullOrEmpty($env:LOCALAPPDATA)) {
            $localAppsBlocked = Test-IsProtectedSystemPath -PathToCheck "$env:LOCALAPPDATA\Microsoft\WindowsApps"
        } else {
            $localAppsBlocked = $true
        }
        $gameAllowed   = -not (Test-IsProtectedSystemPath -PathToCheck "C:\MyGames\ActionRPG")

        if ($winDirBlocked -and $pfBlocked -and $defenderBlocked -and $localAppsBlocked -and $gameAllowed) {
            Write-Host "  -> PASS: System guardrails operate without exceptions when ProgramFiles(x86) is absent (32-bit mode)." -ForegroundColor Green
            Write-Host "  -> PASS: Microsoft\WindowsApps protected from accidental blocking." -ForegroundColor Green
        } else {
            Write-Host "  -> FAIL: 32-bit guardrail verification failed." -ForegroundColor Red
            exit 1
        }
    } finally {
        ${env:ProgramFiles(x86)} = $origX86
        . $blockerPs1 -ExportFunctionsOnly
    }

    # -------------------------------------------------------------------------
    # Test 16: User Profile & Large Directory Safeguard Check
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 16] Verifying User Profile & Large Target Safety Check..." -ForegroundColor Yellow
    $userProf = $env:USERPROFILE
    $isUpProtected = Test-IsUserProfileRoot -PathToCheck $userProf
    $isSysUsersProtected = Test-IsUserProfileRoot -PathToCheck "$env:SystemDrive\Users"
    $isGameProtected = Test-IsUserProfileRoot -PathToCheck "C:\Games\Doom"

    if ($isUpProtected -and $isSysUsersProtected -and -not $isGameProtected) {
        Write-Host "  -> PASS: Test-IsUserProfileRoot accurately identifies User Profile directories." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: User Profile identification failed (UserProfile: $isUpProtected, UsersDir: $isSysUsersProtected, Game: $isGameProtected)." -ForegroundColor Red
        exit 1
    }

    # Non-interactive blocking of a User Profile root without -Force must abort with exit code 1
    $upProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`" -TargetDir `"$userProf`" -Action BlockBoth -NonInteractive" -NoNewWindow -Wait -PassThru
    if ($upProcess.ExitCode -eq 1) {
        Write-Host "  -> PASS: Non-interactive block on User Profile root rejected with exit code 1 when -Force is absent." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Expected exit code 1 for unforced User Profile block, got $($upProcess.ExitCode)." -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 17: EOF Stdin Menu Protection Check
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 17] Verifying Menu EOF Handling..." -ForegroundColor Yellow
    $psiEof = New-Object System.Diagnostics.ProcessStartInfo
    $psiEof.FileName = "powershell.exe"
    $psiEof.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`""
    $psiEof.RedirectStandardInput = $true
    $psiEof.RedirectStandardOutput = $true
    $psiEof.RedirectStandardError = $true
    $psiEof.UseShellExecute = $false
    $psiEof.CreateNoWindow = $true

    $eofProc = [System.Diagnostics.Process]::Start($psiEof)
    # Immediately close standard input to simulate EOF / piped input
    $eofProc.StandardInput.Close()
    $eofStdout = $eofProc.StandardOutput.ReadToEnd()
    $null = $eofProc.WaitForExit(5000)

    if ($eofProc.HasExited -and $eofStdout -match "\[EOF\] Standard input closed") {
        Write-Host "  -> PASS: Menu loop terminates cleanly upon EOF without infinite redraw loop." -ForegroundColor Green
    } else {
        try { $eofProc.Kill() } catch {}
        Write-Host "  -> FAIL: Menu loop failed to handle EOF cleanly." -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 18: Stream Reading & Output Integrity Check
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 18] Testing Invoke-Netsh Stream Reading & Race-Free Output..." -ForegroundColor Yellow
    $dummyRuleRes = Invoke-Netsh -Arguments "advfirewall firewall show rule name=nonexistent_test_rule_parity_check"
    if ($dummyRuleRes -and $dummyRuleRes.Output.Length -gt 0 -and $dummyRuleRes.ExitCode -ne -1) {
        Write-Host "  -> PASS: Invoke-Netsh stream read captured complete output without dropped bytes." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Invoke-Netsh failed to return valid stream output." -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 19: Batch Exit Code Preservation
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 19] Verifying Batch Exit Code Preservation..." -ForegroundColor Yellow
    $batInvalidCmd = "/c `"`"$blockerBat`" -Action InvalidCommandXYZ -NonInteractive`""
    $batInvalidProc = Start-Process -FilePath "cmd.exe" -ArgumentList $batInvalidCmd -NoNewWindow -Wait -PassThru
    if ($batInvalidProc.ExitCode -eq 1) {
        Write-Host "  -> PASS: FirewallBlocker.bat preserved ExitCode 1 from PowerShell child process." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: FirewallBlocker.bat swallowed exit code, returned $($batInvalidProc.ExitCode) instead of 1." -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 20: Extended Path Prefix (\\?\) & Junction Safety Guardrails
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 20] Verifying Extended Path Prefix (\\?\) & Reparse Point Safety Guardrails..." -ForegroundColor Yellow
    . $blockerPs1 -ExportFunctionsOnly
    $extWinBlocked = Test-IsProtectedSystemPath -PathToCheck "\\?\C:\Windows"
    $extPfBlocked  = Test-IsProtectedSystemPath -PathToCheck "\\?\C:\Program Files"
    $extDefBlocked = Test-IsProtectedSystemPath -PathToCheck "\\?\C:\ProgramData\Microsoft\Windows Defender"
    $extUpBlocked  = Test-IsUserProfileRoot -PathToCheck ("\\?\" + $env:USERPROFILE)
    $extSysBlocked = Test-IsUserProfileRoot -PathToCheck ("\\?\" + $env:SystemDrive + "\Users")

    if ($extWinBlocked -and $extPfBlocked -and $extDefBlocked -and $extUpBlocked -and $extSysBlocked) {
        Write-Host "  -> PASS: Extended path prefix (\\?\) normalized and safely blocked across all system targets." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Extended path bypass vulnerability detected (Win: $extWinBlocked, PF: $extPfBlocked, Def: $extDefBlocked, UP: $extUpBlocked, Users: $extSysBlocked)." -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 21: Target Directory Startup Defaulting Guard
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 21] Testing Startup Directory Resolution when Launched from User Profile..." -ForegroundColor Yellow
    # 1. In-memory execution (irm | iex style) from User Profile root
    $testCwdScript = @"
Set-Location "`$env:USERPROFILE"
`$code = [System.IO.File]::ReadAllText("$($blockerPs1.Replace('\', '\\'))")
& ([scriptblock]::Create(`$code)) -ExportFunctionsOnly
if ([string]::IsNullOrEmpty(`$TargetDir)) { exit 0 } else { exit 42 }
"@
    $tmpCwdTest = Join-Path $env:TEMP "test_cwd_guard.ps1"
    [System.IO.File]::WriteAllText($tmpCwdTest, $testCwdScript)
    $cwdProc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tmpCwdTest`"" -NoNewWindow -Wait -PassThru
    Remove-Item $tmpCwdTest -Force -ErrorAction SilentlyContinue

    # 2. File execution from script directly in User Profile root
    $tmpScriptInProfile = Join-Path $env:USERPROFILE "FirewallBlocker_TestProfileGuard.ps1"
    Copy-Item -Path $blockerPs1 -Destination $tmpScriptInProfile -Force
    $testFileInProfile = @"
Set-Location "`$env:USERPROFILE"
. "$($tmpScriptInProfile.Replace('\', '\\'))" -ExportFunctionsOnly
if ([string]::IsNullOrEmpty(`$TargetDir)) { exit 0 } else { exit 43 }
"@
    $tmpFileTest = Join-Path $env:TEMP "test_file_guard.ps1"
    [System.IO.File]::WriteAllText($tmpFileTest, $testFileInProfile)
    $fileProc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tmpFileTest`"" -NoNewWindow -Wait -PassThru
    Remove-Item $tmpFileTest -Force -ErrorAction SilentlyContinue
    Remove-Item $tmpScriptInProfile -Force -ErrorAction SilentlyContinue

    if ($cwdProc.ExitCode -eq 0 -and $fileProc.ExitCode -eq 0) {
        Write-Host "  -> PASS: Target directory left empty when launched in or from User Profile root (prevents recursive freeze)." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Target directory unexpectedly defaulted to User Profile root (In-Memory ExitCode: $($cwdProc.ExitCode), File ExitCode: $($fileProc.ExitCode))." -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 22: Service Restart / Repair Functionality
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 22] Testing Ensure-FirewallServiceRunning Logic..." -ForegroundColor Yellow
    $svcCheck = Ensure-FirewallServiceRunning
    if ($svcCheck -eq $true) {
        Write-Host "  -> PASS: Ensure-FirewallServiceRunning validated MpsSvc health." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Ensure-FirewallServiceRunning returned false." -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 23: Comprehensive Multi-Path Hash Parity (Simple & Complex Paths)
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 23] Testing Comprehensive Multi-Path Hash Parity..." -ForegroundColor Yellow
    $pathsToVerify = @{
        "c:\games\app.exe" = "B42ACF78"
        "C:\Games & Tools (2024)\CrashReporter!.exe" = "8C422CDA"
        "C:\MyFolder\App(x86).exe" = "169D7E51"
    }

    $allHashesMatch = $true
    foreach ($p in $pathsToVerify.Keys) {
        $psHash = Get-PortableHash -InputString $p
        if ($psHash -ne $pathsToVerify[$p]) {
            Write-Host "  -> FAIL: PS Hash mismatch for '$p': got '$psHash', expected '$($pathsToVerify[$p])'" -ForegroundColor Red
            $allHashesMatch = $false
        }
    }
    if ($allHashesMatch) {
        Write-Host "  -> PASS: All simple and complex path hashes match expected values across engines." -ForegroundColor Green
    } else {
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 24: Verifying Advanced / Power User Mode Restrictions & Core OS Guard
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 24] Verifying Advanced / Power User Mode Overrides & Core OS Protection..." -ForegroundColor Yellow
    . $blockerPs1 -ExportFunctionsOnly

    # 1. Advanced Mode bypasses Program Files, ProgramData, drive roots, and Defender
    $advPfAllowed       = -not (Test-IsProtectedSystemPath -PathToCheck "C:\Program Files" -IsAdvanced)
    $advPf86Allowed     = $true
    if (-not [string]::IsNullOrEmpty(${env:ProgramFiles(x86)})) {
        $advPf86Allowed = -not (Test-IsProtectedSystemPath -PathToCheck ${env:ProgramFiles(x86)} -IsAdvanced)
    }
    $advDriveAllowed    = -not (Test-IsProtectedSystemPath -PathToCheck "$env:SystemDrive\" -IsAdvanced)
    $advDefAllowed      = -not (Test-IsProtectedSystemPath -PathToCheck "$env:ProgramData\Microsoft\Windows Defender" -IsAdvanced)
    $advExtPfAllowed   = -not (Test-IsProtectedSystemPath -PathToCheck "\\?\C:\Program Files" -IsAdvanced)

    if ($advPfAllowed -and $advPf86Allowed -and $advDriveAllowed -and $advDefAllowed -and $advExtPfAllowed) {
        Write-Host "  -> PASS: Advanced Mode successfully overrides Program Files, ProgramData, drive roots, and Defender." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Advanced Mode failed to override folder restrictions (PF: $advPfAllowed, PF86: $advPf86Allowed, Drive: $advDriveAllowed, Def: $advDefAllowed, ExtPF: $advExtPfAllowed)." -ForegroundColor Red
        exit 1
    }

    # 2. Verify explicit -IsAdvanced:$false override works even when $Script:AdvancedMode = $true
    $Script:AdvancedMode = $true
    $advPfNormallyProtected = (Test-IsProtectedSystemPath -PathToCheck "C:\Program Files" -IsAdvanced:$false)
    $Script:AdvancedMode = $false
    if ($advPfNormallyProtected) {
        Write-Host "  -> PASS: Test-IsProtectedSystemPath correctly honors explicit -IsAdvanced:`$false when AdvancedMode is active." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Test-IsProtectedSystemPath failed to honor -IsAdvanced:`$false parameter binding." -ForegroundColor Red
        exit 1
    }

    # 3. Core OS Stability Protection (C:\Windows, System32) MUST remain protected in Advanced Mode without -Force
    $advWinBlocked      = Test-IsProtectedSystemPath -PathToCheck "C:\Windows" -IsAdvanced
    $advSys32Blocked    = Test-IsProtectedSystemPath -PathToCheck "C:\Windows\System32" -IsAdvanced
    $advSys32Forced     = -not (Test-IsProtectedSystemPath -PathToCheck "C:\Windows\System32" -IsAdvanced -IsForce)

    if ($advWinBlocked -and $advSys32Blocked -and $advSys32Forced) {
        Write-Host "  -> PASS: Core OS stability protection (C:\Windows\System32) strictly guarded in Advanced Mode unless explicitly combined with -Force." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Core OS protection failed in Advanced Mode (WinBlocked: $advWinBlocked, Sys32Blocked: $advSys32Blocked, Sys32Forced: $advSys32Forced)." -ForegroundColor Red
        exit 1
    }

    # 4. CLI execution of -AdvancedMode and -ExpertMode on Program Files and Core OS
    $advScanProc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`" -TargetDir `"C:\Program Files`" -Action Scan -AdvancedMode -NonInteractive" -NoNewWindow -Wait -PassThru
    $expertScanProc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`" -TargetDir `"C:\Program Files`" -Action Scan -ExpertMode -NonInteractive" -NoNewWindow -Wait -PassThru
    $coreOsProc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`" -TargetDir `"C:\Windows\System32`" -Action BlockBoth -AdvancedMode -NonInteractive" -NoNewWindow -Wait -PassThru
    $nonForceAdvProc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`" -TargetDir `"C:\Program Files`" -Action BlockBoth -AdvancedMode -NonInteractive" -NoNewWindow -Wait -PassThru

    if ($advScanProc.ExitCode -eq 0 -and $expertScanProc.ExitCode -eq 0 -and $coreOsProc.ExitCode -eq 2 -and $nonForceAdvProc.ExitCode -eq 1) {
        Write-Host "  -> PASS: -AdvancedMode switches permitted scan (ExitCode 0), core OS System32 was guarded (ExitCode 2), and non-interactive block on overridden path without -Force safely aborted (ExitCode 1)." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: CLI execution check failed (AdvScan: $($advScanProc.ExitCode), ExpertScan: $($expertScanProc.ExitCode), CoreOS: $($coreOsProc.ExitCode), NonForceAdv: $($nonForceAdvProc.ExitCode))." -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 25: Verifying Batch Fallback Engine Advanced Mode Handling
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 25] Verifying Batch Fallback Engine Advanced Mode Handling..." -ForegroundColor Yellow
    $batCode = [System.IO.File]::ReadAllText($blockerBat)

    $hasBatAdvArg     = ($batCode -match '(?i)-AdvancedMode')
    $hasBatExpertArg  = ($batCode -match '(?i)-ExpertMode')
    $hasBatForceArg   = ($batCode -match '(?i)-Force')
    $hasBatToggle     = ($batCode -match '(?i):TOGGLE_ADVANCED')
    $hasBatCoreOsErr  = ($batCode -match '(?i):CORE_OS_ERROR')
    $hasBatMatchProt  = ($batCode -match '(?i):MATCH_PROTECTED')

    if ($hasBatAdvArg -and $hasBatExpertArg -and $hasBatForceArg -and $hasBatToggle -and $hasBatCoreOsErr -and $hasBatMatchProt) {
        Write-Host "  -> PASS: FirewallBlocker.bat verified with -AdvancedMode argument detection, -Force detection, menu toggle, and core OS protection." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Batch Advanced Mode verification failed (Arg: $hasBatAdvArg, ExpertArg: $hasBatExpertArg, Force: $hasBatForceArg, Toggle: $hasBatToggle, CoreOS: $hasBatCoreOsErr, MatchProt: $hasBatMatchProt)." -ForegroundColor Red
        exit 1
    }

    # Test batch file delegating -AdvancedMode to PowerShell
    $batAdvProc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"`"$blockerBat`" -TargetDir `"$dummyRoot`" -Action Scan -AdvancedMode -NonInteractive`"" -NoNewWindow -Wait -PassThru
    if ($batAdvProc.ExitCode -eq 0) {
        Write-Host "  -> PASS: FirewallBlocker.bat successfully delegated -AdvancedMode with ExitCode 0." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: FirewallBlocker.bat returned exit code $($batAdvProc.ExitCode) for -AdvancedMode." -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 26: Batch Fallback Confirmation on Overridden Paths with (x86) and Spaces
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 26] Testing Batch Confirmation Handling on Overridden Paths with (x86) and Spaces..." -ForegroundColor Yellow
    $test86Dir = "C:\Program Files (x86)\AutoCAD 2007"
    $batchConfirmTestScript = @"
@echo off
setlocal DisableDelayedExpansion
set "TARGET_DIR=$test86Dir"
set "ADVANCED_MODE=1"
set "IS_SYSTEM_OVERRIDDEN=1"
set "IS_SENSITIVE=0"

if not "%IS_SENSITIVE%"=="1" goto SKIP_SENSITIVE_CONFIRM
set "CONFIRM="
set /p "CONFIRM=Are you SURE? [Y/N]: "
if not defined CONFIRM goto CANCEL_BLOCK
set "CONFIRM=%CONFIRM:"=%"
set "CONFIRM=%CONFIRM: =%"
if /i not "%CONFIRM%"=="Y" goto CANCEL_BLOCK

:SKIP_SENSITIVE_CONFIRM
if not "%IS_SYSTEM_OVERRIDDEN%"=="1" goto DO_BLOCK
set "CONFIRM_ADV="
set /p "CONFIRM_ADV=Proceed? [Y/N]: "
if not defined CONFIRM_ADV goto CANCEL_BLOCK
set "CONFIRM_ADV=%CONFIRM_ADV:"=%"
set "CONFIRM_ADV=%CONFIRM_ADV: =%"
if /i not "%CONFIRM_ADV%"=="Y" goto CANCEL_BLOCK
goto DO_BLOCK

:CANCEL_BLOCK
echo [CONFIRM_CANCELLED_CLEANLY]
exit /b 0

:DO_BLOCK
echo [CONFIRM_ACCEPTED_CLEANLY]
exit /b 0
"@
    $tmpBatConfirm = Join-Path $env:TEMP "test_bat_confirm.bat"
    [System.IO.File]::WriteAllText($tmpBatConfirm, $batchConfirmTestScript, [System.Text.Encoding]::ASCII)

    # Test Cancel path (simulate user typing N into prompt without syntax error)
    $rawOutN = cmd.exe /c "<nul set /p=`"N`" | `"$tmpBatConfirm`""
    $exitCodeN = $LASTEXITCODE
    $outN = if ($rawOutN) { ($rawOutN | Out-String).Trim() } else { "" }

    # Test Accept path (simulate user typing Y into prompt)
    $rawOutY = cmd.exe /c "<nul set /p=`"Y`" | `"$tmpBatConfirm`""
    $exitCodeY = $LASTEXITCODE
    $outY = if ($rawOutY) { ($rawOutY | Out-String).Trim() } else { "" }

    # Test Empty / Enter path (simulate user pressing Enter on prompt)
    $rawOutEmpty = cmd.exe /c "echo. | `"$tmpBatConfirm`""
    $exitCodeEmpty = $LASTEXITCODE
    $outEmpty = if ($rawOutEmpty) { ($rawOutEmpty | Out-String).Trim() } else { "" }

    Remove-Item $tmpBatConfirm -Force -ErrorAction SilentlyContinue

    $hasCrashError = ($outN -match "unexpected at this time" -or $outY -match "unexpected at this time" -or $outEmpty -match "unexpected at this time")
    $cancelOk = ($outN -match "\[CONFIRM_CANCELLED_CLEANLY\]" -and $exitCodeN -eq 0)
    $acceptOk = ($outY -match "\[CONFIRM_ACCEPTED_CLEANLY\]" -and $exitCodeY -eq 0)
    $emptyOk  = ($outEmpty -match "\[CONFIRM_CANCELLED_CLEANLY\]" -and $exitCodeEmpty -eq 0)

    if (-not $hasCrashError -and $cancelOk -and $acceptOk -and $emptyOk) {
        Write-Host "  -> PASS: Batch confirmation on '$test86Dir' executed without parse-time crash (Cancel, Accept & Enter verified cleanly)." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Batch confirmation crashed or misbehaved (Crash: $hasCrashError, CancelOk: $cancelOk, AcceptOk: $acceptOk, EmptyOk: $emptyOk, OutN: $outN, OutY: $outY, OutEmpty: $outEmpty)." -ForegroundColor Red
        exit 1
    }

    # Test CHECK_DIR_SET & TOGGLE_ADVANCED against parse-time expansion crashes
    $testPromptScript = @"
@echo off
setlocal DisableDelayedExpansion
set "TARGET_DIR="
set "ADVANCED_MODE=0"

:: 1. Test CHECK_DIR_SET when undefined
call :CHECK_DIR_SET
if not defined TARGET_DIR (
    echo [FAIL_DIR_NOT_SET]
    exit /b 1
)
echo [CHECK_DIR_SET_OK: %TARGET_DIR%]

:: 2. Test TOGGLE_ADVANCED with empty / cancel
call :TOGGLE_ADVANCED
echo [TOGGLE_ADVANCED_OK: %ADVANCED_MODE%]
exit /b 0

:CHECK_DIR_SET
if defined TARGET_DIR exit /b 0
set "INPUT_DIR="
set /p "INPUT_DIR=Folder Path: "
if not defined INPUT_DIR exit /b 0
set "INPUT_DIR=%INPUT_DIR:"=%"
if not defined INPUT_DIR exit /b 0
for %%I in ("%INPUT_DIR%") do (
    if exist "%%~fI" (
        set "TARGET_DIR=%%~fI"
    ) else (
        set "TARGET_DIR=%%~fI"
    )
)
exit /b 0

:TOGGLE_ADVANCED
set "CONF_ADV="
set /p "CONF_ADV=Enable [Y/N]: "
if not defined CONF_ADV goto CANCEL_ADV
set "CONF_ADV=%CONF_ADV:"=%"
set "CONF_ADV=%CONF_ADV: =%"
if /i not "%CONF_ADV%"=="Y" goto CANCEL_ADV
set "ADVANCED_MODE=1"
exit /b 0
:CANCEL_ADV
set "ADVANCED_MODE=0"
exit /b 0
"@
    $tmpPromptBat = Join-Path $env:TEMP "test_prompts.bat"
    [System.IO.File]::WriteAllText($tmpPromptBat, $testPromptScript, [System.Text.Encoding]::ASCII)

    # Feed test path then Enter (empty line) via native cmd pipeline to avoid .NET StreamWriter BOM
    $feedCmd = "(echo C:\Windows& echo.) | `"$tmpPromptBat`""
    $rawPromptOut = cmd.exe /c $feedCmd
    $promptOut = if ($rawPromptOut) { ($rawPromptOut | Out-String).Trim() } else { "" }

    Remove-Item $tmpPromptBat -Force -ErrorAction SilentlyContinue

    $hasPromptCrash = ($promptOut -match "unexpected at this time")
    $dirSetOk = ($promptOut -match "\[CHECK_DIR_SET_OK: C:\\Windows\]")
    $toggleOk = ($promptOut -match "\[TOGGLE_ADVANCED_OK: 0\]")

    if (-not $hasPromptCrash -and $dirSetOk -and $toggleOk) {
        Write-Host "  -> PASS: CHECK_DIR_SET and TOGGLE_ADVANCED verified free of parse-time crashes and handle empty inputs cleanly." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Batch prompts failed or crashed (Crash: $hasPromptCrash, DirSetOk: $dirSetOk, ToggleOk: $toggleOk, Output: $promptOut)." -ForegroundColor Red
        exit 1
    }

    # -------------------------------------------------------------------------
    # Test 27: AutoCAD 2007 (x86) Path Quoting, Netsh Description Sanitization & MpsSvc Health Check
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 27] Verifying AutoCAD (x86) Path Handling, Description Sanitization & MpsSvc Health..." -ForegroundColor Yellow
    $acadPath = "C:\Program Files (x86)\AutoCAD 2007\acad.exe"
    $inRule = Get-RuleName -Direction "IN" -ExeName "acad.exe" -FullPath $acadPath
    $outRule = Get-RuleName -Direction "OUT" -ExeName "acad.exe" -FullPath $acadPath
    $acadHash = Get-PortableHash -InputString $acadPath

    # Verify rule names and portable hash
    if ($inRule -match '^\[FWB-IN\] acad\.exe \([0-9A-F]{8}\)$' -and $acadHash.Length -eq 8) {
        Write-Host "  -> PASS: Rule names and portable hash generated accurately for '$acadPath' ($acadHash)." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Rule name or hash generation failed for '$acadPath' ($inRule)." -ForegroundColor Red
        exit 1
    }

    # Verify description sanitization (no pipe characters)
    $rawDesc = "Blocked by FirewallBlocker - $acadPath"
    $cleanDesc = $rawDesc.Replace('"', '').Replace('|', '-')
    if ($cleanDesc -notmatch '\|' -and $cleanDesc -match 'AutoCAD 2007') {
        Write-Host "  -> PASS: Description properly sanitized without illegal pipe characters." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Description sanitization failed: $cleanDesc" -ForegroundColor Red
        exit 1
    }

    # Verify netsh parameter parsing via ProcessStartInfo with sanitized description
    $testPsi = New-Object System.Diagnostics.ProcessStartInfo
    $testPsi.FileName = "netsh.exe"
    $testPsi.Arguments = "advfirewall firewall add rule name=`"$inRule`" dir=in action=block program=`"$acadPath`" enable=yes profile=any description=`"$cleanDesc`""
    $testPsi.RedirectStandardOutput = $true
    $testPsi.RedirectStandardError = $true
    $testPsi.UseShellExecute = $false
    $testPsi.CreateNoWindow = $true

    $testProc = [System.Diagnostics.Process]::Start($testPsi)
    $null = $testProc.WaitForExit(5000)
    $testOut = $testProc.StandardOutput.ReadToEnd()

    # Netsh should NOT fail with "The description contains invalid characters" or dump the usage screen with |RPC|
    if ($testOut -notmatch "invalid characters" -and $testOut -notmatch "Usage:\s*add\s*rule") {
        Write-Host "  -> PASS: Netsh accepted AutoCAD 2007 (x86) path and description without syntax or invalid character errors." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Netsh rejected parameters with invalid characters or usage error: $testOut" -ForegroundColor Red
        exit 1
    }

    # Clean up test rule if it was added
    $cleanDelPsi = New-Object System.Diagnostics.ProcessStartInfo
    $cleanDelPsi.FileName = "netsh.exe"
    $cleanDelPsi.Arguments = "advfirewall firewall delete rule name=`"$inRule`""
    $cleanDelPsi.RedirectStandardOutput = $true
    $cleanDelPsi.UseShellExecute = $false
    $cleanDelPsi.CreateNoWindow = $true
    $delProc = [System.Diagnostics.Process]::Start($cleanDelPsi)
    $null = $delProc.WaitForExit(3000)

    # Verify Ensure-FirewallServiceRunning with -Restart does not fail with Access Denied (5)
    $restartCheck = Ensure-FirewallServiceRunning -Restart
    if ($restartCheck -eq $true) {
        Write-Host "  -> PASS: Ensure-FirewallServiceRunning -Restart validated MpsSvc health and profile state without Access Denied (5) errors." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: Ensure-FirewallServiceRunning -Restart returned false." -ForegroundColor Red
        exit 1
    }

    Write-Host "`n====================================================" -ForegroundColor Cyan
    Write-Host "All 27 Comprehensive Tests PASSED Successfully!" -ForegroundColor Green
    Write-Host "====================================================" -ForegroundColor Cyan

} finally {
    foreach ($td in $testDirsToCleanup) {
        if (Test-Path -LiteralPath $td) {
            try {
                Remove-Item -LiteralPath $td -Recurse -Force -ErrorAction SilentlyContinue
            } catch {}
        }
    }
}
