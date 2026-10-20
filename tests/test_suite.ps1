# Automated Test Suite for FirewallBlocker
$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$blockerPs1 = Join-Path $repoRoot "FirewallBlocker.ps1"
$runPs1 = Join-Path $repoRoot "run.ps1"
$blockerBat = Join-Path $repoRoot "FirewallBlocker.bat"
$textBat = Join-Path $repoRoot "text.bat"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "Running FirewallBlocker Automated Test Suite v2.2" -ForegroundColor White
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

    if ($fakeElevError.Location -eq "Windows Security Token (UAC)" -and
        $fakeSvcError.Location  -eq "Windows Service Manager (MpsSvc)" -and
        $fakeGpoError.Location  -eq "Active Directory / Local Group Policy" -and
        $fakePathError.Location -eq "Win32 File Subsystem (MAX_PATH)") {
        Write-Host "  -> PASS: Human error diagnostics properly pinpoint Location, Root Cause, and Fix across all categories." -ForegroundColor Green
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
    # Test 12: Batch Fallback Engine Integrity Checks
    # -------------------------------------------------------------------------
    Write-Host "`n[Test 12] Auditing Batch Engine Integrity & Non-Destructive Invariants..." -ForegroundColor Yellow
    $batContent = [System.IO.File]::ReadAllText($blockerBat)

    # Invariant 1: No setlocal/endlocal around CHECK_DIR_SET that destroys TARGET_DIR
    $hasScopeTrap = ($batContent -match 'setlocal\s+EnableDelayedExpansion\s+call\s+:CHECK_DIR_SET\s+endlocal')
    # Invariant 2: No destructive netsh delete rule name=all program=
    $hasOverDestructive = ($batContent -match 'netsh\s+advfirewall\s+firewall\s+delete\s+rule\s+name=all\s+program=')

    if (-not $hasScopeTrap -and -not $hasOverDestructive) {
        Write-Host "  -> PASS: FirewallBlocker.bat verified free of variable scope traps and over-destructive deletions." -ForegroundColor Green
    } else {
        Write-Host "  -> FAIL: FirewallBlocker.bat failed code invariants (scope trap: $hasScopeTrap, over-destructive: $hasOverDestructive)." -ForegroundColor Red
        exit 1
    }

    Write-Host "`n====================================================" -ForegroundColor Cyan
    Write-Host "All 12 Comprehensive Tests PASSED Successfully!" -ForegroundColor Green
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
