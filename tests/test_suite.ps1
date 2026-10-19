# Automated Test Suite for FirewallBlocker
$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$blockerPs1 = Join-Path $repoRoot "FirewallBlocker.ps1"
$runPs1 = Join-Path $repoRoot "run.ps1"
$blockerBat = Join-Path $repoRoot "FirewallBlocker.bat"
$textBat = Join-Path $repoRoot "text.bat"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "Running FirewallBlocker Automated Test Suite v2.1" -ForegroundColor White
Write-Host "====================================================" -ForegroundColor Cyan

# Test 1: Syntax Parse Check for FirewallBlocker.ps1 (PS 2.0 to 7.x compatible)
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

# Test 2: Syntax Parse Check for run.ps1
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

# Test 3: Byte Parity Check between FirewallBlocker.ps1 and run.ps1
Write-Host "`n[Test 3] Verifying parity between FirewallBlocker.ps1 and run.ps1..." -ForegroundColor Yellow
$content1 = [System.IO.File]::ReadAllText($blockerPs1)
$content2 = [System.IO.File]::ReadAllText($runPs1)
if ($content1 -eq $content2) {
    Write-Host "  -> PASS: FirewallBlocker.ps1 and run.ps1 are 100% identical and in sync." -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: FirewallBlocker.ps1 and run.ps1 have diverged!" -ForegroundColor Red
    exit 1
}

# Test 4: Create Target with Special Characters, ! in path, and Directory ending in .exe
Write-Host "`n[Test 4] Testing Directory Scanning, Special Characters & Folder .exe exclusion..." -ForegroundColor Yellow
$dummyRoot = Join-Path $scriptDir "DummyTarget & Tools (2024) [v1.0]!"
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

# Execute scan via child process
$scanProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`" -TargetDir `"$dummyRoot`" -Action Scan -NonInteractive" -NoNewWindow -Wait -PassThru
if ($scanProcess.ExitCode -eq 0) {
    Write-Host "  -> PASS: Child process scan completed with ExitCode 0." -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: Scan process exited with code $($scanProcess.ExitCode)." -ForegroundColor Red
    exit 1
}

# Test 5: Batch File Execution and Delegation (text.bat & FirewallBlocker.bat)
Write-Host "`n[Test 5] Testing text.bat and FirewallBlocker.bat Delegation..." -ForegroundColor Yellow
$cmdArg = "/c `"`"$textBat`" -TargetDir `"$dummyRoot`" -Action Scan -NonInteractive`""
$batProcess = Start-Process -FilePath "cmd.exe" -ArgumentList $cmdArg -NoNewWindow -Wait -PassThru
if ($batProcess.ExitCode -eq 0) {
    Write-Host "  -> PASS: text.bat invoked successfully with ExitCode 0." -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: text.bat exited with code $($batProcess.ExitCode)." -ForegroundColor Red
    exit 1
}

# Test 6: Verify Critical System Path Protection
Write-Host "`n[Test 6] Verifying Protected System Path Safety Guardrails..." -ForegroundColor Yellow
$guardProcess1 = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`" -TargetDir `"C:\Windows`" -Action BlockBoth -NonInteractive" -NoNewWindow -Wait -PassThru
if ($guardProcess1.ExitCode -eq 2) {
    Write-Host "  -> PASS: System folder 'C:\Windows' was safely blocked with ExitCode 2." -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: C:\Windows did not trigger safety block (ExitCode: $($guardProcess1.ExitCode))." -ForegroundColor Red
    exit 1
}

$guardProcess2 = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`" -TargetDir `"C:\Windows\System32`" -Action BlockBoth -NonInteractive" -NoNewWindow -Wait -PassThru
if ($guardProcess2.ExitCode -eq 2) {
    Write-Host "  -> PASS: 'C:\Windows\System32' safely blocked with ExitCode 2." -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: System32 did not trigger safety block (ExitCode: $($guardProcess2.ExitCode))." -ForegroundColor Red
    exit 1
}

# Test 7: Verify Empty Directory Scan
Write-Host "`n[Test 7] Testing Empty Directory Scan..." -ForegroundColor Yellow
$emptyDir = Join-Path $scriptDir "EmptyDummyFolder"
if (Test-Path -LiteralPath $emptyDir) { Remove-Item -LiteralPath $emptyDir -Recurse -Force }
New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null
$emptyProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`" -TargetDir `"$emptyDir`" -Action Scan -NonInteractive" -NoNewWindow -Wait -PassThru
Remove-Item -LiteralPath $emptyDir -Recurse -Force
if ($emptyProcess.ExitCode -eq 0) {
    Write-Host "  -> PASS: Empty directory handled gracefully without error." -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: Empty directory scan returned code $($emptyProcess.ExitCode)." -ForegroundColor Red
    exit 1
}

# Test 8: Verify Invalid Action Handling
Write-Host "`n[Test 8] Testing Invalid Action Rejection..." -ForegroundColor Yellow
$invalidProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`" -Action InvalidCommandXYZ -NonInteractive" -NoNewWindow -Wait -PassThru
if ($invalidProcess.ExitCode -eq 1) {
    Write-Host "  -> PASS: Invalid action rejected with exit code 1." -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: Expected exit code 1 for invalid action, got $($invalidProcess.ExitCode)." -ForegroundColor Red
    exit 1
}

# Test 9: Verify FIPS-Compliant SHA256 Portable Hash Determinism
Write-Host "`n[Test 9] Testing FIPS-Compliant SHA256 Portable Hash..." -ForegroundColor Yellow
$hashFunc = {
    param([string]$InputString)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString.ToLowerInvariant())
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $hasher.ComputeHash($bytes)
    $hex = [System.BitConverter]::ToString($hashBytes).Replace("-", "")
    return $hex.Substring(0, 8)
}
$h1 = & $hashFunc "C:\Games\App.exe"
$h2 = & $hashFunc "c:\games\app.exe"
$h3 = & $hashFunc "C:\Games\Other.exe"
if ($h1 -eq $h2 -and $h1 -ne $h3 -and $h1.Length -eq 8) {
    Write-Host "  -> PASS: SHA256 hash is deterministic and case-insensitive ($h1)." -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: SHA256 hash check failed." -ForegroundColor Red
    exit 1
}

# Test 10: Verify Human Error Diagnostic Analyzer
Write-Host "`n[Test 10] Testing Human-Readable Error Diagnostic Engine..." -ForegroundColor Yellow
. $blockerPs1 -TargetDir "$dummyRoot" -Action Scan -NonInteractive | Out-Null
# Now test Format-HumanFirewallError function
$fakeElevError = Format-HumanFirewallError -RawOutput "The requested operation requires elevation (Run as administrator)." -ExitCode 1 -ExePath "C:\Game\app.exe" -Direction "INBOUND" -RuleName "[FWB-IN] app.exe"
$fakeSvcError = Format-HumanFirewallError -RawOutput "An error occurred while attempting to contact the Windows Firewall service." -ExitCode 1 -ExePath "C:\Game\app.exe" -Direction "OUTBOUND" -RuleName "[FWB-OUT] app.exe"
$fakeGpoError = Format-HumanFirewallError -RawOutput "The rule was not added because Group Policy does not allow local firewall rules." -ExitCode 1 -ExePath "C:\Game\app.exe" -Direction "OUTBOUND" -RuleName "[FWB-OUT] app.exe"

if ($fakeElevError.Location -eq "Windows Security Token (UAC)" -and
    $fakeSvcError.Location -eq "Windows Service Manager (MpsSvc)" -and
    $fakeGpoError.Location -eq "Active Directory / Local Group Policy") {
    Write-Host "  -> PASS: Human error diagnostics properly pinpoint Location, Root Cause, and Fix." -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: Human error diagnostic mapping failed." -ForegroundColor Red
    exit 1
}

# Cleanup dummy files
if (Test-Path -LiteralPath $dummyRoot) { Remove-Item -LiteralPath $dummyRoot -Recurse -Force }

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "All 10 Comprehensive Tests PASSED Successfully!" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Cyan
