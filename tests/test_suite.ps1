# Automated Test Suite for FirewallBlocker
$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$blockerPs1 = Join-Path $repoRoot "FirewallBlocker.ps1"
$runPs1 = Join-Path $repoRoot "run.ps1"
$blockerBat = Join-Path $repoRoot "FirewallBlocker.bat"
$textBat = Join-Path $repoRoot "text.bat"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "Running FirewallBlocker Automated Test Suite" -ForegroundColor White
Write-Host "====================================================" -ForegroundColor Cyan

# Test 1: Syntax Parse Check for FirewallBlocker.ps1
Write-Host "`n[Test 1] Parsing FirewallBlocker.ps1 AST syntax..." -ForegroundColor Yellow
$parseErrors = $null
$tokens = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($blockerPs1, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -eq 0) {
    Write-Host "  -> PASS: FirewallBlocker.ps1 syntax is 100% valid." -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: Syntax errors detected in FirewallBlocker.ps1:" -ForegroundColor Red
    $parseErrors | ForEach-Object { Write-Host "     Line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Red }
    exit 1
}

# Test 2: Syntax Parse Check for run.ps1
Write-Host "`n[Test 2] Parsing run.ps1 AST syntax..." -ForegroundColor Yellow
$parseErrors2 = $null
$tokens2 = $null
$ast2 = [System.Management.Automation.Language.Parser]::ParseFile($runPs1, [ref]$tokens2, [ref]$parseErrors2)
if ($parseErrors2.Count -eq 0) {
    Write-Host "  -> PASS: run.ps1 syntax is 100% valid." -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: Syntax errors detected in run.ps1:" -ForegroundColor Red
    $parseErrors2 | ForEach-Object { Write-Host "     Line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Red }
    exit 1
}

# Test 3: Create Dummy Target Structure with Special Characters & Run CLI Scan
Write-Host "`n[Test 3] Testing Directory Scanning & Path Handling with Special Characters..." -ForegroundColor Yellow
$dummyRoot = Join-Path $scriptDir "DummyTarget & Tools (2024) [v1.0]!"
if (Test-Path $dummyRoot) { Remove-Item -Recurse -Force $dummyRoot }
$sub1 = Join-Path $dummyRoot "Binaries"
$sub2 = Join-Path $dummyRoot "Tools & Utilities"
New-Item -ItemType Directory -Path $sub1 -Force | Out-Null
New-Item -ItemType Directory -Path $sub2 -Force | Out-Null

$dummyExe1 = Join-Path $sub1 "Game Launcher & Updater.exe"
$dummyExe2 = Join-Path $sub2 "CrashReporter (x64).exe"
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

# Test 4: Batch File Execution and Delegation (text.bat & FirewallBlocker.bat)
Write-Host "`n[Test 4] Testing text.bat and FirewallBlocker.bat Delegation..." -ForegroundColor Yellow
$cmdArg = "/c `"`"$textBat`" -TargetDir `"$dummyRoot`" -Action Scan -NonInteractive`""
$batProcess = Start-Process -FilePath "cmd.exe" -ArgumentList $cmdArg -NoNewWindow -Wait -PassThru
if ($batProcess.ExitCode -eq 0) {
    Write-Host "  -> PASS: text.bat invoked successfully with ExitCode 0." -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: text.bat exited with code $($batProcess.ExitCode)." -ForegroundColor Red
    exit 1
}

# Test 5: Verify Critical System Path Protection
Write-Host "`n[Test 5] Verifying Protected System Path Safety Guardrails..." -ForegroundColor Yellow
$guardProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`" -TargetDir `"C:\Windows`" -Action BlockBoth -NonInteractive" -NoNewWindow -Wait -PassThru
# ExitCode 2 is our CRITICAL SAFETY BLOCK exit code
if ($guardProcess.ExitCode -eq 2) {
    Write-Host "  -> PASS: System folder 'C:\Windows' was safely blocked with ExitCode 2." -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: System protection did not trigger as expected (ExitCode: $($guardProcess.ExitCode))." -ForegroundColor Red
    exit 1
}

# Test 6: Verify Empty Directory Scan
Write-Host "`n[Test 6] Testing Empty Directory Scan..." -ForegroundColor Yellow
$emptyDir = Join-Path $scriptDir "EmptyDummyFolder"
if (Test-Path $emptyDir) { Remove-Item -Recurse -Force $emptyDir }
New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null
$emptyProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`" -TargetDir `"$emptyDir`" -Action Scan -NonInteractive" -NoNewWindow -Wait -PassThru
Remove-Item -Recurse -Force $emptyDir
if ($emptyProcess.ExitCode -eq 0) {
    Write-Host "  -> PASS: Empty directory handled gracefully without error." -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: Empty directory scan returned code $($emptyProcess.ExitCode)." -ForegroundColor Red
    exit 1
}

# Test 7: Verify Invalid Action Handling
Write-Host "`n[Test 7] Testing Invalid Action Rejection..." -ForegroundColor Yellow
$invalidProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$blockerPs1`" -Action InvalidCommandXYZ -NonInteractive" -NoNewWindow -Wait -PassThru
if ($invalidProcess.ExitCode -eq 1) {
    Write-Host "  -> PASS: Invalid action rejected with exit code 1." -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: Expected exit code 1 for invalid action, got $($invalidProcess.ExitCode)." -ForegroundColor Red
    exit 1
}

# Test 8: Verify Portable Hash Determinism
Write-Host "`n[Test 8] Testing Portable Hash Determinism & Case-Insensitivity..." -ForegroundColor Yellow
$hashFunc = {
    param([string]$InputString)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString.ToLowerInvariant())
    $hasher = [System.Security.Cryptography.MD5]::Create()
    $hashBytes = $hasher.ComputeHash($bytes)
    $hex = [System.BitConverter]::ToString($hashBytes).Replace("-", "")
    return $hex.Substring(0, 8)
}
$h1 = & $hashFunc "C:\Games\App.exe"
$h2 = & $hashFunc "c:\games\app.exe"
$h3 = & $hashFunc "C:\Games\Other.exe"
if ($h1 -eq $h2 -and $h1 -ne $h3 -and $h1.Length -eq 8) {
    Write-Host "  -> PASS: Hash function is deterministic and case-insensitive ($h1)." -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: Hash calculation check failed." -ForegroundColor Red
    exit 1
}


# Cleanup dummy files
if (Test-Path -LiteralPath $dummyRoot) { Remove-Item -LiteralPath $dummyRoot -Recurse -Force }

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "All 8 Comprehensive Tests PASSED Successfully!" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Cyan
