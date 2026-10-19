<#
.SYNOPSIS
    Windows Firewall - Advanced Recursive Executable Blocker (FirewallBlocker)
    Cross-Platform: Compatible with Windows 7, 8, 8.1, 10, 11 and Windows Server (2008 R2 - 2025).
    PowerShell: Compatible with PowerShell 2.0, 3.0, 4.0, 5.1, 7.x+

.DESCRIPTION
    Recursively scans any target directory for .exe files and creates Inbound and/or Outbound
    block rules in Windows Defender Firewall using the native 'netsh advfirewall' engine.
    Supports dry-run auditing, selective blocking, rule removal, system directory protection,
    service health checks, and human-readable, color-coded logging.

    Supports remote one-liner execution:
    - irm https://raw.githubusercontent.com/Piyushdas1624/Firewall_bat/main/run.ps1 | iex
    - iex (curl.exe -s --doh-url https://1.1.1.1/dns-query https://raw.githubusercontent.com/Piyushdas1624/Firewall_bat/main/run.ps1 | Out-String)
    - Legacy Windows 7:
      powershell -nop -ep bypass -c "[Net.ServicePointManager]::SecurityProtocol=3072; iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Piyushdas1624/Firewall_bat/main/run.ps1'))"

.PARAMETER TargetDir
    The target directory to scan and apply firewall rules to. If omitted, defaults to the
    current working directory or folder where the script is located.

.PARAMETER Action
    Non-interactive action: BlockBoth, BlockOutbound, BlockInbound, UnblockDir, UnblockAll, Scan, Audit.

.PARAMETER NonInteractive
    Runs the specified -Action without displaying the interactive console menu.
#>

[CmdletBinding()]
param(
    [Parameter(Position=0, Mandatory=$false)]
    [string]$TargetDir = "",

    [Parameter(Position=1, Mandatory=$false)]
    [string]$Action = "",

    [Parameter(Mandatory=$false)]
    [switch]$NonInteractive = $false,

    [Parameter(Mandatory=$false)]
    [switch]$Force = $false,

    [Parameter(Mandatory=$false)]
    [string]$InitialDir = ""
)

# ------------------------------------------------------------------------------
# 1. Environment & PowerShell 2.0 - 7.x Compatibility Setup
# ------------------------------------------------------------------------------
# Ensure TLS 1.2 is enabled for any web requests across all .NET versions
try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
} catch {
    # Non-critical on offline systems
}

# Resolve script directory in a way that works in PS 2.0, 3.0+, and in-memory execution
$Script:RunningFromFile = $false
$Script:ScriptFilePath = ""
if ($MyInvocation -and $MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) {
    $Script:ScriptFilePath = $MyInvocation.MyCommand.Path
    $Script:RunningFromFile = [System.IO.File]::Exists($Script:ScriptFilePath)
}

# Target directory resolution logic
if ([string]::IsNullOrEmpty($TargetDir)) {
    if (-not [string]::IsNullOrEmpty($InitialDir) -and (Test-Path -LiteralPath $InitialDir)) {
        $TargetDir = $InitialDir
    } elseif ($Script:RunningFromFile) {
        $TargetDir = Split-Path -Parent $Script:ScriptFilePath
    } else {
        $TargetDir = (Get-Location).Path
    }
}

# Normalize target path
try {
    if (Test-Path -LiteralPath $TargetDir) {
        $TargetDir = (Get-Item -LiteralPath $TargetDir).FullName
    }
} catch {
    # Keep as entered if resolving fails
}

# ------------------------------------------------------------------------------
# 2. Console Color & Formatting Helpers
# ------------------------------------------------------------------------------
function Write-Color {
    param(
        [string]$Text,
        [string]$Color = "White",
        [switch]$NoNewline
    )
    if ($NoNewline) {
        Write-Host $Text -ForegroundColor $Color -NoNewline
    } else {
        Write-Host $Text -ForegroundColor $Color
    }
}

function Write-Banner {
    Clear-Host
    Write-Host "==============================================================================" -ForegroundColor Cyan
    Write-Host "         FIREWALL BLOCKER - RECURSIVE WINDOWS FIREWALL MANAGER                " -ForegroundColor White
    Write-Host "       Windows 7 / 8 / 8.1 / 10 / 11 | Production Grade | Version 2.0        " -ForegroundColor DarkCyan
    Write-Host "==============================================================================" -ForegroundColor Cyan
}

function Write-StatusCard {
    param([string]$Dir)
    
    $isAdmin = Test-IsAdmin
    $svcInfo = Test-FirewallService
    
    $exeCount = 0
    if (Test-Path -LiteralPath $Dir) {
        try {
            $exeCount = @(Get-ChildItem -LiteralPath $Dir -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue).Count
        } catch {
            $exeCount = 0
        }
    }

    Write-Host "  Target Root Folder : " -ForegroundColor Gray -NoNewline
    Write-Host "$Dir" -ForegroundColor Yellow

    Write-Host "  Discovered .EXEs   : " -ForegroundColor Gray -NoNewline
    if ($exeCount -gt 0) {
        Write-Host "$exeCount executable(s) found" -ForegroundColor Green
    } else {
        Write-Host "0 executables found" -ForegroundColor DarkGray
    }

    Write-Host "  Firewall Service   : " -ForegroundColor Gray -NoNewline
    if ($svcInfo.Running) {
        Write-Host "RUNNING" -ForegroundColor Green -NoNewline
        Write-Host " (MpsSvc)" -ForegroundColor DarkGray
    } else {
        Write-Host "STOPPED / DISABLED" -ForegroundColor Red -NoNewline
        Write-Host " (MpsSvc) [!]" -ForegroundColor Yellow
    }

    Write-Host "  Admin Privileges   : " -ForegroundColor Gray -NoNewline
    if ($isAdmin) {
        Write-Host "ELEVATED (Administrator)" -ForegroundColor Green
    } else {
        Write-Host "STANDARD USER (Elevation will be requested)" -ForegroundColor Yellow
    }
    Write-Host "==============================================================================" -ForegroundColor Cyan
}

# ------------------------------------------------------------------------------
# 3. System Validation & Safety Checks
# ------------------------------------------------------------------------------
function Test-IsAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Assert-Elevated {
    param(
        [string]$CurrentTargetDir,
        [string]$CurrentAction,
        [switch]$IsNonInteractive
    )
    if (Test-IsAdmin) { return $true }

    Write-Host ""
    Write-Host "  [!] Administrator privileges are required to manage Windows Firewall rules." -ForegroundColor Yellow
    Write-Host "  [*] Requesting User Account Control (UAC) elevation..." -ForegroundColor Cyan

    $argsToPass = ""
    if (-not [string]::IsNullOrEmpty($CurrentTargetDir)) {
        $argsToPass += " -TargetDir `"$CurrentTargetDir`""
    }
    if (-not [string]::IsNullOrEmpty($CurrentAction)) {
        $argsToPass += " -Action `"$CurrentAction`""
    }
    if ($IsNonInteractive) {
        $argsToPass += " -NonInteractive"
    }

    # If running from a file on disk
    if ($Script:RunningFromFile -and [System.IO.File]::Exists($Script:ScriptFilePath)) {
        $psiArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$($Script:ScriptFilePath)`"$argsToPass"
        try {
            Start-Process -FilePath "powershell.exe" -ArgumentList $psiArgs -Verb RunAs
            exit 0
        } catch {
            Write-Host "  [FAIL] Elevation request was cancelled or denied." -ForegroundColor Red
            if ($IsNonInteractive) { exit 1 }
            return $false
        }
    } else {
        # Running in-memory (e.g. irm | iex). Write a temporary launcher script.
        $tempScript = Join-Path $env:TEMP "FirewallBlocker_Elevated.ps1"
        try {
            # Download or write current script content to temp file
            $webContent = (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/Piyushdas1624/Firewall_bat/main/run.ps1")
            [System.IO.File]::WriteAllText($tempScript, $webContent, [System.Text.Encoding]::UTF8)
            $psiArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$tempScript`"$argsToPass"
            Start-Process -FilePath "powershell.exe" -ArgumentList $psiArgs -Verb RunAs
            exit 0
        } catch {
            Write-Host "  [FAIL] Could not initiate elevated web launcher: $($_.Exception.Message)" -ForegroundColor Red
            if ($IsNonInteractive) { exit 1 }
            return $false
        }
    }
}

function Test-IsProtectedSystemPath {
    param([string]$PathToCheck)
    if ([string]::IsNullOrEmpty($PathToCheck)) { return $true }
    
    try {
        $resolved = [System.IO.Path]::GetFullPath($PathToCheck).TrimEnd('\', '/')
    } catch {
        return $false
    }
    
    $winDir = [System.Environment]::GetFolderPath('Windows').TrimEnd('\', '/')
    $sysDrive = [System.Environment]::GetEnvironmentVariable('SystemDrive')
    if ([string]::IsNullOrEmpty($sysDrive)) { $sysDrive = "C:" }
    $sysDriveRoot = $sysDrive.TrimEnd('\') + "\"

    # 1. Reject Windows root directory and any subdirectory (System32, SysWOW64, etc.)
    if ($resolved.Equals($winDir, [System.StringComparison]::OrdinalIgnoreCase) -or
        $resolved.StartsWith($winDir + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    # 2. Reject root of system drive (e.g. C:\ or C:)
    if ($resolved.Equals($sysDrive, [System.StringComparison]::OrdinalIgnoreCase) -or
        $resolved.Equals($sysDriveRoot.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase) -or
        $resolved -match '^[A-Za-z]:[\\/]?$') {
        return $true
    }

    # 3. Reject Windows Defender folder
    $progFiles = [System.Environment]::GetFolderPath('ProgramFiles')
    $defender = Join-Path $progFiles "Windows Defender"
    if ($resolved.StartsWith($defender, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    return $false
}

function Test-FirewallService {
    try {
        $svc = Get-Service -Name MpsSvc -ErrorAction SilentlyContinue
        if ($null -eq $svc) {
            return @{
                Status = "Missing"
                Running = $false
                Message = "Windows Firewall service ('MpsSvc') is not installed on this system."
            }
        }
        $isRunning = ($svc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running)
        return @{
            Status = $svc.Status.ToString()
            Running = $isRunning
            Message = "Service is $($svc.Status)"
        }
    } catch {
        return @{
            Status = "Error"
            Running = $false
            Message = $_.Exception.Message
        }
    }
}

function Ensure-FirewallServiceRunning {
    $svcInfo = Test-FirewallService
    if ($svcInfo.Running) { return $true }

    Write-Host ""
    Write-Host "  [!] WARNING: Windows Firewall service (MpsSvc) is $($svcInfo.Status)." -ForegroundColor Yellow
    Write-Host "      Windows cannot create or enforce firewall rules while this service is stopped." -ForegroundColor DarkYellow
    Write-Host ""
    
    if ($NonInteractive) {
        Write-Host "  [*] NonInteractive mode: Attempting to start MpsSvc automatically..." -ForegroundColor Cyan
        $choice = "Y"
    } else {
        $choice = Read-Host "  Would you like to start Windows Firewall service now? [Y/N]"
    }

    if ($choice -match '^[Yy]') {
        Write-Host "  [*] Starting MpsSvc..." -ForegroundColor Cyan
        try {
            Start-Service -Name MpsSvc -ErrorAction Stop
            Start-Sleep -Seconds 1
            $newSvc = Get-Service -Name MpsSvc -ErrorAction SilentlyContinue
            if ($newSvc -and $newSvc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
                Write-Host "  [OK] Windows Firewall service started successfully." -ForegroundColor Green
                return $true
            }
        } catch {
            Write-Host "  [FAIL] Failed to start service: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "         Please check if the service is set to 'Disabled' in services.msc." -ForegroundColor Yellow
            return $false
        }
    }
    return $false
}

# ------------------------------------------------------------------------------
# 4. Low-Level Netsh Execution & Rule Naming Engine
# ------------------------------------------------------------------------------
function Get-PortableHash {
    param([string]$InputString)
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString.ToLowerInvariant())
        $hasher = [System.Security.Cryptography.MD5]::Create()
        $hashBytes = $hasher.ComputeHash($bytes)
        $hex = [System.BitConverter]::ToString($hashBytes).Replace("-", "")
        return $hex.Substring(0, 8)
    } catch {
        # Fallback pseudo-hash based on string length and char codes
        $sum = 0
        foreach ($c in $InputString.ToCharArray()) { $sum = ($sum * 31 + [int]$c) -band 0x7FFFFFFF }
        return $sum.ToString("X8")
    }
}

function Invoke-Netsh {
    param([string]$Arguments)
    
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "netsh.exe"
    $psi.Arguments = $Arguments
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()

        $combined = ($stdout + "`n" + $stderr).Trim()
        return @{
            ExitCode = $proc.ExitCode
            Success  = ($proc.ExitCode -eq 0)
            Output   = $combined
        }
    } catch {
        return @{
            ExitCode = -1
            Success  = $false
            Output   = $_.Exception.Message
        }
    }
}

function Get-RuleName {
    param(
        [string]$Direction, # "IN" or "OUT"
        [string]$ExeName,
        [string]$FullPath
    )
    $hash = Get-PortableHash -InputString $FullPath
    # Keep rule name safe and under 255 chars
    $namePrefix = "[FWB-$Direction] $ExeName"
    if ($namePrefix.Length -gt 230) {
        $namePrefix = $namePrefix.Substring(0, 230)
    }
    return "$namePrefix ($hash)"
}

function Get-TargetExecutables {
    param([string]$PathToScan)
    if (-not (Test-Path -LiteralPath $PathToScan)) {
        return @()
    }
    try {
        $items = Get-ChildItem -LiteralPath $PathToScan -Filter "*.exe" -Recurse -Force -ErrorAction SilentlyContinue
        return @($items)
    } catch {
        return @()
    }
}

function Test-ExecutableRuleStatus {
    param(
        [string]$ExePath,
        [string]$ExeName
    )
    $hash = Get-PortableHash -InputString $ExePath
    $inRule = "[FWB-IN] $ExeName ($hash)"
    $outRule = "[FWB-OUT] $ExeName ($hash)"
    
    # Query netsh for rule existence
    $checkIn = Invoke-Netsh -Arguments "advfirewall firewall show rule name=`"$inRule`""
    $checkOut = Invoke-Netsh -Arguments "advfirewall firewall show rule name=`"$outRule`""
    
    $inBlocked = ($checkIn.Success -and $checkIn.Output -match "Action:\s+Block")
    $outBlocked = ($checkOut.Success -and $checkOut.Output -match "Action:\s+Block")

    # Also check legacy rules
    if (-not $inBlocked) {
        $legacyIn = Invoke-Netsh -Arguments "advfirewall firewall show rule name=`"[FolderBlock-IN] $ExeName`""
        if ($legacyIn.Success -and $legacyIn.Output -match "Action:\s+Block") { $inBlocked = $true }
    }
    if (-not $outBlocked) {
        $legacyOut = Invoke-Netsh -Arguments "advfirewall firewall show rule name=`"[FolderBlock-OUT] $ExeName`""
        if ($legacyOut.Success -and $legacyOut.Output -match "Action:\s+Block") { $outBlocked = $true }
    }

    return @{
        InBlocked  = $inBlocked
        OutBlocked = $outBlocked
    }
}

# ------------------------------------------------------------------------------
# 5. High-Level Operations (Block, Unblock, Scan, System Clean)
# ------------------------------------------------------------------------------
function Invoke-BlockOperation {
    param(
        [string]$Dir,
        [string]$Mode # "Both", "OutboundOnly", "InboundOnly"
    )

    if (Test-IsProtectedSystemPath -PathToCheck $Dir) {
        Write-Host ""
        Write-Host "  ==========================================================================" -ForegroundColor Red
        Write-Host "  [CRITICAL SAFETY BLOCK] TARGET IS A PROTECTED WINDOWS SYSTEM PATH!        " -ForegroundColor White
        Write-Host "  ==========================================================================" -ForegroundColor Red
        Write-Host "  Directory: $Dir" -ForegroundColor Yellow
        Write-Host "  Blocking Windows system folders will break Windows Networking, Windows Update," -ForegroundColor Red
        Write-Host "  and critical operating system services." -ForegroundColor Red
        Write-Host "  Operation aborted immediately to protect system stability." -ForegroundColor Red
        Write-Host "  ==========================================================================" -ForegroundColor Red
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return }
        exit 2
    }

    if (-not (Assert-Elevated -CurrentTargetDir $Dir -CurrentAction "Block$Mode" -IsNonInteractive:$NonInteractive)) {
        if ($NonInteractive) { exit 1 }
        return
    }

    if (-not (Ensure-FirewallServiceRunning)) {
        Write-Host "  [ABORT] Cannot proceed without Windows Firewall service." -ForegroundColor Red
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return }
        exit 3
    }

    Write-Host ""
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  BLOCKING OPERATION STARTED: Mode = $Mode" -ForegroundColor White
    Write-Host "  Target: $Dir" -ForegroundColor Yellow
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Cyan

    $exes = Get-TargetExecutables -PathToScan $Dir
    if ($exes.Count -eq 0) {
        Write-Host "  [i] No .exe files were found in target folder." -ForegroundColor Yellow
        Write-Host "      Path: $Dir" -ForegroundColor DarkGray
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return }
        return
    }

    Write-Host "  Discovered $($exes.Count) executable(s) to process.`n" -ForegroundColor Cyan

    $startTime = [System.DateTime]::Now
    $processedCount = 0
    $successRules = 0
    $failRules = 0
    $failedExes = New-Object System.Collections.ArrayList

    foreach ($exe in $exes) {
        $processedCount++
        $exeName = $exe.Name
        $exePath = $exe.FullName

        $inRuleName = Get-RuleName -Direction "IN" -ExeName $exeName -FullPath $exePath
        $outRuleName = Get-RuleName -Direction "OUT" -ExeName $exeName -FullPath $exePath
        $desc = "Blocked by FirewallBlocker | $exePath"

        Write-Host ("  [{0,3}/{1,-3}] {2}" -f $processedCount, $exes.Count, $exeName) -ForegroundColor White
        Write-Host "          Path: $exePath" -ForegroundColor DarkGray

        $inSuccess = $true
        $outSuccess = $true
        $failDetails = @()

        # Inbound Rule
        if ($Mode -eq "Both" -or $Mode -eq "InboundOnly") {
            # Delete old/duplicate rule first
            $null = Invoke-Netsh -Arguments "advfirewall firewall delete rule name=`"$inRuleName`""
            $null = Invoke-Netsh -Arguments "advfirewall firewall delete rule name=`"[FolderBlock-IN] $exeName`" program=`"$exePath`""

            $addArgs = "advfirewall firewall add rule name=`"$inRuleName`" dir=in action=block program=`"$exePath`" enable=yes profile=any description=`"$desc`""
            $resIn = Invoke-Netsh -Arguments $addArgs

            if ($resIn.Success) {
                $successRules++
                Write-Host "          [+] INBOUND  : " -ForegroundColor DarkGray -NoNewline
                Write-Host "[OK] Rule Created" -ForegroundColor Green -NoNewline
                Write-Host " ('$inRuleName')" -ForegroundColor DarkCyan
            } else {
                $failRules++
                $inSuccess = $false
                $failDetails += "INBOUND: $($resIn.Output)"
                Write-Host "          [-] INBOUND  : " -ForegroundColor DarkGray -NoNewline
                Write-Host "[FAIL] netsh error" -ForegroundColor Red
                Write-Host "              Detail : $($resIn.Output)" -ForegroundColor Yellow
            }
        }

        # Outbound Rule
        if ($Mode -eq "Both" -or $Mode -eq "OutboundOnly") {
            # Delete old/duplicate rule first
            $null = Invoke-Netsh -Arguments "advfirewall firewall delete rule name=`"$outRuleName`""
            $null = Invoke-Netsh -Arguments "advfirewall firewall delete rule name=`"[FolderBlock-OUT] $exeName`" program=`"$exePath`""

            $addArgs = "advfirewall firewall add rule name=`"$outRuleName`" dir=out action=block program=`"$exePath`" enable=yes profile=any description=`"$desc`""
            $resOut = Invoke-Netsh -Arguments $addArgs

            if ($resOut.Success) {
                $successRules++
                Write-Host "          [+] OUTBOUND : " -ForegroundColor DarkGray -NoNewline
                Write-Host "[OK] Rule Created" -ForegroundColor Green -NoNewline
                Write-Host " ('$outRuleName')" -ForegroundColor DarkCyan
            } else {
                $failRules++
                $outSuccess = $false
                $failDetails += "OUTBOUND: $($resOut.Output)"
                Write-Host "          [-] OUTBOUND : " -ForegroundColor DarkGray -NoNewline
                Write-Host "[FAIL] netsh error" -ForegroundColor Red
                Write-Host "              Detail : $($resOut.Output)" -ForegroundColor Yellow
            }
        }

        if (-not $inSuccess -or -not $outSuccess) {
            $null = $failedExes.Add(@{ Name = $exeName; Path = $exePath; Errors = $failDetails })
        }
    }

    $duration = [System.DateTime]::Now - $startTime

    # Render Operation Summary Report
    Write-Host ""
    Write-Host "  ==========================================================================" -ForegroundColor Cyan
    Write-Host "                         OPERATION SUMMARY REPORT                           " -ForegroundColor White
    Write-Host "  ==========================================================================" -ForegroundColor Cyan
    Write-Host ("  Target Directory      : {0}" -f $Dir) -ForegroundColor Yellow
    Write-Host ("  Execution Mode        : {0}" -f $Mode) -ForegroundColor White
    Write-Host ("  Executables Processed : {0}" -f $processedCount) -ForegroundColor White
    Write-Host ("  Rules Created [OK]    : {0}" -f $successRules) -ForegroundColor Green
    if ($failRules -gt 0) {
        Write-Host ("  Rules Failed  [FAIL]  : {0}" -f $failRules) -ForegroundColor Red
    } else {
        Write-Host ("  Rules Failed  [FAIL]  : 0") -ForegroundColor DarkGray
    }
    Write-Host ("  Elapsed Time          : {0:N2} seconds" -f $duration.TotalSeconds) -ForegroundColor DarkCyan

    if ($failedExes.Count -gt 0) {
        Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Red
        Write-Host "  [!] ATTENTION: The following $($failedExes.Count) executable(s) encountered errors:" -ForegroundColor Red
        foreach ($f in $failedExes) {
            Write-Host "  * $($f.Name)" -ForegroundColor Yellow
            Write-Host "    Path   : $($f.Path)" -ForegroundColor DarkGray
            foreach ($err in $f.Errors) {
                Write-Host "    Reason : $err" -ForegroundColor Red
            }
        }
        Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Red
    }
    Write-Host "  ==========================================================================" -ForegroundColor Cyan

    if (-not $NonInteractive) {
        Read-Host "`n  Press ENTER to return to menu..."
    }
}

function Invoke-UnblockOperation {
    param([string]$Dir)

    if (Test-IsProtectedSystemPath -PathToCheck $Dir) {
        Write-Host ""
        Write-Host "  ==========================================================================" -ForegroundColor Red
        Write-Host "  [CRITICAL SAFETY BLOCK] TARGET IS A PROTECTED WINDOWS SYSTEM PATH!        " -ForegroundColor White
        Write-Host "  ==========================================================================" -ForegroundColor Red
        Write-Host "  Directory: $Dir" -ForegroundColor Yellow
        Write-Host "  Operation aborted to protect system stability." -ForegroundColor Red
        Write-Host "  ==========================================================================" -ForegroundColor Red
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return }
        exit 2
    }

    if (-not (Assert-Elevated -CurrentTargetDir $Dir -CurrentAction "UnblockDir" -IsNonInteractive:$NonInteractive)) {
        if ($NonInteractive) { exit 1 }
        return
    }

    Write-Host ""
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  UNBLOCKING: Removing Firewall Rules for Directory Tree" -ForegroundColor White
    Write-Host "  Target: $Dir" -ForegroundColor Yellow
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Cyan

    $exes = Get-TargetExecutables -PathToScan $Dir
    if ($exes.Count -eq 0) {
        Write-Host "  [i] No .exe files found in target folder to unblock." -ForegroundColor Yellow
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return }
        return
    }

    $startTime = [System.DateTime]::Now
    $processedCount = 0
    $deletedRules = 0

    foreach ($exe in $exes) {
        $processedCount++
        $exeName = $exe.Name
        $exePath = $exe.FullName

        $inRuleName = Get-RuleName -Direction "IN" -ExeName $exeName -FullPath $exePath
        $outRuleName = Get-RuleName -Direction "OUT" -ExeName $exeName -FullPath $exePath

        Write-Host ("  [{0,3}/{1,-3}] Cleaning: {2}" -f $processedCount, $exes.Count, $exeName) -ForegroundColor White

        # Delete new hash format rules
        $resIn = Invoke-Netsh -Arguments "advfirewall firewall delete rule name=`"$inRuleName`""
        if ($resIn.Success -and $resIn.Output -notmatch "No rules match") { $deletedRules++ }

        $resOut = Invoke-Netsh -Arguments "advfirewall firewall delete rule name=`"$outRuleName`""
        if ($resOut.Success -and $resOut.Output -notmatch "No rules match") { $deletedRules++ }

        # Delete legacy [FolderBlock-IN/OUT] format rules
        $resLegIn = Invoke-Netsh -Arguments "advfirewall firewall delete rule name=`"[FolderBlock-IN] $exeName`" program=`"$exePath`""
        if ($resLegIn.Success -and $resLegIn.Output -notmatch "No rules match") { $deletedRules++ }

        $resLegOut = Invoke-Netsh -Arguments "advfirewall firewall delete rule name=`"[FolderBlock-OUT] $exeName`" program=`"$exePath`""
        if ($resLegOut.Success -and $resLegOut.Output -notmatch "No rules match") { $deletedRules++ }

        # Also purge any rule bound to this exact program path
        $resProg = Invoke-Netsh -Arguments "advfirewall firewall delete rule name=all program=`"$exePath`""
        if ($resProg.Success -and $resProg.Output -notmatch "No rules match") { $deletedRules++ }
    }

    $duration = [System.DateTime]::Now - $startTime

    Write-Host ""
    Write-Host "  ==========================================================================" -ForegroundColor Cyan
    Write-Host "                        UNBLOCK COMPLETE SUMMARY                            " -ForegroundColor White
    Write-Host "  ==========================================================================" -ForegroundColor Cyan
    Write-Host ("  Target Directory      : {0}" -f $Dir) -ForegroundColor Yellow
    Write-Host ("  Executables Cleaned   : {0}" -f $processedCount) -ForegroundColor White
    Write-Host ("  Rules Removed         : {0}" -f $deletedRules) -ForegroundColor Green
    Write-Host ("  Elapsed Time          : {0:N2} seconds" -f $duration.TotalSeconds) -ForegroundColor DarkCyan
    Write-Host "  ==========================================================================" -ForegroundColor Cyan

    if (-not $NonInteractive) {
        Read-Host "`n  Press ENTER to return to menu..."
    }
}

function Invoke-UnblockAllSystem {
    if (-not (Assert-Elevated -CurrentAction "UnblockAll" -IsNonInteractive:$NonInteractive)) {
        return
    }

    Write-Host ""
    Write-Host "  ==========================================================================" -ForegroundColor Yellow
    Write-Host "  GLOBAL PURGE: Scan & Clean All FirewallBlocker Rules Across System       " -ForegroundColor White
    Write-Host "  ==========================================================================" -ForegroundColor Yellow
    Write-Host "  Scanning Windows Firewall for rules created by this tool..." -ForegroundColor Cyan

    # Query all rules from netsh
    $allRules = Invoke-Netsh -Arguments "advfirewall firewall show rule name=all"
    if (-not $allRules.Success) {
        Write-Host "  [FAIL] Could not query firewall rules: $($allRules.Output)" -ForegroundColor Red
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return }
        return
    }

    # Match rule names starting with [FWB- or [FolderBlock- regardless of console language
    $matchedRuleNames = New-Object System.Collections.ArrayList
    $lines = $allRules.Output -split "`r?`n"
    foreach ($line in $lines) {
        if ($line -match ':\s*(\[FWB-(?:IN|OUT)\].+|\b\[FolderBlock-(?:IN|OUT)\].+)') {
            $rName = $matches[1].Trim()
            if (-not $matchedRuleNames.Contains($rName)) {
                $null = $matchedRuleNames.Add($rName)
            }
        }
    }

    if ($matchedRuleNames.Count -eq 0) {
        Write-Host "  [OK] No FirewallBlocker rules were found on this system." -ForegroundColor Green
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return }
        return
    }

    Write-Host "  Discovered $($matchedRuleNames.Count) matching FirewallBlocker rule(s):" -ForegroundColor Yellow
    $displayLimit = [Math]::Min(15, $matchedRuleNames.Count)
    for ($i = 0; $i -lt $displayLimit; $i++) {
        Write-Host "    - $($matchedRuleNames[$i])" -ForegroundColor DarkGray
    }
    if ($matchedRuleNames.Count -gt 15) {
        Write-Host "    ... and $($matchedRuleNames.Count - 15) more." -ForegroundColor DarkGray
    }

    Write-Host ""
    if (-not $NonInteractive) {
        $confirm = Read-Host "  Are you SURE you want to delete all $($matchedRuleNames.Count) rules? [Y/N]"
        if ($confirm -notmatch '^[Yy]') {
            Write-Host "  [CANCEL] Deletion aborted by user." -ForegroundColor Yellow
            Read-Host "`n  Press ENTER to return to menu..."
            return
        }
    }

    $deleted = 0
    foreach ($rName in $matchedRuleNames) {
        $res = Invoke-Netsh -Arguments "advfirewall firewall delete rule name=`"$rName`""
        if ($res.Success) { $deleted++ }
    }

    Write-Host "  [OK] Successfully removed $deleted rule(s) from Windows Firewall." -ForegroundColor Green
    if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..." }
}

function Invoke-ScanAudit {
    param([string]$Dir)

    Write-Host ""
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  SCAN & AUDIT: Directory Executables and Firewall Status (Dry Run)" -ForegroundColor White
    Write-Host "  Target: $Dir" -ForegroundColor Yellow
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Cyan

    $exes = Get-TargetExecutables -PathToScan $Dir
    if ($exes.Count -eq 0) {
        Write-Host "  [i] No .exe files were found in target folder." -ForegroundColor Yellow
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return }
        return
    }

    Write-Host "  Discovered $($exes.Count) executable file(s):`n" -ForegroundColor Cyan

    $count = 0
    $blockedBoth = 0
    $blockedInOnly = 0
    $blockedOutOnly = 0
    $unblocked = 0

    foreach ($exe in $exes) {
        $count++
        $status = Test-ExecutableRuleStatus -ExePath $exe.FullName -ExeName $exe.Name
        
        $sizeMB = $exe.Length / 1MB

        Write-Host ("  [{0,3}/{1,-3}] {2} ({3:N1} MB)" -f $count, $exes.Count, $exe.Name, $sizeMB) -ForegroundColor White
        Write-Host "          Path: $($exe.FullName)" -ForegroundColor DarkGray

        # Status indicators
        if ($status.InBlocked -and $status.OutBlocked) {
            $blockedBoth++
            Write-Host "          Status: " -ForegroundColor DarkGray -NoNewline
            Write-Host "[FULL BLOCK] Inbound: BLOCKED | Outbound: BLOCKED" -ForegroundColor Red
        } elseif ($status.InBlocked) {
            $blockedInOnly++
            Write-Host "          Status: " -ForegroundColor DarkGray -NoNewline
            Write-Host "[PARTIAL] Inbound: BLOCKED | Outbound: Open" -ForegroundColor Yellow
        } elseif ($status.OutBlocked) {
            $blockedOutOnly++
            Write-Host "          Status: " -ForegroundColor DarkGray -NoNewline
            Write-Host "[PARTIAL] Inbound: Open | Outbound: BLOCKED" -ForegroundColor Yellow
        } else {
            $unblocked++
            Write-Host "          Status: " -ForegroundColor DarkGray -NoNewline
            Write-Host "[UNBLOCKED] Inbound: Open | Outbound: Open" -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-Host "  ==========================================================================" -ForegroundColor Cyan
    Write-Host "                            AUDIT SUMMARY RESULTS                           " -ForegroundColor White
    Write-Host "  ==========================================================================" -ForegroundColor Cyan
    Write-Host ("  Total Executables Discovered : {0}" -f $count) -ForegroundColor White
    Write-Host ("  Fully Blocked (IN + OUT)     : {0}" -f $blockedBoth) -ForegroundColor Red
    Write-Host ("  Outbound Blocked Only        : {0}" -f $blockedOutOnly) -ForegroundColor Yellow
    Write-Host ("  Inbound Blocked Only         : {0}" -f $blockedInOnly) -ForegroundColor Yellow
    Write-Host ("  Completely Unblocked (Open)  : {0}" -f $unblocked) -ForegroundColor Green
    Write-Host "  ==========================================================================" -ForegroundColor Cyan

    if (-not $NonInteractive) {
        Read-Host "`n  Press ENTER to return to menu..."
    }
}

function Set-NewTargetDirectory {
    Write-Host ""
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  CHANGE TARGET DIRECTORY" -ForegroundColor White
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  Tip: You can drag and drop any folder directly into this console window!" -ForegroundColor DarkCyan
    Write-Host "  Current: $Script:CurrentTarget" -ForegroundColor Yellow
    Write-Host ""
    $inputPath = Read-Host "  Enter new folder path (or press ENTER to keep current)"
    
    if ([string]::IsNullOrEmpty($inputPath)) { return }

    # Clean leading and trailing quotes if pasted
    $cleaned = $inputPath.Trim('"', "'", ' ')
    
    if (-not (Test-Path -LiteralPath $cleaned)) {
        Write-Host "  [FAIL] The specified folder does not exist: $cleaned" -ForegroundColor Red
        Start-Sleep -Seconds 2
        return
    }

    try {
        $Script:CurrentTarget = (Get-Item -LiteralPath $cleaned).FullName
        Write-Host "  [OK] Target folder updated successfully." -ForegroundColor Green
        Start-Sleep -Seconds 1
    } catch {
        Write-Host "  [FAIL] Invalid path: $($_.Exception.Message)" -ForegroundColor Red
        Start-Sleep -Seconds 2
    }
}

function Show-FirewallMMC {
    Write-Host "  [*] Launching Windows Defender Firewall with Advanced Security (wf.msc)..." -ForegroundColor Cyan
    try {
        Start-Process "wf.msc"
    } catch {
        Write-Host "  [FAIL] Could not open wf.msc: $($_.Exception.Message)" -ForegroundColor Red
        Start-Sleep -Seconds 2
    }
}

# ------------------------------------------------------------------------------
# 6. Main Interactive Menu & CLI Dispatcher
# ------------------------------------------------------------------------------
$Script:CurrentTarget = $TargetDir

# Non-interactive CLI Execution Dispatch
if (-not [string]::IsNullOrEmpty($Action)) {
    switch -Regex ($Action) {
        '^(BlockAll|BlockBoth|Both)$'      { Invoke-BlockOperation -Dir $Script:CurrentTarget -Mode "Both"; exit 0 }
        '^(BlockOutbound|Outbound)$'       { Invoke-BlockOperation -Dir $Script:CurrentTarget -Mode "OutboundOnly"; exit 0 }
        '^(BlockInbound|Inbound)$'         { Invoke-BlockOperation -Dir $Script:CurrentTarget -Mode "InboundOnly"; exit 0 }
        '^(UnblockDir|Unblock)$'           { Invoke-UnblockOperation -Dir $Script:CurrentTarget; exit 0 }
        '^(UnblockAll|Purge)$'             { Invoke-UnblockAllSystem; exit 0 }
        '^(Scan|Audit|List)$'              { Invoke-ScanAudit -Dir $Script:CurrentTarget; exit 0 }
        default {
            Write-Host "Unknown Action: $Action. Valid actions: BlockBoth, BlockOutbound, BlockInbound, UnblockDir, UnblockAll, Scan." -ForegroundColor Red
            exit 1
        }
    }
}

# Interactive Menu Loop
while ($true) {
    Write-Banner
    Write-StatusCard -Dir $Script:CurrentTarget

    Write-Host "  FIREWALL BLOCK OPTIONS:" -ForegroundColor DarkCyan
    Write-Host "   [1]  BLOCK all .exes (Inbound + Outbound)   " -ForegroundColor White -NoNewline
    Write-Host "- Complete Network Isolation" -ForegroundColor DarkGray
    Write-Host "   [2]  BLOCK all .exes (Outbound Only)        " -ForegroundColor White -NoNewline
    Write-Host "- Stop Outgoing / Telemetry / DRM" -ForegroundColor DarkGray
    Write-Host "   [3]  BLOCK all .exes (Inbound Only)         " -ForegroundColor White -NoNewline
    Write-Host "- Block Incoming Connection Requests" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  MANAGEMENT & AUDIT OPTIONS:" -ForegroundColor DarkCyan
    Write-Host "   [4]  UNBLOCK target folder                  " -ForegroundColor White -NoNewline
    Write-Host "- Remove rules created for this folder" -ForegroundColor DarkGray
    Write-Host "   [5]  UNBLOCK ALL system rules               " -ForegroundColor White -NoNewline
    Write-Host "- Clean up all FirewallBlocker rules on PC" -ForegroundColor DarkGray
    Write-Host "   [6]  SCAN / AUDIT target folder (Dry Run)   " -ForegroundColor White -NoNewline
    Write-Host "- Inspect rule status without changes" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  CONFIGURATION & TOOLS:" -ForegroundColor DarkCyan
    Write-Host "   [7]  CHANGE target directory                " -ForegroundColor White -NoNewline
    Write-Host "- Pick or drag-and-drop a new folder" -ForegroundColor DarkGray
    Write-Host "   [8]  OPEN Windows Firewall GUI (wf.msc)     " -ForegroundColor White -NoNewline
    Write-Host "- Inspect native firewall rules" -ForegroundColor DarkGray
    Write-Host "   [9]  RESTART Windows Firewall Service       " -ForegroundColor White -NoNewline
    Write-Host "- Check & ensure MpsSvc health" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "   [0]  Exit" -ForegroundColor Red
    Write-Host "==============================================================================" -ForegroundColor Cyan
    
    $choice = Read-Host "  Select an option [0-9]"

    switch ($choice.Trim()) {
        "1" { Invoke-BlockOperation -Dir $Script:CurrentTarget -Mode "Both" }
        "2" { Invoke-BlockOperation -Dir $Script:CurrentTarget -Mode "OutboundOnly" }
        "3" { Invoke-BlockOperation -Dir $Script:CurrentTarget -Mode "InboundOnly" }
        "4" { Invoke-UnblockOperation -Dir $Script:CurrentTarget }
        "5" { Invoke-UnblockAllSystem }
        "6" { Invoke-ScanAudit -Dir $Script:CurrentTarget }
        "7" { Set-NewTargetDirectory }
        "8" { Show-FirewallMMC }
        "9" { 
            Write-Host "  [*] Verifying Windows Firewall Service (MpsSvc)..." -ForegroundColor Cyan
            $svcRes = Ensure-FirewallServiceRunning
            if ($svcRes) { Write-Host "  [OK] Service is active and ready." -ForegroundColor Green }
            Start-Sleep -Seconds 2
        }
        "0" { 
            Write-Host "`n  Exiting FirewallBlocker. Goodbye!`n" -ForegroundColor Cyan
            exit 0
        }
        default {
            Write-Host "  [!] Invalid choice: '$choice'. Please select a number between 0 and 9." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
        }
    }
}
