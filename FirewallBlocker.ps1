<#
.SYNOPSIS
    Windows Firewall - Universal Recursive Executable Blocker (FirewallBlocker)
    Compatibility: Windows 7 SP1, 8, 8.1, 10, 11 and Windows Server (2008 R2 - 2025).
    PowerShell: Compatible with PowerShell 2.0, 3.0, 4.0, 5.1, 7.x+

.DESCRIPTION
    Recursively scans any target directory for .exe files and creates Inbound and/or Outbound
    block rules in Windows Defender Firewall using the native 'netsh advfirewall' engine.
    Supports dry-run auditing, selective blocking, rule removal, system directory protection,
    service health checks, and human-readable, color-coded logging.

    Supports remote one-liner execution:
    - irm https://raw.githubusercontent.com/Piyushdas1624/Firewall_bat/main/run.ps1 | iex
    - iex (curl.exe -s --doh-url https://1.1.1.1/dns-query https://raw.githubusercontent.com/Piyushdas1624/Firewall_bat/main/run.ps1 | Out-String)
    - Legacy Windows 7 SP1:
      powershell -nop -ep bypass -c "[Net.ServicePointManager]::SecurityProtocol=3072; iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Piyushdas1624/Firewall_bat/main/run.ps1'))"

.PARAMETER TargetDir
    The target directory to scan and apply firewall rules to.

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
# 1. Environment & TLS 1.2 Setup across all .NET / PowerShell Versions
# ------------------------------------------------------------------------------
try {
    # Tls12 is 3072. Use bitwise OR to keep existing protocols enabled while adding TLS 1.2
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]3072
} catch {
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = 3072
    } catch {
        # Offline or older system without KB3154518
    }
}

# Resolve running mode (File vs In-Memory IEX)
$Script:RunningFromFile = $false
$Script:ScriptFilePath = ""
if ($MyInvocation -and $MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) {
    $Script:ScriptFilePath = $MyInvocation.MyCommand.Path
    $Script:RunningFromFile = [System.IO.File]::Exists($Script:ScriptFilePath)
}

# Store self-content for reliable offline elevation if running via IEX
$Script:SelfCode = ""
if ($MyInvocation -and $MyInvocation.MyCommand -and $MyInvocation.MyCommand.ScriptBlock) {
    $Script:SelfCode = $MyInvocation.MyCommand.ScriptBlock.ToString()
}

# ------------------------------------------------------------------------------
# 2. System Validation & Safety Checks
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

function Test-IsProtectedSystemPath {
    param([string]$PathToCheck)
    if ([string]::IsNullOrEmpty($PathToCheck)) { return $true }
    
    try {
        $resolved = [System.IO.Path]::GetFullPath($PathToCheck).TrimEnd('\', '/')
    } catch {
        return $false
    }
    
    # Safe resolution using environment variables compatible with all Windows versions (Win 7 - 11)
    $winDir = $env:SystemRoot
    if ([string]::IsNullOrEmpty($winDir)) { $winDir = $env:windir }
    if ([string]::IsNullOrEmpty($winDir)) { $winDir = "C:\Windows" }
    $winDir = $winDir.TrimEnd('\', '/')

    $sysDrive = $env:SystemDrive
    if ([string]::IsNullOrEmpty($sysDrive)) { $sysDrive = "C:" }
    $sysDriveRoot = $sysDrive.TrimEnd('\') + "\"

    # 1. Reject Windows root directory and any subdirectory (System32, SysWOW64, WinSxS, etc.)
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

    # 3. Reject Windows Defender / Security folders
    $progFiles = $env:ProgramFiles
    if (-not [string]::IsNullOrEmpty($progFiles)) {
        $defender = (Join-Path $progFiles "Windows Defender").TrimEnd('\', '/')
        if ($resolved.Equals($defender, [System.StringComparison]::OrdinalIgnoreCase) -or
            $resolved.StartsWith($defender + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

# Target directory initialization logic
# Prevent accidental targeting of Windows\System32 when running from elevated console or web one-liner!
if ([string]::IsNullOrEmpty($TargetDir)) {
    if (-not [string]::IsNullOrEmpty($InitialDir) -and (Test-Path -LiteralPath $InitialDir) -and (-not (Test-IsProtectedSystemPath -PathToCheck $InitialDir))) {
        $TargetDir = $InitialDir
    } elseif ($Script:RunningFromFile) {
        $scriptParent = Split-Path -Parent $Script:ScriptFilePath
        if (-not (Test-IsProtectedSystemPath -PathToCheck $scriptParent)) {
            $TargetDir = $scriptParent
        } else {
            $TargetDir = ""
        }
    } else {
        $cwd = (Get-Location).Path
        if (-not (Test-IsProtectedSystemPath -PathToCheck $cwd)) {
            $TargetDir = $cwd
        } else {
            $TargetDir = ""
        }
    }
}

# Normalize target path if provided
if (-not [string]::IsNullOrEmpty($TargetDir)) {
    try {
        if (Test-Path -LiteralPath $TargetDir) {
            $TargetDir = (Get-Item -LiteralPath $TargetDir).FullName
        }
    } catch {
        # Keep as entered
    }
}

# ------------------------------------------------------------------------------
# 3. Console Color & Formatting Helpers
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
    Write-Host "       Windows 7 / 8 / 8.1 / 10 / 11 | Production Grade | Version 2.1        " -ForegroundColor DarkCyan
    Write-Host "==============================================================================" -ForegroundColor Cyan
}

# Cache for executable counting so menu loops render in < 1ms without disk lag
$Script:CachedDir = ""
$Script:CachedExeCount = -1

function Get-CachedExecutableCount {
    param([string]$Dir)
    if ([string]::IsNullOrEmpty($Dir) -or -not (Test-Path -LiteralPath $Dir) -or (Test-IsProtectedSystemPath -PathToCheck $Dir)) {
        return 0
    }
    if ($Script:CachedDir -eq $Dir -and $Script:CachedExeCount -ge 0) {
        return $Script:CachedExeCount
    }
    try {
        $exes = Get-TargetExecutables -PathToScan $Dir
        $Script:CachedDir = $Dir
        $Script:CachedExeCount = $exes.Count
        return $Script:CachedExeCount
    } catch {
        return 0
    }
}

function Write-StatusCard {
    param([string]$Dir)
    
    $isAdmin = Test-IsAdmin
    $svcInfo = Test-FirewallService
    
    Write-Host "  Target Root Folder : " -ForegroundColor Gray -NoNewline
    if ([string]::IsNullOrEmpty($Dir)) {
        Write-Host "[NOT SET] - Drag & drop a folder or select Option 7" -ForegroundColor Yellow
    } elseif (Test-IsProtectedSystemPath -PathToCheck $Dir) {
        Write-Host "$Dir [PROTECTED SYSTEM FOLDER - CANNOT BLOCK]" -ForegroundColor Red
    } else {
        Write-Host "$Dir" -ForegroundColor Yellow
    }

    Write-Host "  Discovered .EXEs   : " -ForegroundColor Gray -NoNewline
    if ([string]::IsNullOrEmpty($Dir) -or (Test-IsProtectedSystemPath -PathToCheck $Dir)) {
        Write-Host "None (Select target folder first)" -ForegroundColor DarkGray
    } else {
        $exeCount = Get-CachedExecutableCount -Dir $Dir
        if ($exeCount -gt 0) {
            Write-Host "$exeCount executable(s) found" -ForegroundColor Green
        } else {
            Write-Host "0 executables found" -ForegroundColor DarkGray
        }
    }

    Write-Host "  Firewall Service   : " -ForegroundColor Gray -NoNewline
    if ($svcInfo.Running) {
        Write-Host "RUNNING" -ForegroundColor Green -NoNewline
        Write-Host " (MpsSvc)" -ForegroundColor DarkGray
    } else {
        Write-Host "$($svcInfo.Status.ToUpper())" -ForegroundColor Red -NoNewline
        Write-Host " (MpsSvc) [! Service must be running]" -ForegroundColor Yellow
    }

    Write-Host "  Admin Privileges   : " -ForegroundColor Gray -NoNewline
    if ($isAdmin) {
        Write-Host "ELEVATED (Administrator)" -ForegroundColor Green
    } else {
        Write-Host "STANDARD USER (Elevation will be requested on action)" -ForegroundColor Yellow
    }
    Write-Host "==============================================================================" -ForegroundColor Cyan
}

# ------------------------------------------------------------------------------
# 4. Elevation Engine
# ------------------------------------------------------------------------------
function Assert-Elevated {
    param(
        [string]$CurrentTargetDir,
        [string]$CurrentAction,
        [switch]$IsNonInteractive
    )
    if (Test-IsAdmin) { return $true }

    Write-Host ""
    Write-Host "  ==========================================================================" -ForegroundColor Yellow
    Write-Host "  [ELEVATION REQUIRED] Administrative privileges are needed for firewall rules" -ForegroundColor White
    Write-Host "  ==========================================================================" -ForegroundColor Yellow
    Write-Host "  Requesting Windows User Account Control (UAC) elevation..." -ForegroundColor Cyan

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
        # Running in-memory (e.g. irm | iex). Write self script content to temp file.
        $tempScript = Join-Path $env:TEMP "FirewallBlocker_Elevated.ps1"
        try {
            if (-not [string]::IsNullOrEmpty($Script:SelfCode)) {
                [System.IO.File]::WriteAllText($tempScript, $Script:SelfCode, [System.Text.Encoding]::UTF8)
            } else {
                # Fallback: fetch from repository if self-code unavailable
                $webContent = (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/Piyushdas1624/Firewall_bat/main/run.ps1")
                [System.IO.File]::WriteAllText($tempScript, $webContent, [System.Text.Encoding]::UTF8)
            }
            $psiArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$tempScript`"$argsToPass"
            Start-Process -FilePath "powershell.exe" -ArgumentList $psiArgs -Verb RunAs
            exit 0
        } catch {
            Write-Host "  [FAIL] Could not initiate elevated launcher: $($_.Exception.Message)" -ForegroundColor Red
            if ($IsNonInteractive) { exit 1 }
            return $false
        }
    }
}

# ------------------------------------------------------------------------------
# 5. Firewall Service Health & Healing
# ------------------------------------------------------------------------------
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
    Write-Host "  [!] WARNING: Windows Defender Firewall service (MpsSvc) is $($svcInfo.Status)." -ForegroundColor Yellow
    Write-Host "      Windows cannot create or enforce firewall rules while this service is stopped." -ForegroundColor DarkYellow
    Write-Host ""
    
    if ($NonInteractive) {
        Write-Host "  [*] NonInteractive mode: Attempting to configure and start MpsSvc..." -ForegroundColor Cyan
        $choice = "Y"
    } else {
        $choice = Read-Host "  Would you like to automatically configure and start Windows Firewall service now? [Y/N]"
    }

    if ($choice -match '^[Yy]') {
        Write-Host "  [*] Configuring MpsSvc to Automatic startup and starting..." -ForegroundColor Cyan
        try {
            # Use sc.exe config for universal compatibility across Win 7 - 11 even if Disabled
            $null = Start-Process -FilePath "sc.exe" -ArgumentList "config MpsSvc start= auto" -NoNewWindow -Wait
            $null = Start-Process -FilePath "sc.exe" -ArgumentList "start MpsSvc" -NoNewWindow -Wait
            Start-Sleep -Seconds 1
            $newSvc = Get-Service -Name MpsSvc -ErrorAction SilentlyContinue
            if ($newSvc -and $newSvc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
                Write-Host "  [OK] Windows Defender Firewall service is now ACTIVE and RUNNING." -ForegroundColor Green
                return $true
            }
        } catch {
            Write-Host "  [FAIL] Failed to start service: $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }
    return $false
}

# ------------------------------------------------------------------------------
# 6. FIPS-Compliant Hash & Low-Level Netsh Engine
# ------------------------------------------------------------------------------
function Get-PortableHash {
    param([string]$InputString)
    try {
        # SHA256 is FIPS-compliant across all Windows versions (Win 7 - 11)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString.ToLowerInvariant())
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $hasher.ComputeHash($bytes)
        $hex = [System.BitConverter]::ToString($hashBytes).Replace("-", "")
        return $hex.Substring(0, 8)
    } catch {
        # Fallback pseudo-hash
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
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEnd()
        $proc.WaitForExit()

        $output = $stdout.Trim()
        return @{
            ExitCode = $proc.ExitCode
            Success  = ($proc.ExitCode -eq 0)
            Output   = $output
        }
    } catch {
        return @{
            ExitCode = -1
            Success  = $false
            Output   = $_.Exception.Message
        }
    }
}

function Format-HumanFirewallError {
    param(
        [string]$RawOutput,
        [int]$ExitCode,
        [string]$ExePath,
        [string]$Direction,
        [string]$RuleName
    )

    $diagnosis = @{
        Component    = "Windows Defender Firewall (netsh)"
        Location     = "Network Subsystem"
        ExePath      = $ExePath
        Direction    = $Direction
        RuleName     = $RuleName
        RawMessage   = $RawOutput
        RootCause    = "Unknown network shell error."
        ActionableFix = "Verify Windows Firewall status and try again."
    }

    if ($RawOutput -match "(?i)(requires elevation|access is denied|run as administrator)") {
        $diagnosis.Location = "Windows Security Token (UAC)"
        $diagnosis.RootCause = "Administrator privileges were lost, revoked, or denied."
        $diagnosis.ActionableFix = "Right-click PowerShell or Terminal and select 'Run as administrator'."
    } elseif ($RawOutput -match "(?i)(attempting to contact the Windows Firewall service|service has not been started|0x6D9|1753|RPC)") {
        $diagnosis.Location = "Windows Service Manager (MpsSvc)"
        $diagnosis.RootCause = "The Windows Defender Firewall service (MpsSvc) is stopped, disabled, or RPC is unreachable."
        $diagnosis.ActionableFix = "Press [9] in the menu or run 'services.msc' and start the 'Windows Defender Firewall' service."
    } elseif ($RawOutput -match "(?i)(Group Policy|policy does not allow|blocked by policy)") {
        $diagnosis.Location = "Active Directory / Local Group Policy"
        $diagnosis.RootCause = "Domain or Local Group Policy explicitly restricts local firewall rule creation."
        $diagnosis.ActionableFix = "Check 'Computer Configuration -> Windows Settings -> Security Settings -> Windows Firewall' in gpedit.msc."
    } elseif ($ExePath.Length -gt 250) {
        $diagnosis.Location = "Win32 File Subsystem (MAX_PATH)"
        $diagnosis.RootCause = "The executable file path ($($ExePath.Length) chars) approaches or exceeds the Windows 260-character MAX_PATH limit."
        $diagnosis.ActionableFix = "Move the target folder to a shorter path (e.g. C:\Games) or enable Win32 Long Paths in Windows."
    } elseif ($RawOutput -match "(?i)(parameter is incorrect|syntax of the command)") {
        $diagnosis.Location = "Command Parser"
        $diagnosis.RootCause = "The executable path contains unsupported characters or unbalanced formatting."
        $diagnosis.ActionableFix = "Ensure the directory name does not contain illegal special characters."
    } else {
        $diagnosis.RootCause = "netsh exited with non-zero code ($ExitCode): $RawOutput"
    }

    return $diagnosis
}

function Get-RuleName {
    param(
        [string]$Direction, # "IN" or "OUT"
        [string]$ExeName,
        [string]$FullPath
    )
    $cleanExe = $ExeName.Replace('"', '')
    $hash = Get-PortableHash -InputString $FullPath
    $namePrefix = "[FWB-$Direction] $cleanExe"
    if ($namePrefix.Length -gt 230) {
        $namePrefix = $namePrefix.Substring(0, 230)
    }
    return "$namePrefix ($hash)"
}

function Get-TargetExecutables {
    param([string]$PathToScan)
    if ([string]::IsNullOrEmpty($PathToScan) -or -not (Test-Path -LiteralPath $PathToScan)) {
        return @()
    }
    try {
        # Exclude directories ending in .exe using PSIsContainer for universal PS 2.0-7.x compatibility
        $items = Get-ChildItem -LiteralPath $PathToScan -Filter "*.exe" -Recurse -Force -ErrorAction SilentlyContinue |
                 Where-Object { -not $_.PSIsContainer -and $_.Extension -match '^\.exe$' }
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
    $inRule = "[FWB-IN] $($ExeName.Replace('"', '')) ($hash)"
    $outRule = "[FWB-OUT] $($ExeName.Replace('"', '')) ($hash)"
    
    $checkIn = Invoke-Netsh -Arguments "advfirewall firewall show rule name=`"$inRule`""
    $checkOut = Invoke-Netsh -Arguments "advfirewall firewall show rule name=`"$outRule`""
    
    $inBlocked = ($checkIn.Success -and $checkIn.Output -match "Action:\s+Block")
    $outBlocked = ($checkOut.Success -and $checkOut.Output -match "Action:\s+Block")

    # Also check legacy rule formats
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
# 7. High-Level Operations (Block, Unblock, Scan, System Clean)
# ------------------------------------------------------------------------------
function Select-DirectoryIfEmpty {
    if ([string]::IsNullOrEmpty($Script:CurrentTarget) -or -not (Test-Path -LiteralPath $Script:CurrentTarget)) {
        Write-Host ""
        Write-Host "  ==========================================================================" -ForegroundColor Yellow
        Write-Host "  [SELECT TARGET FOLDER] Please specify the folder containing .exe files    " -ForegroundColor White
        Write-Host "  ==========================================================================" -ForegroundColor Yellow
        Write-Host "  Tip: You can drag and drop any folder directly into this console window!" -ForegroundColor Cyan
        $newPath = Read-Host "  Folder Path"
        if ([string]::IsNullOrEmpty($newPath)) { return $false }
        
        $cleaned = $newPath.Trim('"', "'", ' ')
        if (-not (Test-Path -LiteralPath $cleaned)) {
            Write-Host "  [FAIL] Folder does not exist: $cleaned" -ForegroundColor Red
            Start-Sleep -Seconds 2
            return $false
        }
        $Script:CurrentTarget = (Get-Item -LiteralPath $cleaned).FullName
        $Script:CachedExeCount = -1
    }
    return $true
}

function Invoke-BlockOperation {
    param(
        [string]$Dir,
        [string]$Mode # "Both", "OutboundOnly", "InboundOnly"
    )

    if ([string]::IsNullOrEmpty($Dir)) {
        if (-not (Select-DirectoryIfEmpty)) { return }
        $Dir = $Script:CurrentTarget
    }

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
        Write-Host "  [ABORT] Cannot proceed without Windows Defender Firewall service." -ForegroundColor Red
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return }
        exit 3
    }

    Write-Host ""
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  BLOCKING OPERATION: Applying Windows Firewall Rules (Mode: $Mode)" -ForegroundColor White
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
    $diagnostics = New-Object System.Collections.ArrayList

    foreach ($exe in $exes) {
        $processedCount++
        $exeName = $exe.Name
        $exePath = $exe.FullName

        $inRuleName = Get-RuleName -Direction "IN" -ExeName $exeName -FullPath $exePath
        $outRuleName = Get-RuleName -Direction "OUT" -ExeName $exeName -FullPath $exePath
        $desc = "Blocked by FirewallBlocker | $exePath"

        Write-Host ("  [{0,3}/{1,-3}] {2}" -f $processedCount, $exes.Count, $exeName) -ForegroundColor White
        Write-Host "          Path: $exePath" -ForegroundColor DarkGray

        # Inbound Rule
        if ($Mode -eq "Both" -or $Mode -eq "InboundOnly") {
            $null = Invoke-Netsh -Arguments "advfirewall firewall delete rule name=`"$inRuleName`""
            $null = Invoke-Netsh -Arguments "advfirewall firewall delete rule name=`"[FolderBlock-IN] $exeName`" program=`"$exePath`""

            $addArgs = "advfirewall firewall add rule name=`"$inRuleName`" dir=in action=block program=`"$exePath`" enable=yes profile=any description=`"$desc`""
            $resIn = Invoke-Netsh -Arguments $addArgs

            if ($resIn.Success) {
                $successRules++
                Write-Host "          [+] INBOUND  : " -ForegroundColor DarkGray -NoNewline
                Write-Host "[OK] Blocked" -ForegroundColor Green -NoNewline
                Write-Host " ('$inRuleName')" -ForegroundColor DarkCyan
            } else {
                $failRules++
                $diag = Format-HumanFirewallError -RawOutput $resIn.Output -ExitCode $resIn.ExitCode -ExePath $exePath -Direction "INBOUND" -RuleName $inRuleName
                $null = $diagnostics.Add($diag)
                Write-Host "          [-] INBOUND  : " -ForegroundColor DarkGray -NoNewline
                Write-Host "[FAIL]" -ForegroundColor Red
                Write-Host "              Where  : $($diag.Location)" -ForegroundColor Yellow
                Write-Host "              Reason : $($diag.RootCause)" -ForegroundColor Red
                Write-Host "              Fix    : $($diag.ActionableFix)" -ForegroundColor DarkYellow
            }
        }

        # Outbound Rule
        if ($Mode -eq "Both" -or $Mode -eq "OutboundOnly") {
            $null = Invoke-Netsh -Arguments "advfirewall firewall delete rule name=`"$outRuleName`""
            $null = Invoke-Netsh -Arguments "advfirewall firewall delete rule name=`"[FolderBlock-OUT] $exeName`" program=`"$exePath`""

            $addArgs = "advfirewall firewall add rule name=`"$outRuleName`" dir=out action=block program=`"$exePath`" enable=yes profile=any description=`"$desc`""
            $resOut = Invoke-Netsh -Arguments $addArgs

            if ($resOut.Success) {
                $successRules++
                Write-Host "          [+] OUTBOUND : " -ForegroundColor DarkGray -NoNewline
                Write-Host "[OK] Blocked" -ForegroundColor Green -NoNewline
                Write-Host " ('$outRuleName')" -ForegroundColor DarkCyan
            } else {
                $failRules++
                $diag = Format-HumanFirewallError -RawOutput $resOut.Output -ExitCode $resOut.ExitCode -ExePath $exePath -Direction "OUTBOUND" -RuleName $outRuleName
                $null = $diagnostics.Add($diag)
                Write-Host "          [-] OUTBOUND : " -ForegroundColor DarkGray -NoNewline
                Write-Host "[FAIL]" -ForegroundColor Red
                Write-Host "              Where  : $($diag.Location)" -ForegroundColor Yellow
                Write-Host "              Reason : $($diag.RootCause)" -ForegroundColor Red
                Write-Host "              Fix    : $($diag.ActionableFix)" -ForegroundColor DarkYellow
            }
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

    if ($diagnostics.Count -gt 0) {
        Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Red
        Write-Host "  [!] DIAGNOSTIC FAILURE BREAKDOWN ($($diagnostics.Count) issue(s) detected):" -ForegroundColor Red
        foreach ($d in $diagnostics) {
            Write-Host "  * Rule     : $($d.RuleName)" -ForegroundColor Yellow
            Write-Host "    Path     : $($d.ExePath)" -ForegroundColor DarkGray
            Write-Host "    Location : $($d.Location)" -ForegroundColor Cyan
            Write-Host "    Cause    : $($d.RootCause)" -ForegroundColor Red
            Write-Host "    Solution : $($d.ActionableFix)" -ForegroundColor Green
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

    if ([string]::IsNullOrEmpty($Dir)) {
        if (-not (Select-DirectoryIfEmpty)) { return }
        $Dir = $Script:CurrentTarget
    }

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

        Write-Host ("  [{0,3}/{1,-3}] Unblocking: {2}" -f $processedCount, $exes.Count, $exeName) -ForegroundColor White

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

        # Purge rules bound to program path
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
    Write-Host "  Scanning Windows Defender Firewall for rules created by this tool..." -ForegroundColor Cyan

    $allRules = Invoke-Netsh -Arguments "advfirewall firewall show rule name=all"
    if (-not $allRules.Success) {
        Write-Host "  [FAIL] Could not query firewall rules: $($allRules.Output)" -ForegroundColor Red
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return }
        return
    }

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

    Write-Host "  [OK] Successfully removed $deleted rule(s) from Windows Defender Firewall." -ForegroundColor Green
    if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..." }
}

function Invoke-ScanAudit {
    param([string]$Dir)

    if ([string]::IsNullOrEmpty($Dir)) {
        if (-not (Select-DirectoryIfEmpty)) { return }
        $Dir = $Script:CurrentTarget
    }

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
    Write-Host "  Current: $(if ([string]::IsNullOrEmpty($Script:CurrentTarget)) { '[NOT SET]' } else { $Script:CurrentTarget })" -ForegroundColor Yellow
    Write-Host ""
    $inputPath = Read-Host "  Enter new folder path (or press ENTER to keep current)"
    
    if ([string]::IsNullOrEmpty($inputPath)) { return }

    $cleaned = $inputPath.Trim('"', "'", ' ')
    
    if (-not (Test-Path -LiteralPath $cleaned)) {
        Write-Host "  [FAIL] The specified folder does not exist: $cleaned" -ForegroundColor Red
        Start-Sleep -Seconds 2
        return
    }

    if (Test-IsProtectedSystemPath -PathToCheck $cleaned) {
        Write-Host "  [!] WARNING: '$cleaned' is a protected Windows system path." -ForegroundColor Red
        Write-Host "      Blocking system paths will break Windows networking. Please choose a game or app folder." -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        return
    }

    try {
        $Script:CurrentTarget = (Get-Item -LiteralPath $cleaned).FullName
        $Script:CachedExeCount = -1
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
# 8. Main Interactive Menu & CLI Dispatcher
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
    Write-Host "   [9]  RESTART / REPAIR Firewall Service      " -ForegroundColor White -NoNewline
    Write-Host "- Auto-configure & ensure MpsSvc health" -ForegroundColor DarkGray
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
            Write-Host "  [*] Verifying & repairing Windows Defender Firewall Service (MpsSvc)..." -ForegroundColor Cyan
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
