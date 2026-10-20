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
    - irm https://raw.githubusercontent.com/Piyushdas1624/Firewall-Blocker/main/run.ps1 | iex
    - iex (curl.exe -s --doh-url https://1.1.1.1/dns-query https://raw.githubusercontent.com/Piyushdas1624/Firewall-Blocker/main/run.ps1 | Out-String)
    - Legacy Windows 7 SP1 / PS 2.0:
      powershell -nop -ep bypass -c "[Net.ServicePointManager]::SecurityProtocol=3072; iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Piyushdas1624/Firewall-Blocker/main/run.ps1'))"

.PARAMETER TargetDir
    The target directory to scan and apply firewall rules to.

.PARAMETER Action
    Non-interactive action: BlockBoth, BlockOutbound, BlockInbound, UnblockDir, UnblockAll, Scan, Audit, RepairService.

.PARAMETER NonInteractive
    Runs the specified -Action without displaying the interactive console menu.

.PARAMETER Force
    Suppresses confirmation prompts for operations such as UnblockAll.

.PARAMETER InitialDir
    Initial directory passed by the batch launcher.

.PARAMETER ExportFunctionsOnly
    Loads functions into the caller scope and returns immediately without running the menu or dispatcher.
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
    [string]$InitialDir = "",

    [Parameter(Mandatory=$false)]
    [switch]$ExportFunctionsOnly = $false
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

function Test-IsRealScriptContent {
    param([string]$Code)
    if ([string]::IsNullOrEmpty($Code)) { return $false }
    return ($Code.Length -gt 5000 -and
            $Code.Contains("Invoke-BlockOperation") -and
            $Code.Contains("Get-PortableHash") -and
            $Code.Contains("Test-IsProtectedSystemPath"))
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
if ($Script:RunningFromFile) {
    try {
        $Script:SelfCode = [System.IO.File]::ReadAllText($Script:ScriptFilePath, [System.Text.Encoding]::UTF8)
    } catch {}
}
if (-not (Test-IsRealScriptContent -Code $Script:SelfCode)) {
    if ($MyInvocation -and $MyInvocation.MyCommand) {
        $candidateCode = ""
        if ($MyInvocation.MyCommand.ScriptBlock) {
            $candidateCode = $MyInvocation.MyCommand.ScriptBlock.ToString()
        } elseif ($MyInvocation.MyCommand.Definition) {
            $candidateCode = $MyInvocation.MyCommand.Definition
        }
        if (Test-IsRealScriptContent -Code $candidateCode) {
            $Script:SelfCode = $candidateCode
        }
    }
}
if (-not (Test-IsRealScriptContent -Code $Script:SelfCode)) {
    if (-not [string]::IsNullOrEmpty($global:FirewallBlocker_ScriptCode) -and (Test-IsRealScriptContent -Code $global:FirewallBlocker_ScriptCode)) {
        $Script:SelfCode = $global:FirewallBlocker_ScriptCode
    }
}

function Cleanup-TempElevationScript {
    if ($Script:RunningFromFile -and $Script:ScriptFilePath -and ($Script:ScriptFilePath -like "*FirewallBlocker_Elevated*.ps1")) {
        try {
            Remove-Item -LiteralPath $Script:ScriptFilePath -Force -ErrorAction SilentlyContinue
        } catch {}
    }
    try {
        if (-not [string]::IsNullOrEmpty($env:TEMP) -and (Test-Path -LiteralPath $env:TEMP)) {
            Get-ChildItem -LiteralPath $env:TEMP -Filter "*FirewallBlocker_Elevated*.ps1" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}
try {
    $null = Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action { Cleanup-TempElevationScript } -SupportEvent
} catch {}

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

    # 2. Reject root of any drive (e.g. C:\ or C: or D:\)
    if ($resolved.Equals($sysDrive, [System.StringComparison]::OrdinalIgnoreCase) -or
        $resolved.Equals($sysDriveRoot.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase) -or
        $resolved -match '^[A-Za-z]:[\\/]?$') {
        return $true
    }

    # 3. Reject root Program Files and Program Files (x86) folders directly (subdirectories like C:\Program Files\Game ARE allowed)
    $cleanProg = $null
    $progFiles = $env:ProgramFiles
    if (-not [string]::IsNullOrEmpty($progFiles)) {
        $cleanProg = $progFiles.TrimEnd('\', '/')
        if ($resolved.Equals($cleanProg, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    $cleanProgX86 = $null
    $progFilesX86 = ${env:ProgramFiles(x86)}
    if (-not [string]::IsNullOrEmpty($progFilesX86)) {
        $cleanProgX86 = $progFilesX86.TrimEnd('\', '/')
        if ($resolved.Equals($cleanProgX86, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    # 4. Reject ProgramData root folder directly
    $progData = $env:ProgramData
    if ([string]::IsNullOrEmpty($progData)) {
        $progData = Join-Path $sysDriveRoot "ProgramData"
    }
    $cleanProgData = $progData.TrimEnd('\', '/')
    if ($resolved.Equals($cleanProgData, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    # 5. Reject Windows Defender, Microsoft Security, and WindowsApps folders (and all subdirectories)
    $defenderFolders = New-Object System.Collections.ArrayList
    if (-not [string]::IsNullOrEmpty($cleanProg)) {
        $null = $defenderFolders.Add((Join-Path $cleanProg "Windows Defender"))
        $null = $defenderFolders.Add((Join-Path $cleanProg "Windows Defender Advanced Threat Protection"))
    }
    if (-not [string]::IsNullOrEmpty($cleanProgX86)) {
        $null = $defenderFolders.Add((Join-Path $cleanProgX86 "Windows Defender"))
    }
    if (-not [string]::IsNullOrEmpty($cleanProgData)) {
        $null = $defenderFolders.Add((Join-Path $cleanProgData "Microsoft\Windows Defender"))
        $null = $defenderFolders.Add((Join-Path $cleanProgData "Microsoft\Windows Defender Advanced Threat Protection"))
    }
    $localAppData = $env:LOCALAPPDATA
    if (-not [string]::IsNullOrEmpty($localAppData)) {
        $cleanLocalAppData = $localAppData.TrimEnd('\', '/')
        $null = $defenderFolders.Add((Join-Path $cleanLocalAppData "Microsoft\WindowsApps"))
    }

    foreach ($df in $defenderFolders) {
        if (-not [string]::IsNullOrEmpty($df)) {
            $cleanDf = $df.TrimEnd('\', '/')
            if ($resolved.Equals($cleanDf, [System.StringComparison]::OrdinalIgnoreCase) -or
                $resolved.StartsWith($cleanDf + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
    }

    return $false
}

function Test-IsUserProfileRoot {
    param([string]$PathToCheck)
    if ([string]::IsNullOrEmpty($PathToCheck)) { return $false }
    try {
        $resolved = [System.IO.Path]::GetFullPath($PathToCheck).TrimEnd('\', '/')
    } catch {
        return $false
    }

    $userProfile = $env:USERPROFILE
    if (-not [string]::IsNullOrEmpty($userProfile)) {
        $cleanUP = $userProfile.TrimEnd('\', '/')
        if ($resolved.Equals($cleanUP, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    $sysDrive = $env:SystemDrive
    if ([string]::IsNullOrEmpty($sysDrive)) { $sysDrive = "C:" }
    $usersDir = Join-Path ($sysDrive.TrimEnd('\') + "\") "Users"
    $cleanUsers = $usersDir.TrimEnd('\', '/')
    if ($resolved.Equals($cleanUsers, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    $publicDir = $env:PUBLIC
    if (-not [string]::IsNullOrEmpty($publicDir)) {
        $cleanPublic = $publicDir.TrimEnd('\', '/')
        if ($resolved.Equals($cleanPublic, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    # Direct child of C:\Users (e.g. C:\Users\Username)
    try {
        $parent = [System.IO.Path]::GetDirectoryName($resolved)
        if (-not [string]::IsNullOrEmpty($parent)) {
            $cleanParent = $parent.TrimEnd('\', '/')
            if ($cleanParent.Equals($cleanUsers, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
    } catch {}

    return $false
}

# Target directory initialization logic
# Prevent accidental targeting of Windows\System32 or Temp folder when running from elevated console or web one-liner!
$isTempElevated = ($Script:RunningFromFile -and ($Script:ScriptFilePath -like "*FirewallBlocker_Elevated*"))
$isTempDir = $false
try {
    if (-not [string]::IsNullOrEmpty($env:TEMP)) {
        $tempRoot = [System.IO.Path]::GetFullPath($env:TEMP).TrimEnd('\', '/')
        $currentScriptDir = if ($Script:RunningFromFile) { (Split-Path -Parent $Script:ScriptFilePath).TrimEnd('\', '/') } else { "" }
        if (-not [string]::IsNullOrEmpty($currentScriptDir) -and $currentScriptDir.Equals($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            $isTempDir = $true
        }
    }
} catch {}

if ([string]::IsNullOrEmpty($TargetDir)) {
    if (-not [string]::IsNullOrEmpty($InitialDir) -and (Test-Path -LiteralPath $InitialDir) -and (-not (Test-IsProtectedSystemPath -PathToCheck $InitialDir))) {
        $TargetDir = $InitialDir
    } elseif ($Script:RunningFromFile -and -not $isTempElevated -and -not $isTempDir) {
        $scriptParent = Split-Path -Parent $Script:ScriptFilePath
        if (-not (Test-IsProtectedSystemPath -PathToCheck $scriptParent)) {
            $TargetDir = $scriptParent
        } else {
            $TargetDir = ""
        }
    } else {
        $cwd = (Get-Location).Path
        if (-not (Test-IsProtectedSystemPath -PathToCheck $cwd) -and -not $isTempDir) {
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
    Write-Host "       Windows 7 / 8 / 8.1 / 10 / 11 | Production Grade | Version 2.3        " -ForegroundColor DarkCyan
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
        $exes = @(Get-TargetExecutables -PathToScan $Dir)
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
        [switch]$IsNonInteractive,
        [switch]$Force = $false
    )
    if (Test-IsAdmin) { return $true }

    Write-Host ""
    Write-Host "  ==========================================================================" -ForegroundColor Yellow
    Write-Host "  [ELEVATION REQUIRED] Administrative privileges are needed for firewall rules" -ForegroundColor White
    Write-Host "  ==========================================================================" -ForegroundColor Yellow
    Write-Host "  Requesting Windows User Account Control (UAC) elevation..." -ForegroundColor Cyan

    $argsToPass = ""
    if (-not [string]::IsNullOrEmpty($CurrentTargetDir)) {
        # Safe directory path without trailing backslash that breaks CLI quotes
        $safeDir = $CurrentTargetDir.TrimEnd('\', '/')
        $argsToPass += " -TargetDir `"$safeDir`""
    }
    if (-not [string]::IsNullOrEmpty($CurrentAction)) {
        $argsToPass += " -Action `"$CurrentAction`""
    }
    if ($IsNonInteractive) {
        $argsToPass += " -NonInteractive"
    }
    if ($Force) {
        $argsToPass += " -Force"
    }

    # If running from a file on disk
    if ($Script:RunningFromFile -and [System.IO.File]::Exists($Script:ScriptFilePath)) {
        $psiArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$($Script:ScriptFilePath)`"$argsToPass"
        try {
            if ($IsNonInteractive) {
                $elevProc = Start-Process -FilePath "powershell.exe" -ArgumentList $psiArgs -Verb RunAs -Wait -PassThru
                Cleanup-TempElevationScript
                exit $elevProc.ExitCode
            } else {
                Start-Process -FilePath "powershell.exe" -ArgumentList $psiArgs -Verb RunAs
                Cleanup-TempElevationScript
                exit 0
            }
        } catch {
            Write-Host "  [FAIL] Elevation request was cancelled or denied." -ForegroundColor Red
            if ($IsNonInteractive) { Cleanup-TempElevationScript; exit 1 }
            return $false
        }
    } else {
        # Running in-memory (e.g. irm | iex). Write self script content to a unique temp file.
        try {
            Get-ChildItem -Path $env:TEMP -Filter "*FirewallBlocker_Elevated*.ps1" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        } catch {}
        $tempGuid = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
        $tempScript = Join-Path $env:TEMP "FirewallBlocker_Elevated_$tempGuid.ps1"
        try {
            $scriptPayload = $Script:SelfCode
            if (-not (Test-IsRealScriptContent -Code $scriptPayload)) {
                # Fallback: fetch from repository if self-code unavailable
                try {
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]3072
                } catch {}
                try {
                    $wc = New-Object System.Net.WebClient
                    $webContent = $wc.DownloadString("https://raw.githubusercontent.com/Piyushdas1624/Firewall-Blocker/main/run.ps1")
                    if (Test-IsRealScriptContent -Code $webContent) {
                        $scriptPayload = $webContent
                        $Script:SelfCode = $webContent
                    }
                } catch {}
            }

            if (-not (Test-IsRealScriptContent -Code $scriptPayload)) {
                Write-Host "  [FAIL] Could not elevate: Full script content is unavailable in memory." -ForegroundColor Red
                Write-Host "         Please save FirewallBlocker.ps1 locally or run from an elevated PowerShell console." -ForegroundColor Yellow
                if ($IsNonInteractive) { Cleanup-TempElevationScript; exit 1 }
                return $false
            }

            [System.IO.File]::WriteAllText($tempScript, $scriptPayload, [System.Text.Encoding]::UTF8)
            $psiArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$tempScript`"$argsToPass"
            if ($IsNonInteractive) {
                $elevProc = Start-Process -FilePath "powershell.exe" -ArgumentList $psiArgs -Verb RunAs -Wait -PassThru
                Cleanup-TempElevationScript
                exit $elevProc.ExitCode
            } else {
                Start-Process -FilePath "powershell.exe" -ArgumentList $psiArgs -Verb RunAs
                Cleanup-TempElevationScript
                exit 0
            }
        } catch {
            Write-Host "  [FAIL] Could not initiate elevated launcher: $($_.Exception.Message)" -ForegroundColor Red
            if ($IsNonInteractive) { Cleanup-TempElevationScript; exit 1 }
            return $false
        }
    }
}

# ------------------------------------------------------------------------------
# 5. Firewall Service Health & Healing
# ------------------------------------------------------------------------------
function Test-FirewallService {
    try {
        $svc = Get-Service -Name MpsSvc -ErrorAction Stop
        if ($null -eq $svc) {
            return @{
                Status = "Missing"
                Running = $false
                Message = "Windows Defender Firewall service (MpsSvc) not found."
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
    
    if (-not (Test-IsAdmin)) {
        Write-Host "  [!] Administrator privileges are required to configure and start MpsSvc." -ForegroundColor Red
        if (-not (Assert-Elevated -CurrentTargetDir $Script:CurrentTarget -CurrentAction "RepairService" -IsNonInteractive:$NonInteractive)) {
            return $false
        }
    }

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
            $pConfig = Start-Process -FilePath "sc.exe" -ArgumentList "config MpsSvc start= auto" -NoNewWindow -Wait -PassThru
            $pStart = Start-Process -FilePath "sc.exe" -ArgumentList "start MpsSvc" -NoNewWindow -Wait -PassThru
            Start-Sleep -Seconds 2
            $newSvc = Get-Service -Name MpsSvc -ErrorAction SilentlyContinue
            if ($newSvc -and $newSvc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
                Write-Host "  [OK] Windows Defender Firewall service is now ACTIVE and RUNNING." -ForegroundColor Green
                return $true
            } else {
                Write-Host "  [FAIL] Failed to start service (sc config: $($pConfig.ExitCode), sc start: $($pStart.ExitCode))." -ForegroundColor Red
                return $false
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
        $hasher = $null
        try {
            # SHA256CryptoServiceProvider is FIPS-certified in .NET 2.0/3.5/4.x/Core
            $hasher = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
        } catch {
            try {
                $hasher = New-Object System.Security.Cryptography.SHA256Cng
            } catch {
                $hasher = [System.Security.Cryptography.SHA256]::Create()
            }
        }
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
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    try {
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        $null = $proc.Start()

        $hasAsync = ([System.IO.StreamReader].GetMethod('ReadToEndAsync', [Type]::EmptyTypes) -ne $null)
        if ($hasAsync) {
            $outTask = $proc.StandardOutput.ReadToEndAsync()
            $errTask = $proc.StandardError.ReadToEndAsync()
            if (-not $proc.WaitForExit(15000)) {
                try { $proc.Kill() } catch {}
            }
            # Drain stream tasks completely - wait up to 3000ms after process exit
            if (-not $outTask.Wait(3000)) {
                try { $stdout = $outTask.Result } catch { $stdout = "" }
            } else {
                $stdout = $outTask.Result
            }
            if (-not $errTask.Wait(3000)) {
                try { $stderr = $errTask.Result } catch { $stderr = "" }
            } else {
                $stderr = $errTask.Result
            }
        } else {
            # Synchronous fallback for legacy PowerShell 2.0 / .NET 2.0/3.5
            # Read stderr asynchronously via event handler to prevent pipe buffer deadlock
            $errSb = New-Object System.Text.StringBuilder
            $errHandler = [System.Diagnostics.DataReceivedEventHandler]{
                param($s, $e)
                if ($e.Data) { $null = $errSb.AppendLine($e.Data) }
            }
            $proc.add_ErrorDataReceived($errHandler)
            $proc.BeginErrorReadLine()

            $stdout = $proc.StandardOutput.ReadToEnd()
            if (-not $proc.WaitForExit(15000)) {
                try { $proc.Kill() } catch {}
            }
            try { $proc.WaitForExit() } catch {}
            $stderr = $errSb.ToString()
        }

        $exitCode = -1
        try {
            if ($proc.HasExited) {
                $exitCode = $proc.ExitCode
            }
        } catch {}

        $combined = ($stdout + "`n" + $stderr).Trim()
        return @{
            ExitCode = $exitCode
            Success  = ($exitCode -eq 0)
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

function Format-HumanFirewallError {
    param(
        [string]$RawOutput,
        [int]$ExitCode,
        [string]$ExePath,
        [string]$Direction,
        [string]$RuleName
    )

    $diagnosis = @{
        Component     = "Windows Defender Firewall (netsh)"
        Location      = "Network Subsystem"
        ExePath       = $ExePath
        Direction     = $Direction
        RuleName      = $RuleName
        RawMessage    = $RawOutput
        RootCause     = "Unknown network shell error."
        ActionableFix = "Verify Windows Firewall status and try again."
    }

    if ($RawOutput -match "(?i)(requires elevation|access is denied|run as administrator|zugriff verweigert|erh[o\u00F6]hte|n[e\u00E9]cessite|acc[e\u00E8]s refus|requiere elevaci|acceso denegado|\u043F\u043E\u0432\u044B\u0448\u0435\u043D\u0438|\u63D0\u5347|\u62D2\u7EDD\u8BBF\u95EE|\uAC70\uBD80|0x5\b)") {
        $diagnosis.Location = "Windows Security Token (UAC)"
        $diagnosis.RootCause = "Administrator privileges were lost, revoked, or denied."
        $diagnosis.ActionableFix = "Right-click PowerShell or Terminal and select 'Run as administrator'."
    } elseif ($RawOutput -match "(?i)(contact the Windows Firewall service|service has not been started|Dienst wurde nicht gestartet|n'a pas [e\u00E9]t[e\u00E9] d[e\u00E9]marr|no se ha iniciado el servicio|\u0421\u043B\u0443\u0436\u0431\u0430 \u043D\u0435 \u0437\u0430\u043F\u0443\u0449\u0435\u043D\u0430|\u670D\u52A1\u672A\u542F\u52A8|0x6D9|1753|RPC)") {
        $diagnosis.Location = "Windows Service Manager (MpsSvc)"
        $diagnosis.RootCause = "The Windows Defender Firewall service (MpsSvc) is stopped, disabled, or RPC is unreachable."
        $diagnosis.ActionableFix = "Press [9] in the menu or run 'services.msc' and start the 'Windows Defender Firewall' service."
    } elseif ($RawOutput -match "(?i)(Group Policy|policy does not allow|blocked by policy|Gruppenrichtlinie|strat[e\u00E9]gie de groupe|directiva de grupo|\u0413\u0440\u0443\u043F\u043F\u043E\u0432|\u7EC4\u7B56\u7565|\uADF8\uB8F9\s*\uC815\uCC45)") {
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
        $items = @(Get-ChildItem -LiteralPath $PathToScan -Filter "*.exe" -Recurse -Force -ErrorAction SilentlyContinue |
                   Where-Object { -not $_.PSIsContainer -and $_.Extension -match '^\.exe$' })
        return $items
    } catch {
        return @()
    }
}

function Test-ExecutableRuleStatus {
    param(
        [string]$ExePath,
        [string]$ExeName
    )
    $cleanName = $ExeName.Replace('"', '')
    $hash = Get-PortableHash -InputString $ExePath
    $inRule = "[FWB-IN] $cleanName ($hash)"
    $outRule = "[FWB-OUT] $cleanName ($hash)"
    
    # 1. Prefer language-neutral NetSecurity cmdlets if available (PowerShell 3.0+ / Windows 8+)
    $hasNetSecurity = $false
    try {
        if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
            $hasNetSecurity = $true
        }
    } catch {}

    if ($hasNetSecurity) {
        $checkRuleCim = {
            param([string]$ruleDisplayName, [string]$programPath)
            try {
                $rules = @(Get-NetFirewallRule -DisplayName $ruleDisplayName -ErrorAction SilentlyContinue)
                if ($rules.Count -eq 0) {
                    $rules = @(Get-NetFirewallRule -Name $ruleDisplayName -ErrorAction SilentlyContinue)
                }
                foreach ($r in $rules) {
                    $isEnabled = ($r.Enabled -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::True -or $r.Enabled -eq "True" -or $r.Enabled -eq 1)
                    if ($isEnabled) {
                        $act = $r.Action.ToString()
                        if ($act -eq "Block" -or $r.Action -eq 4 -or $r.Action -eq 2) {
                            return $true
                        }
                    }
                }
            } catch {}
            return $false
        }

        $inBlocked = (& $checkRuleCim $inRule $ExePath)
        if (-not $inBlocked) {
            $inBlocked = (& $checkRuleCim "[FWB-IN] $cleanName" $ExePath)
        }
        if (-not $inBlocked) {
            $inBlocked = (& $checkRuleCim "[FolderBlock-IN] $cleanName" $ExePath)
        }

        $outBlocked = (& $checkRuleCim $outRule $ExePath)
        if (-not $outBlocked) {
            $outBlocked = (& $checkRuleCim "[FWB-OUT] $cleanName" $ExePath)
        }
        if (-not $outBlocked) {
            $outBlocked = (& $checkRuleCim "[FolderBlock-OUT] $cleanName" $ExePath)
        }

        return @{
            InBlocked  = $inBlocked
            OutBlocked = $outBlocked
        }
    }

    # 2. Netsh Fallback for Windows 7 SP1 / PS 2.0 or environments without NetSecurity
    $checkIn = Invoke-Netsh -Arguments "advfirewall firewall show rule name=`"$inRule`""
    $checkOut = Invoke-Netsh -Arguments "advfirewall firewall show rule name=`"$outRule`""
    
    # Multilingual token matchers (EN, DE, FR, ES, IT, PT, PL, TR, NL, RU, ZH-Hans, ZH-Hant, JA, KO)
    $blockActionRegex = '(?i)(?:Action|Aktion|Acci[o\u00F3]n|Azione|A[c\u00E7][a\u00E3]o|Dzia[l\u0142]anie|Eylem|Actie|\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u0435|\u64CD\u4F5C|\u52D5\u4F5C|\uC791\uC5C5|\uB3D9\uC791)[\s:\uFF1A]+(?:Block|Bloqu|Blockier|Blocca|Blok|Zablokuj|Engelle|Blokkeren|\u0411\u043B\u043E\u043A\u0438\u0440|\u963B\u6B62|\u5C01\u9396|\u30D6\u30ED\u30C3\u30AF|\uCC28\uB2E8)'
    $allowActionRegex = '(?i)(?:Action|Aktion|Acci[o\u00F3]n|Azione|A[c\u00E7][a\u00E3]o|Dzia[l\u0142]anie|Eylem|Actie|\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u0435|\u64CD\u4F5C|\u52D5\u4F5C|\uC791\uC5C5|\uB3D9\uC791)[\s:\uFF1A]+(?:Allow|Zulassen|Autoris|Permit|Consenti|Zezwalaj|Izin|Toestaan|\u0420\u0430\u0437\u0440\u0435\u0448|\u5141\u8BB8|\u5141\u8A31|\u8A31\u53EF|\uD5C8\uC6A9)'
    $ruleExistsRegex  = '(?i)(?:Rule Name|Regelname|Nom de r[e\u00E8\u00E9]gle|Nombre de regla|Nome regola|Nazwa regu[l\u0142]y|Kural Ad[i\u0131]|Regelnaam|\u0418\u043C\u044F \u043F\u0440\u0430\u0432\u0438\u043B\u0430|\u89C4\u5219\u540D\u79F0|\u898F\u5247\u540D|\uADDC\uCE59\s*\uC774\uB984|Name)[\s:\uFF1A]+'
    $disabledRegex    = '(?i)(?:Enabled|Aktiviert|Activ[e\u00E9]|Habilitado|Abilitato|W[l\u0142][a\u0105]czone|Etkin|Ingeschakeld|\u0412\u043A\u043B\u044E\u0447\u0435\u043D\u043E|\u5DF2\u542F\u7528|\u5DF2\u555F\u7528|\u6709\u52B9|\uC0AC\uC6A9|\uD65C\uC131\uD654)[\s:\uFF1A]+(?:No|Nein|Non|Nie|Hay[i\u0131]r|Nee|\u041D\u0435\u0442|\u5426|\u3044\u3044\u3048|\uC544\uB2C8\uC694|False|0)'

    $isRuleBlocked = {
        param($res)
        if (-not $res.Success) { return $false }
        $txt = $res.Output
        if ($txt -match $disabledRegex) { return $false }
        if ($txt -match $blockActionRegex) { return $true }
        if ($txt -match $allowActionRegex) { return $false }
        # Language-neutral existence fallback: if netsh exited 0 and rule name exists, it is a blocked rule created by this tool
        if ($txt -match $ruleExistsRegex -or ($res.Success -and $txt.Length -gt 10)) { return $true }
        return $false
    }

    $inBlocked = (& $isRuleBlocked $checkIn)
    $outBlocked = (& $isRuleBlocked $checkOut)

    # Also check batch format rules (without hash)
    if (-not $inBlocked) {
        $batchIn = Invoke-Netsh -Arguments "advfirewall firewall show rule name=`"[FWB-IN] $cleanName`""
        if (& $isRuleBlocked $batchIn) { $inBlocked = $true }
    }
    if (-not $outBlocked) {
        $batchOut = Invoke-Netsh -Arguments "advfirewall firewall show rule name=`"[FWB-OUT] $cleanName`""
        if (& $isRuleBlocked $batchOut) { $outBlocked = $true }
    }

    # Also check legacy rule formats
    if (-not $inBlocked) {
        $legacyIn = Invoke-Netsh -Arguments "advfirewall firewall show rule name=`"[FolderBlock-IN] $cleanName`""
        if (& $isRuleBlocked $legacyIn) { $inBlocked = $true }
    }
    if (-not $outBlocked) {
        $legacyOut = Invoke-Netsh -Arguments "advfirewall firewall show rule name=`"[FolderBlock-OUT] $cleanName`""
        if (& $isRuleBlocked $legacyOut) { $outBlocked = $true }
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
        if (-not (Select-DirectoryIfEmpty)) { return $false }
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
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return $false }
        exit 2
    }

    if (-not (Assert-Elevated -CurrentTargetDir $Dir -CurrentAction "Block$Mode" -IsNonInteractive:$NonInteractive)) {
        if ($NonInteractive) { exit 1 }
        return $false
    }

    if (-not (Ensure-FirewallServiceRunning)) {
        Write-Host "  [ABORT] Cannot proceed without Windows Defender Firewall service." -ForegroundColor Red
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return $false }
        exit 3
    }

    Write-Host ""
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  BLOCKING OPERATION: Applying Windows Firewall Rules (Mode: $Mode)" -ForegroundColor White
    Write-Host "  Target: $Dir" -ForegroundColor Yellow
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Cyan

    $exes = @(Get-TargetExecutables -PathToScan $Dir)
    if ($exes.Count -eq 0) {
        Write-Host "  [i] No .exe files were found in target folder." -ForegroundColor Yellow
        Write-Host "      Path: $Dir" -ForegroundColor DarkGray
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return $true }
        return $true
    }

    # Safeguard check for sensitive directory (User Profile root) or large batch (> 100 exes)
    $isUserRoot = Test-IsUserProfileRoot -PathToCheck $Dir
    $isLargeTarget = ($exes.Count -gt 100)

    if ($isUserRoot -or $isLargeTarget) {
        Write-Host ""
        Write-Host "  ==========================================================================" -ForegroundColor Yellow
        Write-Host "  [CONFIRMATION REQUIRED] POTENTIALLY SENSITIVE OR LARGE TARGET!             " -ForegroundColor White
        Write-Host "  ==========================================================================" -ForegroundColor Yellow
        if ($isUserRoot) {
            Write-Host "  [!] WARNING: Target is a User Profile directory: $Dir" -ForegroundColor Yellow
            Write-Host "      Blocking this folder will affect apps in AppData, Local, and Desktop." -ForegroundColor Yellow
        }
        if ($isLargeTarget) {
            Write-Host "  [!] WARNING: Target contains $($exes.Count) executables (> 100)." -ForegroundColor Yellow
        }
        Write-Host "  ==========================================================================" -ForegroundColor Yellow

        if ($NonInteractive) {
            if (-not $Force) {
                Write-Host "  [ABORT] Blocking a User Profile root or > 100 executables in NonInteractive mode requires -Force." -ForegroundColor Red
                Cleanup-TempElevationScript
                exit 1
            }
        } else {
            if (-not $Force) {
                $confirmBlock = Read-Host "  Are you SURE you want to block all $($exes.Count) executable(s) in this folder? [Y/N]"
                if ($null -eq $confirmBlock -or $confirmBlock -notmatch '^[Yy]') {
                    Write-Host "  [CANCEL] Block operation aborted by user." -ForegroundColor Yellow
                    Read-Host "`n  Press ENTER to return to menu..."
                    return $true
                }
            }
        }
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
            $null = Invoke-Netsh -Arguments "advfirewall firewall delete rule name=`"[FWB-IN] $($exeName.Replace('"', ''))`" program=`"$exePath`""
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
            $null = Invoke-Netsh -Arguments "advfirewall firewall delete rule name=`"[FWB-OUT] $($exeName.Replace('"', ''))`" program=`"$exePath`""
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
    
    return ($failRules -eq 0)
}

function Invoke-UnblockOperation {
    param([string]$Dir)

    if ([string]::IsNullOrEmpty($Dir)) {
        if (-not (Select-DirectoryIfEmpty)) { return $false }
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
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return $false }
        exit 2
    }

    if (-not (Assert-Elevated -CurrentTargetDir $Dir -CurrentAction "UnblockDir" -IsNonInteractive:$NonInteractive)) {
        if ($NonInteractive) { exit 1 }
        return $false
    }

    Write-Host ""
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  UNBLOCKING OPERATION: Removing FirewallBlocker Rules" -ForegroundColor White
    Write-Host "  Target: $Dir" -ForegroundColor Yellow
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Cyan

    $exes = @(Get-TargetExecutables -PathToScan $Dir)
    if ($exes.Count -eq 0) {
        Write-Host "  [i] No .exe files were found in target folder." -ForegroundColor Yellow
        Write-Host "      Path: $Dir" -ForegroundColor DarkGray
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return $true }
        return $true
    }

    Write-Host "  Discovered $($exes.Count) executable(s) to process.`n" -ForegroundColor Cyan

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

        $rulesToDelete = @(
            @{ Name = $inRuleName; Program = $null },
            @{ Name = $outRuleName; Program = $null },
            @{ Name = "[FWB-IN] $($exeName.Replace('"', ''))"; Program = $exePath },
            @{ Name = "[FWB-OUT] $($exeName.Replace('"', ''))"; Program = $exePath },
            @{ Name = "[FolderBlock-IN] $exeName"; Program = $exePath },
            @{ Name = "[FolderBlock-OUT] $exeName"; Program = $exePath }
        )

        foreach ($r in $rulesToDelete) {
            $rName = $r.Name
            $delArgs = "advfirewall firewall delete rule name=`"$rName`""
            if ($r.Program) {
                $delArgs += " program=`"$($r.Program)`""
            }
            $delRes = Invoke-Netsh -Arguments $delArgs
            if ($delRes.Success -and $delRes.Output -notmatch '(?i)(No rules match|Keine Regeln|Aucune r[e\u00E8\u00E9]gle|Ninguna regla|\u0421\u043E\u0432\u043F\u0430\u0434\u0430\u044E\u0449\u0438\u0445|\u6CA1\u6709\u4E0E\u6307\u5B9A|\u6CA1\u6709\u89C4\u5219|\u4E00\u81F4\u3059\u308B\u898F\u5247|\uC77C\uCE58\uD558\uB294\s*\uADDC\uCE59|0 rule\(s\)|0 Regel\(n\))') {
                if ($delRes.Output -match '(?i)(?:Deleted\s+|gel[o\u00F6]scht|supprim[e\u00E9]\(s\)|eliminaron\s+|\u043F\u0440\u0430\u0432\u0438\u043B|\u89C4\u5219|\u898F\u5247|\uADDC\uCE59\s*)(\d+)' -or $delRes.Output -match '(\d+)\s*(?:rule|regel|r[e\u00E8\u00E9]gle|regla)') {
                    $deletedRules += [int]$matches[1]
                } else {
                    $deletedRules++
                }
            }
        }
    }

    $duration = [System.DateTime]::Now - $startTime

    Write-Host ""
    Write-Host "  ==========================================================================" -ForegroundColor Cyan
    Write-Host "                        UNBLOCK COMPLETE SUMMARY                            " -ForegroundColor White
    Write-Host "  ==========================================================================" -ForegroundColor Cyan
    Write-Host ("  Target Directory      : {0}" -f $Dir) -ForegroundColor Yellow
    Write-Host ("  Executables Scanned   : {0}" -f $processedCount) -ForegroundColor White
    Write-Host ("  Rules Cleaned Up      : {0}" -f $deletedRules) -ForegroundColor Green
    Write-Host ("  Elapsed Time          : {0:N2} seconds" -f $duration.TotalSeconds) -ForegroundColor DarkCyan
    Write-Host "  ==========================================================================" -ForegroundColor Cyan

    if (-not $NonInteractive) {
        Read-Host "`n  Press ENTER to return to menu..."
    }
    return $true
}

function Invoke-UnblockAllSystem {
    if (-not (Assert-Elevated -CurrentAction "UnblockAll" -IsNonInteractive:$NonInteractive -Force:$Force)) {
        if ($NonInteractive) { exit 1 }
        return $false
    }

    Write-Host ""
    Write-Host "  ==========================================================================" -ForegroundColor Yellow
    Write-Host "  GLOBAL PURGE: Scan & Clean All FirewallBlocker Rules Across System       " -ForegroundColor White
    Write-Host "  ==========================================================================" -ForegroundColor Yellow
    Write-Host "  Scanning Windows Defender Firewall for rules created by this tool..." -ForegroundColor Cyan

    $allRules = Invoke-Netsh -Arguments "advfirewall firewall show rule name=all"
    if (-not $allRules.Success) {
        Write-Host "  [FAIL] Could not query firewall rules: $($allRules.Output)" -ForegroundColor Red
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return $false }
        if ($NonInteractive) { exit 1 }
        return $false
    }

    $matchedRuleNames = New-Object System.Collections.ArrayList
    $lines = $allRules.Output -split "`r?`n"
    foreach ($line in $lines) {
        if ($line -match '(?i)(?:Rule Name|Regelname|Nom de r[e\u00E8\u00E9]gle|Nombre de regla|Nome regola|\u0418\u043C\u044F \u043F\u0440\u0430\u0432\u0438\u043B\u0430|\u89C4\u5219\u540D\u79F0|\u898F\u5247\u540D|\uADDC\uCE59\s*\uC774\uB984|Name)[\s:\uFF1A]+(\[(?:FWB|FolderBlock)-(?:IN|OUT)\].+)') {
            $rName = $matches[1].Trim()
            if (-not $matchedRuleNames.Contains($rName)) {
                $null = $matchedRuleNames.Add($rName)
            }
        } elseif ($line -match '[:\uFF1A]\s*(\[(?:FWB|FolderBlock)-(?:IN|OUT)\].+)' -and $line -notmatch '(?i)(Description|Beschreibung|Descripci[o\u00F3]n|Descrizione|\u041E\u043F\u0438\u0441\u0430\u043D\u0438\u0435|\u63CF\u8FF0|\u8AAC\u660E|\uC124\uBA85)') {
            $rName = $matches[1].Trim()
            if (-not $matchedRuleNames.Contains($rName)) {
                $null = $matchedRuleNames.Add($rName)
            }
        }
    }

    if ($matchedRuleNames.Count -eq 0) {
        Write-Host "  [OK] No FirewallBlocker rules were found on this system." -ForegroundColor Green
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return $true }
        return $true
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
    if (-not $NonInteractive -and -not $Force) {
        $confirm = Read-Host "  Are you SURE you want to delete all $($matchedRuleNames.Count) rules? [Y/N]"
        if ($confirm -notmatch '^[Yy]') {
            Write-Host "  [CANCEL] Deletion aborted by user." -ForegroundColor Yellow
            Read-Host "`n  Press ENTER to return to menu..."
            return $true
        }
    }

    $deleted = 0
    foreach ($rName in $matchedRuleNames) {
        $res = Invoke-Netsh -Arguments "advfirewall firewall delete rule name=`"$rName`""
        if ($res.Success) { $deleted++ }
    }

    Write-Host "  [OK] Successfully removed $deleted rule(s) from Windows Defender Firewall." -ForegroundColor Green
    if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..." }
    return $true
}

function Invoke-ScanAudit {
    param([string]$Dir)

    if ([string]::IsNullOrEmpty($Dir)) {
        if (-not (Select-DirectoryIfEmpty)) { return $false }
        $Dir = $Script:CurrentTarget
    }

    Write-Host ""
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  SCAN & AUDIT: Directory Executables and Firewall Status (Dry Run)" -ForegroundColor White
    Write-Host "  Target: $Dir" -ForegroundColor Yellow
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Cyan

    $exes = @(Get-TargetExecutables -PathToScan $Dir)
    if ($exes.Count -eq 0) {
        Write-Host "  [i] No .exe files were found in target folder." -ForegroundColor Yellow
        if (-not $NonInteractive) { Read-Host "`n  Press ENTER to return to menu..."; return $true }
        return $true
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
    return $true
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

# If requested to only export functions (used by unit tests), return immediately
if ($ExportFunctionsOnly) {
    return
}

# Non-interactive CLI Execution Dispatch
if (-not [string]::IsNullOrEmpty($Action)) {
    $actionSuccess = $true
    switch -Regex ($Action) {
        '^(BlockAll|BlockBoth|Both)$'              { $actionSuccess = Invoke-BlockOperation -Dir $Script:CurrentTarget -Mode "Both" }
        '^(BlockOutbound(Only)?|Outbound)$'       { $actionSuccess = Invoke-BlockOperation -Dir $Script:CurrentTarget -Mode "OutboundOnly" }
        '^(BlockInbound(Only)?|Inbound)$'         { $actionSuccess = Invoke-BlockOperation -Dir $Script:CurrentTarget -Mode "InboundOnly" }
        '^(UnblockDir|Unblock)$'                   { $actionSuccess = Invoke-UnblockOperation -Dir $Script:CurrentTarget }
        '^(UnblockAll|Purge)$'                     { $actionSuccess = Invoke-UnblockAllSystem }
        '^(Scan|Audit|List)$'                      { $actionSuccess = Invoke-ScanAudit -Dir $Script:CurrentTarget }
        '^(RepairService|RestartService|Repair|FixService)$' { $actionSuccess = Ensure-FirewallServiceRunning }
        default {
            Write-Host "Unknown Action: $Action. Valid actions: BlockBoth, BlockOutbound, BlockInbound, UnblockDir, UnblockAll, Scan, RepairService." -ForegroundColor Red
            Cleanup-TempElevationScript
            exit 1
        }
    }

    if ($NonInteractive) {
        Cleanup-TempElevationScript
        if ($actionSuccess) {
            exit 0
        } else {
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
    if ($null -eq $choice) {
        Write-Host "`n  [EOF] Standard input closed. Exiting FirewallBlocker." -ForegroundColor DarkCyan
        Cleanup-TempElevationScript
        break
    }

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
            if (-not (Assert-Elevated -CurrentTargetDir $Script:CurrentTarget -CurrentAction "RepairService" -IsNonInteractive:$NonInteractive)) {
                Start-Sleep -Seconds 2
                continue
            }
            $svcRes = Ensure-FirewallServiceRunning
            if ($svcRes) { 
                Write-Host "  [OK] Service is active and ready." -ForegroundColor Green 
            } else {
                Write-Host "  [FAIL] Failed to start Windows Defender Firewall service (MpsSvc)." -ForegroundColor Red
            }
            Start-Sleep -Seconds 2
        }
        "0" { 
            Write-Host "`n  Exiting FirewallBlocker. Goodbye!`n" -ForegroundColor Cyan
            Cleanup-TempElevationScript
            exit 0
        }
        default {
            Write-Host "  [!] Invalid choice: '$choice'. Please select a number between 0 and 9." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
        }
    }
}
