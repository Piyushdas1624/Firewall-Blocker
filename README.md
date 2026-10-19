<p align="center">
  <img src="https://img.shields.io/badge/🔥_FirewallBlocker-Universal_Windows_Firewall_Suite-ef4444?style=for-the-badge&labelColor=0f172a" alt="FirewallBlocker">
</p>

<p align="center">
  <strong>Zero dependencies. Zero slop. Universal Windows Firewall control.</strong><br>
  Recursively block, unblock, and audit any folder of executables from Windows 7 SP1 to Windows 11.
</p>

<p align="center">
  <a href="https://github.com/Piyushdas1624/Firewall_bat"><img src="https://img.shields.io/badge/GitHub-Piyushdas1624%2FFirewall__bat-181717?style=flat-square&logo=github" alt="GitHub Repository"></a>
  <img src="https://img.shields.io/badge/Platform-Windows%207%20SP1%20%7C%208%20%7C%208.1%20%7C%2010%20%7C%2011%20%7C%20Server-0ea5e9?style=flat-square&logo=windows" alt="Platform">
  <img src="https://img.shields.io/badge/PowerShell-2.0%20to%207.x%2B-2563eb?style=flat-square&logo=powershell&logoColor=white" alt="PowerShell 2.0+">
  <img src="https://img.shields.io/badge/Engine-Native%20netsh%20%2B%20Batch%20Fallback-10b981?style=flat-square" alt="Native Engine">
  <img src="https://img.shields.io/badge/License-MIT-10b981?style=flat-square" alt="MIT License">
  <img src="https://img.shields.io/badge/Dependencies-Zero%20Install-f59e0b?style=flat-square" alt="Zero Dependencies">
</p>

---

## ❓ Why I Built This

I was completely fed up with the native **Windows Defender Firewall** GUI (`wf.msc`). 

Whenever you want to block an application, isolate a game directory, or stop telemetry and DRM updates from calling home, you have to open `wf.msc`, click *New Rule*, browse for an `.exe`, configure outbound blocking, repeat the same steps for inbound blocking, and then do that **30+ times** for every single executable scattered across nested subdirectories.

Most community batch files and scripts online suffer from serious flaws:
- ❌ **Broken on Windows 7 / Server 2008 R2** because they rely on modern `NetSecurity` PowerShell cmdlets introduced in PowerShell 3.0+.
- ❌ **Mangled by paths with special characters** (`&`, spaces, brackets, or exclamation marks `!`) due to sloppy CMD delayed expansion.
- ❌ **No system protection** — one wrong run can accidentally block `C:\Windows\System32` and knock out Windows Update and network connectivity.
- ❌ **Cryptic error dumps** — when `netsh` fails, you get raw hex codes (`0x6D9`, `1753`) with zero explanation of *where* or *why* it failed.

I built **FirewallBlocker** to eliminate this friction forever: a universal, zero-install, battle-tested tool that works out-of-the-box on every Windows version from **Windows 7 SP1 to Windows 11**, featuring **1-click web launching** (MAS / `get.activated.win` style), **human-readable color-coded error diagnostics**, and **ironclad system safety guardrails**.

---

## ⚡ Speed & Feature Comparison

| Feature / Metric | Traditional Windows GUI (`wf.msc`) / Generic Scripts | 🔥 FirewallBlocker |
|---|---|---|
| **Directory Recursive Blocking** | ❌ Manual rule creation for every single `.exe` file | ⚡ **1-Click recursive scan & block (IN + OUT)** |
| **OS Compatibility** | ⚠️ Mostly broken on Windows 7 / Server 2008 R2 | ✅ **Universal: Windows 7 SP1 through Windows 11** |
| **Execution Method** | ❌ Download ZIP, extract, unblock policies, configure | 🚀 **One-liner web launch (`irm ... \| iex`)** |
| **Offline / Restricted Environments** | ❌ Crashes without PowerShell 5.1 | ✅ **Hardened native CMD batch fallback (`FirewallBlocker.bat`)** |
| **Special Character Handling** | ❌ Stripped or broken by delayed expansion (`!`, `&`, `[]`) | ✅ **100% path-safe via isolated expansion & literal quoting** |
| **System Directory Safety** | ❌ Easy to accidentally target `C:\Windows\System32` | 🛑 **Critical safety guard blocks OS directories (`ExitCode 2`)** |
| **Failure Localization** | ❌ Raw cryptic error messages (`0x6D9`, `Access Denied`) | 🔍 **Pinpoints: `Where`, `Which`, `Reason`, and actionable `Fix`** |
| **Rule Collision Prevention** | ❌ Identical executable names overwrite each other | 🔒 **Deterministic FIPS-compliant SHA256 path hashes** |

---

## 🚀 Quick Start: One-Liner Web Launch

Launch directly in PowerShell without manually cloning or extracting any files:

### 1. Standard PowerShell (Windows 8 / 10 / 11)
Open PowerShell (Standard User or Administrator) and run:
```powershell
irm https://raw.githubusercontent.com/Piyushdas1624/Firewall_bat/main/run.ps1 | iex
```

### 2. Cloudflare 1.1.1.1 DNS-over-HTTPS (DoH)
Bypasses ISP DNS interception or regional censorship:
```powershell
iex (curl.exe -s --doh-url https://1.1.1.1/dns-query https://raw.githubusercontent.com/Piyushdas1624/Firewall_bat/main/run.ps1 | Out-String)
```

### 3. Windows 7 SP1 / Legacy PowerShell 2.0 / .NET 3.5
Works cleanly on vanilla Windows 7 SP1 machines with automated TLS 1.2 negotiation:
```powershell
powershell -nop -ep bypass -c "[Net.ServicePointManager]::SecurityProtocol=3072; iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Piyushdas1624/Firewall_bat/main/run.ps1'))"
```

### 4. Command Prompt (`cmd.exe`)
Paste directly into an ordinary Command Prompt window:
```cmd
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=3072; iex (irm 'https://raw.githubusercontent.com/Piyushdas1624/Firewall_bat/main/run.ps1')"
```

---

## 💾 Local & Offline Execution

If you prefer to clone or download the repository locally:

1. **Option A (Batch Launcher):** Double-click `FirewallBlocker.bat` (or `text.bat`).
2. **Option B (PowerShell):** Right-click `FirewallBlocker.ps1` → **Run with PowerShell**, or in terminal:
   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\FirewallBlocker.ps1
   ```
3. **Drag & Drop:** You can drag and drop any folder from File Explorer directly into the console window to instantly set your target directory.

---

## 🖥️ Interactive Console Interface

```text
==============================================================================
         FIREWALL BLOCKER - RECURSIVE WINDOWS FIREWALL MANAGER                
       Windows 7 / 8 / 8.1 / 10 / 11 | Production Grade | Version 2.1        
==============================================================================
  Target Root Folder : D:\Games\ActionRPG
  Discovered .EXEs   : 14 executable(s) found
  Firewall Service   : RUNNING (MpsSvc)
  Admin Privileges   : ELEVATED (Administrator)
==============================================================================
  FIREWALL BLOCK OPTIONS:
   [1]  BLOCK all .exes (Inbound + Outbound)   - Complete Network Isolation
   [2]  BLOCK all .exes (Outbound Only)        - Stop Outgoing / Telemetry / DRM
   [3]  BLOCK all .exes (Inbound Only)         - Block Incoming Connection Requests

  MANAGEMENT & AUDIT OPTIONS:
   [4]  UNBLOCK target folder                  - Remove rules created for this folder
   [5]  UNBLOCK ALL system rules               - Clean up all FirewallBlocker rules on PC
   [6]  SCAN / AUDIT target folder (Dry Run)   - Inspect rule status without changes

  CONFIGURATION & TOOLS:
   [7]  CHANGE target directory                - Pick or drag-and-drop a new folder
   [8]  OPEN Windows Firewall GUI (wf.msc)     - Inspect native firewall rules
   [9]  RESTART / REPAIR Firewall Service      - Auto-configure & ensure MpsSvc health

   [0]  Exit
==============================================================================
```

---

## ✨ Key Features & Production Hardening

- ⚡ **1-Click Recursive Folder Blocking**: Automatically discovers all `.exe` files in any nested folder structure and applies Inbound, Outbound, or bidirectional firewall block rules.
- 🌐 **Universal Windows Spectrum**: Compatible with Windows 7 SP1, 8, 8.1, 10, 11, and Windows Server (2008 R2–2025) across PowerShell 2.0 through PowerShell 7.4+.
- 🔍 **Human-Readable Diagnostics & Failure Localization**: Replaces cryptic `netsh` error dumps with a color-coded diagnostic analyzer pinpointing Subsystem (`Where`), Component (`Which`), Root Cause (`Why`), and actionable 1-click Fixes (`How`).
- 🛑 **Critical Safety Guardrails**: Prevents catastrophic user accidents by automatically refusing to target `C:\Windows`, `System32`, `SysWOW64`, root drives (`C:\`), or `Windows Defender` folders (`ExitCode 2`).
- 🔒 **FIPS-Compliant Deterministic Hashing**: Rule identifiers use FIPS-approved SHA256 path hashes (e.g. `[FWB-IN] app.exe (7A4B1C2D)`), eliminating rule collisions across duplicate executable names.
- 🛡️ **Safe Default Working Directory**: Avoids accidentally targeting `C:\Windows\System32` when invoked from an elevated admin command prompt or web one-liner.
- 📁 **False-Positive Directory Filtering**: Folders ending with `.exe` (e.g. `Game.exe/`) are strictly filtered out using `-not $_.PSIsContainer`.
- 🏥 **Firewall Service Healing**: Detects if `MpsSvc` (Windows Defender Firewall) is stopped or disabled, providing automatic service configuration and startup via `sc.exe`.
- 🧪 **Dry-Run Audit Mode**: Inspects the firewall status of all executables in a directory without altering rules.
- 🧹 **Global Rule Purge**: 1-click cleanup to find and wipe all rules created by FirewallBlocker across your entire machine.
- 🖲️ **Hardened CMD Batch Fallback**: Includes a standalone CMD batch engine in `FirewallBlocker.bat` with isolated delayed expansion safe against paths containing exclamation marks (`!`).

---

## 🔍 Human-Readable Error Diagnostics

When a rule fails due to system policies, stopped services, or permissions, FirewallBlocker provides plain-English failure localization instead of raw error codes:

```text
  [-] OUTBOUND : [FAIL]
      Where  : Windows Service Manager (MpsSvc)
      Reason : The Windows Defender Firewall service (MpsSvc) is stopped or RPC is unreachable.
      Fix    : Press [9] in the menu or run 'services.msc' and start the 'Windows Defender Firewall' service.
```

Or when hitting Windows MAX_PATH limits:
```text
  [-] INBOUND  : [FAIL]
      Where  : Win32 File Subsystem (MAX_PATH)
      Reason : The executable file path (268 chars) exceeds the Windows 260-character limit.
      Fix    : Move the target folder to a shorter path (e.g. C:\Games) or enable Win32 Long Paths.
```

---

## 🤖 Headless / CLI Automation (CI/CD & Scripting)

Run operations silently without user prompts using `-Action` and `-NonInteractive`:

```powershell
# Block both Inbound & Outbound
powershell -ExecutionPolicy Bypass -File .\FirewallBlocker.ps1 -TargetDir "D:\MyApp" -Action BlockBoth -NonInteractive

# Block Outbound only
powershell -ExecutionPolicy Bypass -File .\FirewallBlocker.ps1 -TargetDir "D:\MyApp" -Action BlockOutbound -NonInteractive

# Unblock target directory
powershell -ExecutionPolicy Bypass -File .\FirewallBlocker.ps1 -TargetDir "D:\MyApp" -Action UnblockDir -NonInteractive

# Scan and print audit summary (Dry Run)
powershell -ExecutionPolicy Bypass -File .\FirewallBlocker.ps1 -TargetDir "D:\MyApp" -Action Scan -NonInteractive
```

### Exit Codes:
| Code | Meaning |
|:---:|:---|
| `0` | Operation succeeded cleanly. |
| `1` | General error or invalid arguments. |
| `2` | Critical safety block (attempted to target a protected Windows system path). |
| `3` | Windows Defender Firewall service (`MpsSvc`) is stopped or unavailable. |

---

## 🧪 Verification & Automated Testing

FirewallBlocker includes an automated 10-point test suite in `tests/test_suite.ps1`. To run it locally:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\test_suite.ps1
```

All 10 tests validate:
1. `FirewallBlocker.ps1` AST syntax validity (PS 2.0 to 7.x compatible).
2. `run.ps1` AST syntax validity.
3. Byte-for-byte parity between `FirewallBlocker.ps1` and `run.ps1`.
4. Directory scanning with complex special characters (`&`, `()`, `[]`, `!`, spaces) and folder `.exe` exclusion.
5. `text.bat` & `FirewallBlocker.bat` delegation and parameter passing.
6. System folder safety guardrails (`C:\Windows` and `C:\Windows\System32` rejected with `ExitCode 2`).
7. Empty directory handling.
8. Invalid action parameter rejection.
9. FIPS-compliant SHA256 portable hash determinism and case-insensitivity.
10. Human-readable error diagnostic analyzer accuracy.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
