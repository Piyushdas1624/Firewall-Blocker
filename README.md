# 🔥 FirewallBlocker — Universal Windows Firewall Folder Blocker

[![Platform](https://img.shields.io/badge/Platform-Windows%207%20%7C%208%20%7C%208.1%20%7C%2010%20%7C%2011-blue?logo=windows)](https://github.com/Piyushdas1624/Firewall_bat)
[![PowerShell](https://img.shields.io/badge/PowerShell-2.0%20to%207.x%2B-blue?logo=powershell)](https://github.com/Piyushdas1624/Firewall_bat)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-success)](#)

A high-performance, robust, and universal tool to recursively block and unblock all executable files (`.exe`) in any target folder using native **Windows Defender Firewall** (`netsh advfirewall`). 

Engineered for **Windows 7 through Windows 11** and **Windows Server (2008 R2 – 2025)** with zero external dependencies, human-readable color-coded diagnostics, dry-run auditing, system directory safety guards, and one-liner web execution.

---

## ⚡ Quick Start: One-Liner Web Launch

Run directly in PowerShell without manually cloning or downloading files (in the spirit of MAS / `get.activated.win`):

### 1. Standard PowerShell (Windows 8 / 10 / 11)
Open PowerShell (as Administrator or Standard User) and run:
```powershell
irm https://raw.githubusercontent.com/Piyushdas1624/Firewall_bat/main/run.ps1 | iex
```

### 2. Curl with Cloudflare 1.1.1.1 DNS-over-HTTPS (DoH)
Bypasses DNS poisoning, ISP interception, or regional blocking:
```powershell
iex (curl.exe -s --doh-url https://1.1.1.1/dns-query https://raw.githubusercontent.com/Piyushdas1624/Firewall_bat/main/run.ps1 | Out-String)
```

### 3. Windows 7 / Legacy PowerShell 2.0 / .NET 3.5
Works out-of-the-box on older Windows 7 SP1 machines with TLS 1.2 auto-negotiation:
```powershell
powershell -nop -ep bypass -c "[Net.ServicePointManager]::SecurityProtocol=3072; iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Piyushdas1624/Firewall_bat/main/run.ps1'))"
```

### 4. Command Prompt (`cmd.exe`)
Paste directly into an ordinary Command Prompt:
```cmd
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=3072; iex (irm 'https://raw.githubusercontent.com/Piyushdas1624/Firewall_bat/main/run.ps1')"
```

---

## 💾 Local / Offline Execution

If you cloned or downloaded the repository:

1. **Option A (Batch Launcher):** Double-click `FirewallBlocker.bat` (or `text.bat`).
2. **Option B (PowerShell):** Right-click `FirewallBlocker.ps1` → **Run with PowerShell**, or in terminal:
   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\FirewallBlocker.ps1
   ```
3. **Drag & Drop:** You can drag and drop any folder from File Explorer directly into the console to set your target directory.

---

## 🖥️ Interactive Console Interface

```text
==============================================================================
         FIREWALL BLOCKER - RECURSIVE WINDOWS FIREWALL MANAGER                
       Windows 7 / 8 / 8.1 / 10 / 11 | Production Grade | Version 2.0        
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
   [9]  RESTART Windows Firewall Service       - Check & ensure MpsSvc health

   [0]  Exit
==============================================================================
```

---

## ✨ Features & Production Hardening

| Feature | Description |
| :--- | :--- |
| **Broad Compatibility** | Native support for Windows 7 SP1, 8, 8.1, 10, 11 and Windows Server (2008 R2–2025). |
| **PowerShell 2.0 to 7.x+** | Strict syntax compatibility across legacy PowerShell 2.0 (Win 7 default) through PowerShell 7.4+. |
| **Human-Readable Diagnostics** | Full color-coded output highlighting exact reasons for any `netsh` failure with actionable fixes. |
| **Deterministic Rule Naming** | Generates unique 8-character path hashes (e.g. `[FWB-IN] game.exe (7A4B1C2D)`) preventing rule collisions across different subdirectories with identical executable names. |
| **Critical Safety Guardrails** | Automatically protects Windows system directories (`C:\Windows`, `System32`, `SysWOW64`, root drives, Defender folder) from accidental blocking. |
| **Firewall Health Checks** | Detects whether `MpsSvc` (Windows Defender Firewall service) is stopped or disabled, with one-click restart. |
| **Dry-Run Audit Engine** | Audit any directory to inspect which executables are currently blocked or unblocked without making changes. |
| **Global Rule Purge** | One-click cleanup option to wipe all rules created by FirewallBlocker across the entire system. |
| **Automated Test Suite** | Includes `tests/test_suite.ps1` covering AST parsing, special characters (`&`, `()`, `[]`, `!`), safety checks, and hash verification. |

---

## 🤖 Headless / CLI Automation (CI/CD & Scripting)

Run operations silently without user prompts by specifying `-Action` and `-NonInteractive`:

```powershell
# Block both Inbound & Outbound
powershell -ExecutionPolicy Bypass -File .\FirewallBlocker.ps1 -TargetDir "D:\MyApp" -Action BlockBoth -NonInteractive

# Block Outbound only
powershell -ExecutionPolicy Bypass -File .\FirewallBlocker.ps1 -TargetDir "D:\MyApp" -Action BlockOutbound -NonInteractive

# Unblock target directory
powershell -ExecutionPolicy Bypass -File .\FirewallBlocker.ps1 -TargetDir "D:\MyApp" -Action UnblockDir -NonInteractive

# Scan and print audit summary
powershell -ExecutionPolicy Bypass -File .\FirewallBlocker.ps1 -TargetDir "D:\MyApp" -Action Scan -NonInteractive
```

### Exit Codes:
- `0`: Operation succeeded cleanly.
- `1`: General error or invalid arguments.
- `2`: Critical safety block (attempted to target a protected Windows system directory).
- `3`: Windows Firewall service (`MpsSvc`) is stopped or unavailable.

---

## 🧪 Verification & Testing

To run the automated test suite locally:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\test_suite.ps1
```

All 8 tests validate:
1. `FirewallBlocker.ps1` AST syntax validity.
2. `run.ps1` AST syntax validity.
3. Directory scanning with complex special characters (`&`, `()`, `[]`, `!`, spaces).
4. `text.bat` & `FirewallBlocker.bat` delegation.
5. System folder safety guardrails (`C:\Windows` block prevention).
6. Empty directory handling.
7. Invalid action parameter rejection.
8. Portable hash determinism and case-insensitivity.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
