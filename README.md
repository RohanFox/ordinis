# Ordinis — Microsoft Ecosystem Security Suite

> Professional Windows hardening audit tool. Scan, detect, and remediate security misconfigurations across Windows OS, Active Directory, SQL Server, NTLM, Kerberos, and more — with per-finding failure context, remediation steps, automated backup, and detailed reporting.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20%7C%20Server%202019%2F2022-lightgrey)]()
[![.NET](https://img.shields.io/badge/.NET-9.0-purple)]()
[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()

---

## Overview

Ordinis is a free, open-source desktop application for Windows security professionals, system administrators, and penetration testers. It runs CIS Benchmark, STIG, and custom security checks against the full Microsoft ecosystem in a GUI-based workflow.

Unlike raw PowerShell scripts or CSV-based tools, Ordinis provides:
- Per-finding failure context: *"Found '3' — must be ≥ 5"*
- Multiple remediation paths per check (GPO, registry, PowerShell) where available
- Backup-before-fix with one-click restore
- HTML, JSON, and CSV report export
- GPO export (LGPO format) for batch policy application

---

## Modules & Coverage

| Module | Checks | Benchmark | Key Areas |
|--------|--------|-----------|-----------|
| **Windows OS** | 133 lists | CIS L1/L2, STIG, BSI | Registry, secedit, auditpol, services, Defender, firewall — loaded from 133 HardeningKitty CSV lists, de-duplicated and OS/profile-filtered at scan time |
| **Active Directory** | 14 | CIS AD / PingCastle | Password policy, privileged accounts, stale objects, LDAP signing, trusts |
| **Kerberos** | 9 | MITRE ATT&CK T1558 | AS-REP Roasting, Kerberoasting, unconstrained delegation, Protected Users, krbtgt age, DES disabled |
| **NTLM / Credential** | 10 | CIS / STIG | LmCompatibilityLevel, NtlmMinClientSec, WDigest, LSA RunAsPPL, Credential Guard, anonymous access |
| **Local Security** | 13 | CIS / STIG | BitLocker, LAPS, local accounts, AppLocker/WDAC, UAC, Secure Boot, WMI persistence |
| **Logging & Audit** | 13 | CIS / NIST SP 800-92 | PowerShell Script Block/Module/Transcription logging, process creation cmdline, event log sizing, Advanced Audit Policy |
| **Attack Surface** | 14 | CIS / NSA / CISA | Print Spooler, Remote Registry, unnecessary services, Defender ASR rules, tamper protection, Windows Update |
| **Network** | 16 | CIS / STIG | SMBv1, SMB signing, RDP NLA, LLMNR, NetBIOS, mDNS, WPAD, IPv6 transition protocols, firewall |
| **SQL Server** | 22 | CIS SQL Server 2019/2022 | SA account, xp_cmdshell, surface area, auditing, TLS, agent account |
| **GPO Manager** | — | — | Export findings as LGPO, apply LGPO files, RSoP report, list applied GPOs |

**Total: 111 purpose-built checks across 8 modules + 133 HardeningKitty CSV lists for the Windows OS module**

---

## Key Features

### Comprehensive Audit
- Runs all modules in a single scan with live progress
- Detects the host OS and installed AV/EDR product and shows both on the dashboard
- Findings filtered by status (Pass/Fail/Error), severity (Critical → Info), and module
- Full-text search across finding IDs, names, and categories

### "Why It Failed" Context
Every failed finding shows:
```
WHY IT FAILED
Found "3" — must be ≥ 5
```
Plus the exact source (registry path, WMI class, PS cmdlet) that produced the value.

### Multi-Step Remediation
Each finding includes all remediation paths:
```
1. GPO: Computer Config > Security Options > Network security: LAN Manager authentication level = NTLMv2 only
2. Registry: Set-ItemProperty 'HKLM:\...\Lsa' LmCompatibilityLevel 5
3. secedit: LmCompatibilityLevel = 5 in [System Access]
```

### Safe Remediation with Backup
The fix workflow always: **Validate → Backup → Confirm → Apply → Verify**
Every fix — single-row or batch — is confirmed in a dialog showing the before/after values and the exact script, then re-audited afterwards to confirm it took effect.
- Registry keys backed up as `.reg` files
- Security policy exported via `secedit /export`
- Audit policy backed up via `auditpol /backup`
- One-click restore from the Backups tab

### Remote Scanning via WinRM
Scan any Windows machine over PowerShell Remoting. Methods that require local execution (`secedit`, `auditpol`, `accountpolicy`) are automatically skipped with an explanatory message rather than errored-out scan.

### Report Export
- **HTML** — full interactive report with severity breakdown
- **JSON** — machine-readable for SIEM integration
- **CSV** — import into Excel, Jira, or custom dashboards

---

## Attack Vectors Covered

### Kerberoasting / AS-REP Roasting (T1558)
Detects accounts vulnerable to offline ticket cracking:
- Service accounts with RC4 encryption (Kerberoastable)
- Accounts with `DONT_REQUIRE_PREAUTH` (AS-REP Roastable)
- Unconstrained Kerberos delegation on non-DC computers and user accounts

### Golden / Diamond Ticket Defenses
- `krbtgt` password age ≤ 180 days
- Protected Users group coverage for Domain Admins
- Kerberos ticket lifetime enforcement
- DES encryption disabled

### Pass-the-Hash / NTLM Relay (T1550, T1557)
- `LmCompatibilityLevel = 5` (NTLMv1/LM refused entirely)
- `NtlmMinClientSec` / `NtlmMinServerSec = 537395200` (NTLMv2 + 128-bit)
- WDigest disabled (no cleartext passwords in LSASS)
- Outbound NTLM restricted/audited
- LSA RunAsPPL + Credential Guard

### Credential Dumping (T1003)
- LSA RunAsPPL prevents unauthenticated injection into LSASS
- Credential Guard isolates credential material in VBS enclave
- WDigest disabled eliminates cleartext credential storage

### Persistence (T1053, T1546)
- WMI event subscription detection (fileless persistence)
- Scheduled tasks running as SYSTEM from user-writable paths
- Task Scheduler history enabled for forensic trail

### Lateral Movement (T1021)
- SMBv1 disabled (EternalBlue/WannaCry)
- SMB signing required (NTLM relay prevention)
- Remote Registry disabled
- Print Spooler disabled on servers (PrintNightmare CVE-2021-34527)

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| Windows 10 / 11 or Windows Server 2019 / 2022 | Required — WPF is Windows-only |
| .NET 9.0 Runtime | Included in self-contained build |
| PowerShell 5.1+ | Built into Windows |
| **Run as Administrator** | Required for registry, secedit, auditpol, Defender API access |
| RSAT (optional) | Required for Active Directory and Kerberos module checks |
| SQL Server access (optional) | Required for SQL Server module |

---

## Build

### Prerequisites
- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- Windows 10/11 with Visual Studio 2022 or VS Code with C# Dev Kit

### Clone & Build
```powershell
git clone https://github.com/RohanFox/ordinis.git
cd ordinis/Ordinis
dotnet build Ordinis.sln
```

### Run
```powershell
dotnet run --project Ordinis/Ordinis.csproj
```

### Run Tests
```powershell
dotnet test Ordinis.Tests/Ordinis.Tests.csproj
```

### Publish Self-Contained Executable
```powershell
dotnet publish Ordinis/Ordinis.csproj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o publish/
```
Output: `publish/Ordinis.exe` — single file, no .NET installation required on target.

---

## Usage

### Local Scan
1. Launch `Ordinis.exe` **as Administrator**
2. Select a benchmark profile from the dropdown (CIS Level 1, STIG, etc.)
3. Click **Run Audit**
4. Navigate to **Findings** tab — filter by severity, status, or module
5. Click any finding to see the failure reason, source, and remediation steps
6. Click **Apply Fix** on safe-to-fix findings (backs up first, asks confirmation)
7. Generate a report from the **Reports** tab

### Remote Scan via WinRM
1. Go to **Settings** tab and enter the remote hostname/IP, username, and password
2. Target machine must have WinRM enabled: `Enable-PSRemoting -Force`
3. Run audit — secedit/auditpol checks are automatically skipped with a note
4. Registry and service checks run remotely via `Invoke-Command`

### GPO Workflow
1. Run an audit
2. Go to **GPO Manager** tab
3. **Export LGPO** — exports all failed findings as an LGPO-compatible `.txt` file
4. Apply to other machines: copy the file and run **Apply LGPO File**
5. **GPO Report (RSoP)** — generates an HTML report of all currently applied Group Policy settings

---

## WinRM Remote Scanning Notes

| Method | Works Remotely | Notes |
|--------|---------------|-------|
| Registry reads | ✅ Yes | Via `Invoke-Command` + registry PS cmdlets |
| Service status | ✅ Yes | `Get-Service` over remoting |
| WMI / CIM queries | ✅ Yes | `Get-CimInstance` works over WinRM |
| PowerShell inline scripts | ✅ Yes | Standard PS remoting |
| `secedit /analyze` | ❌ No | Local process — skipped with explanation |
| `auditpol /get` | ❌ No | Local process — skipped with explanation |
| Account Policy (net accounts) | ❌ No | Local process — skipped with explanation |
| BitLocker (Get-BitLockerVolume) | ⚠️ Limited | Requires BitLocker PS module on target |

Target prerequisites:
```powershell
# On the remote machine (as Administrator):
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "<scanning-machine-IP>"
# For non-domain environments, also:
winrm set winrm/config/service/auth @{Basic="true"}
```

---

## Disclaimer

Ordinis is designed for **authorized use only** — auditing systems you own or have explicit written permission to scan. The remediation scripts modify security policy, registry settings, and Windows services, which can cause irreparable damage to non-targeted systems if not handled with expertise.

---

## License

MIT License — Copyright © 2026 [RohanFox](https://github.com/RohanFox)

See [LICENSE](LICENSE) for full text.

---

## Acknowledgements

Some modules and benchmarks sourced from https://github.com/0x6d69636b/windows_hardening (used under its license).

---

*Ordinis v1.3.1 · Free & Open Source (MIT) · [github.com/RohanFox](https://github.com/RohanFox)*