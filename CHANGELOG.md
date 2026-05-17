# Ordinis v1.3.1

## Bug fixes

**"Fix Selected" bypassed the confirmation dialog.** The toolbar's batch-fix button applied registry, security-policy and audit-policy changes directly — no FixDialog, so no before/after preview, no backup notice, no restart warning. Per-row fixes went through the dialog; the batch button did not. Both paths are now consolidated: every fix, single or batch, opens FixDialog first, and cancelling the dialog skips that finding.

**Fixes were reported as passed without being checked.** After applying a fix the code set the finding to Pass and assumed it now held the expected value — it never re-read the system, so a fix that "succeeded" but changed nothing still showed green. Added `AuditEngine.AuditSingleAsync`: after a fix the finding is re-audited against the live system and its status reflects the real result. The status bar now reports how many fixes were verified.

**Batch fix had no error handling.** The toolbar fix path was not wrapped — an exception surfaced only through the global crash handler, with no context and no loading state shown. It now shares the same wrapped routine as the single-row fix.

**Version string drift.** The sidebar and the HTML report footer were hardcoded to "v1.2" while the app was 1.3.0. The version now lives in one place — `Core/AppInfo.cs` — and the sidebar, About dialog and reports all read from it.

**Critical severity was dropped from CSV findings.** `CsvFindingLoader` had no mapping for a "Critical" severity, so a Critical row in a custom finding list silently became Low. Added the mapping. HardeningKitty's own lists only use High/Medium/Low, so this affects custom lists.

## Upgrade notes

No migration needed. Self-contained builds still work as-is.

---

# Ordinis v1.3.0

## What's new

**OS and AV shown on Dashboard**
The dashboard now shows the detected OS name and AV/EDR product. Detection tries SecurityCenter2 WMI first, then checks for known EDR service names (CrowdStrike, SentinelOne, Bitdefender, ESET, Kaspersky, Sophos, Malwarebytes, Carbon Black...), then falls back to Get-MpComputerStatus if nothing else matched.

**Auto-fix for NTLM, Local Security, Logging, Attack Surface, Network**
These modules only had guidance text — no actual fix scripts. Added PowerShell remediation scripts to 30+ findings across those modules. Things like WDigest, RunAsPPL, PS logging registry keys, auditpol settings, log sizes, Print Spooler, Remote Registry, LLMNR. Registry fixes create the key first if it doesn't exist.

## Bug fixes

**Fix button always crashed.** `FixSelectedAsync` didn't capture `Selected` before the confirmation dialog. During the PowerShell await the UI message pump ran, clicking another row nulled out `Selected`, and the code crashed on `Selected.Status` after the await came back. Captured the reference up front. Also added a proper catch block — it was showing "Object reference not set" with no context before.

**Blank values on Windows Server 2019.** `Confirm-SecureBootUEFI`, `Get-BitLockerVolume`, and the Defender cmdlets (`Get-MpComputerStatus`, `Get-MpPreference`) all throw terminating errors on Server SKUs even with `-ErrorAction SilentlyContinue`. Wrapped in try/catch with safe fallbacks. Also removed a `Schedule.Service` COM call in the task scheduler check that was throwing on every system.

**AD-2.3 and AD-2.4 wrong results.** Both checks used `Get-ADUser -Filter {SID -like '*-500'}`. The `-like` operator on the binary `objectSid` attribute silently returns nothing — AD-2.3 was always passing, AD-2.4 was always failing. Fixed to build the SID from `(Get-ADDomain).DomainSID.Value` and use `-Identity`.

**AV detection returned Defender instead of Bitdefender.** SecurityCenter2 lists both when a third-party AV is installed, Defender comes first. Was using `Select-Object -First 1` which always grabbed Defender. Now filters Defender out first and only falls back to it if nothing else is registered.

**LLMNR fix silently did nothing.** `Set-ItemProperty` on `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient` fails when the key doesn't exist. The GPO path is absent on most machines that haven't had that policy applied. Added `New-Item -Force` before setting the value.

## Upgrade notes

No migration needed. Self-contained builds still work as-is.

---

## [1.2.0] — prior release

See [v1.2.0 release notes](https://github.com/RohanFox/ordinis/releases/tag/v.1.2.0).
