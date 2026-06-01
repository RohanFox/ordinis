# Ordinis

A Windows security hardening and auditing suite. Ordinis audits a host against the
CIS, DoD STIG, BSI SiSyPHuS and Microsoft baselines, explains every failed check in
plain language, and remediates with a backup-first workflow — all from a single
portable `.exe`, no install.

It's a WPF desktop app (.NET 9, C# 12, MVVM) that grew out of three older tools:
HardeningKitty's audit engine, a YAML-rule CIS scanner, and a PHP policy browser.
Ordinis folds the useful parts of all three into one GUI and adds the things they
were missing — per-finding backup, a verify-after-fix loop, and modules for the rest
of the Microsoft stack (Active Directory, Kerberos, NTLM, SQL Server).

> Status: **v1.3.2.** Builds clean and the test suite is green. Auditing is safe to
> run anywhere; remediation writes to the registry as administrator, so try fixes on a
> throwaway VM before you trust them on a machine you care about.

## What it checks

Ordinis pulls findings from two places:

- **Benchmark CSVs** in `Ordinis/Data/FindingLists/` — the HardeningKitty finding
  lists (CIS Win10/11/Server, STIG, BSI, Microsoft baselines). These are plain data:
  read a registry value / service / audit policy, compare against an expected value.
  Drop your own CSV in that folder and it gets picked up on the next scan — no rebuild.
- **Built-in modules** in C# for the checks a flat CSV can't express, each grouped by
  the attack it defends against:

  | Module | Covers |
  |---|---|
  | Windows | the benchmark CSV engine — registry, services, `secedit`, `auditpol`, account policy, user rights, Defender, BitLocker |
  | NTLM / Credential | LM compat level, NTLM session security, WDigest, LSA protection, Credential Guard, anonymous access |
  | Active Directory | password & lockout policy, stale privileged accounts, LDAP signing, trusts |
  | Kerberos | Kerberoasting, AS-REP roasting, unconstrained delegation, krbtgt rotation, DES |
  | Network / IPv6 | SMB signing, RDP NLA, LLMNR/NetBIOS/mDNS, Teredo/ISATAP/6to4, firewall |
  | Local Security | BitLocker, LAPS, AppLocker/WDAC, UAC, Secure Boot, scheduled-task & WMI persistence |
  | Logging & Audit | PowerShell logging, process command-line capture, event-log sizing, advanced audit policy |
  | Attack Surface | Print Spooler, Remote Registry, ASR rules, Defender health, patch state |
  | SQL Server | the CIS SQL Server benchmark — auth mode, surface area, auditing, encryption |

The split is deliberate: declarative checks live in editable data so anyone can extend
them; checks whose logic is a script stay compiled inside the signed executable, which
is the trust boundary — a data file should never be able to run code as admin.

## Fixing things

Nothing changes on the host without going through the fix dialog first. For each
finding you see the current value, the value it'll be set to, the exact script that
will run, and a note that a backup is taken. Registry, security-policy and audit-policy
changes are exported to a restore file before the change; the Backups page lists them
and restores with one click. After a fix runs, the check is re-audited against the live
system — a fix only shows green once the machine actually reports the new value.

SQL Server findings are audit-only by design. A configuration change there can break a
running application, so Ordinis shows you the T-SQL and leaves you to apply it.

## Build & run

Requires the .NET 9 SDK.

```powershell
# build + test
dotnet build Ordinis/Ordinis.sln -c Debug
dotnet test  Ordinis/Ordinis.Tests/Ordinis.Tests.csproj

# single-file portable exe (run this on the target machine)
dotnet publish Ordinis/Ordinis/Ordinis.csproj -r win-x64 --self-contained -c Release `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish/
```

The finding lists, check JSON and PowerShell scripts under `Ordinis/Data` and
`Ordinis/Scripts` are copied to the output automatically. Run the app as administrator —
machine-scope checks need it. For domain checks (AD, Kerberos) run it on a domain-joined
host with RSAT installed; Ordinis skips those modules automatically when it can't reach AD.

## Adding your own checks

For a registry / service / audit-policy check, you don't touch code. Add a row to a CSV
in `Ordinis/Data/FindingLists/`. Two schemas are accepted:

- the stock HardeningKitty columns (`ID, Method, RegistryPath, RegistryItem,
  RecommendedValue, Operator, …`), or
- the extended Ordinis schema, which adds `Module`, `Description`, `Rationale`,
  `Remediation` and `RequiresRestart` so your check keeps its own ID, lands in the right
  module, and carries proper guidance. See `finding_list_ordinis_ntlm_machine.csv` for
  the shape.

A check whose logic needs real code (anything beyond "read X, compare to Y") belongs in
a module under `Ordinis/Ordinis/Modules/` — keep it in C# so it can't be injected from a
data file.

## Layout

```
Ordinis/Ordinis/          the app
  Core/                   models, services (audit, remediation, backup, reports)
  Modules/                the check modules listed above
  Data/FindingLists/      benchmark + curated CSVs
  Scripts/                backup / fix / audit PowerShell
Ordinis/Ordinis.Tests/    xUnit tests
CHANGELOG.md              release notes
ORDINIS_HANDOFF.md        deeper architecture notes
```

## Attribution

The finding lists and the audit methodology come from
[**HardeningKitty**](https://github.com/scipag/HardeningKitty) by Michael Schneider /
scip AG, MIT-licensed. Benchmark content belongs to its authors — CIS, DISA (STIG), BSI
and Microsoft. Ordinis bundles these for convenience; it doesn't replace the source
projects or their guidance.

## License

MIT. See [LICENSE](LICENSE).
