using Ordinis.Core.Models;
using Ordinis.Core.Services;
using Ordinis.Modules.Base;
using Ordinis.Modules.Windows;

namespace Ordinis.Modules.Logging;

public class LoggingModule : IModule
{
    private readonly PowerShellRunner _ps;

    public FindingModule Module  => FindingModule.Logging;
    public string DisplayName    => "Logging & Audit Policy";
    public string Description    => "PowerShell Script Block / Module / Transcription logging, Advanced Audit Policy, event log sizing, process creation auditing";

    public LoggingModule(PowerShellRunner ps) { _ps = ps; }

    public Task<List<Finding>> GetFindingsAsync(ScanProfile profile, CancellationToken ct = default)
        => Task.FromResult(GetChecks());

    public async Task AuditFindingAsync(Finding finding, ScanTarget target, CancellationToken ct = default)
    {
        finding.CheckParams.TryGetValue("Script", out string? script);
        if (string.IsNullOrEmpty(script))
        {
            await new WindowsModule(new CsvFindingLoader(), _ps).AuditFindingAsync(finding, target, ct);
            return;
        }

        var result = await _ps.RunInlineAsync(script, ct: ct);
        if (!result.Success && string.IsNullOrWhiteSpace(result.Output))
        {
            finding.Status       = FindingStatus.Error;
            finding.ErrorMessage = result.Error.Length > 200 ? result.Error[..200] : result.Error;
            return;
        }

        string actual = result.Output.Trim();
        if (actual.Length == 0 && !string.IsNullOrEmpty(finding.DefaultValue))
        {
            finding.IsUsingDefault = true;
            actual = finding.DefaultValue;
        }
        finding.ActualValue = actual;
        finding.Status = WindowsModule.Evaluate(finding.ActualValue, finding.ExpectedValue, finding.Operator)
                         ? FindingStatus.Pass : FindingStatus.Fail;
    }

    // The five PowerShell-logging / process-command-line registry checks (LOG-1.x, LOG-2.1)
    // moved to Data/FindingLists/finding_list_ordinis_logging_machine.csv — single-value
    // registry settings that audit via the registry method and gain a .reg backup before any
    // fix. The event-log-sizing (Get-WinEvent) and Advanced Audit Policy (auditpol) checks stay
    // here: they are PowerShell-logic checks a flat CSV row cannot express.
    private static List<Finding> GetChecks() => new()
    {
        // ── Event Log Sizing ──────────────────────────────────────────────────────
        Log("LOG-3.1", "Security event log size ≥ 196608 KB (192 MB)",
            "Default Security log size (20 MB) fills within hours during an attack. CISA recommends ≥ 1 GB for incident response viability. 192 MB is the CIS minimum. Logs overwritten before collection = blind spot.",
            "([int]((Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue).MaximumSizeInBytes / 1KB))",
            "Get-WinEvent -ListLog Security | Select MaximumSizeInBytes",
            ">=", "196608", FindingSeverity.High,
            "",
            new[]
            {
                "wevtutil sl Security /ms:1073741824  # Set to 1 GB",
                "GPO: Computer Config > Windows Settings > Security Settings > Event Log > Maximum Security log size = 1048576 KB (1 GB)",
                "PowerShell: Limit-EventLog -LogName Security -MaximumSize 1GB"
            },
            "wevtutil sl Security /ms:1073741824"),

        Log("LOG-3.2", "System event log size ≥ 32768 KB (32 MB)",
            "System log should be large enough to capture boot events, service changes, and driver failures needed for forensic reconstruction.",
            "([int]((Get-WinEvent -ListLog System -ErrorAction SilentlyContinue).MaximumSizeInBytes / 1KB))",
            "Get-WinEvent -ListLog System | Select MaximumSizeInBytes",
            ">=", "32768", FindingSeverity.Medium,
            "",
            new[]
            {
                "wevtutil sl System /ms:104857600  # 100 MB",
                "GPO: Maximum System log size = 102400 KB"
            },
            "wevtutil sl System /ms:104857600"),

        Log("LOG-3.3", "Application event log size ≥ 32768 KB (32 MB)",
            "Application events capture service crashes, application errors, and AV events. Undersized logs lose critical context during incidents.",
            "([int]((Get-WinEvent -ListLog Application -ErrorAction SilentlyContinue).MaximumSizeInBytes / 1KB))",
            "Get-WinEvent -ListLog Application | Select MaximumSizeInBytes",
            ">=", "32768", FindingSeverity.Low,
            "",
            new[]
            {
                "wevtutil sl Application /ms:104857600",
                "GPO: Maximum Application log size = 102400 KB"
            },
            "wevtutil sl Application /ms:104857600"),

        // ── Advanced Audit Policy ─────────────────────────────────────────────────
        Log("LOG-4.1", "Advanced audit: Logon events audited (Success + Failure)",
            "Without logon auditing, there is no record of authentication attempts. Logon failures (4625) reveal password spraying and brute force. Logon success (4624) is essential for lateral movement detection.",
            "$r = auditpol /get /subcategory:'Logon' 2>$null | Select-String 'Logon'; if ($r -match 'Success and Failure') { '1' } elseif ($r -match 'Success') { '1' } else { '0' }",
            "auditpol /get /subcategory:Logon",
            "=", "1", FindingSeverity.Critical,
            "",
            new[]
            {
                "auditpol /set /subcategory:'Logon' /success:enable /failure:enable",
                "GPO: Computer Config > Security Settings > Advanced Audit Policy > Logon/Logoff > Audit Logon = Success and Failure"
            },
            "auditpol /set /subcategory:'Logon' /success:enable /failure:enable"),

        Log("LOG-4.2", "Advanced audit: Account Management audited (Success + Failure)",
            "Account creation, deletion, password changes, and group membership changes (Event IDs 4720–4798) are critical for detecting privilege escalation and unauthorized account creation.",
            "$r = auditpol /get /subcategory:'User Account Management' 2>$null | Select-String 'User Account Management'; if ($r -match 'Success and Failure') { '1' } elseif ($r -match 'Success') { '1' } else { '0' }",
            "auditpol /get /subcategory:'User Account Management'",
            "=", "1", FindingSeverity.Critical,
            "",
            new[]
            {
                "auditpol /set /subcategory:'User Account Management' /success:enable /failure:enable",
                "GPO: Advanced Audit Policy > Account Management > Audit User Account Management = Success and Failure"
            },
            "auditpol /set /subcategory:'User Account Management' /success:enable /failure:enable"),

        Log("LOG-4.3", "Advanced audit: Process Creation audited (Success)",
            "Event ID 4688 (Process Creation) combined with command-line auditing is one of the most valuable data sources for detecting attacks. Enables tracking of malware execution, LOLBin abuse, and suspicious child processes.",
            "$r = auditpol /get /subcategory:'Process Creation' 2>$null | Select-String 'Process Creation'; if ($r -match 'Success') { '1' } else { '0' }",
            "auditpol /get /subcategory:'Process Creation'",
            "=", "1", FindingSeverity.Critical,
            "",
            new[]
            {
                "auditpol /set /subcategory:'Process Creation' /success:enable",
                "GPO: Advanced Audit Policy > Detailed Tracking > Audit Process Creation = Success",
                "Also enable LOG-2.1 (command line capture) for full value"
            },
            "auditpol /set /subcategory:'Process Creation' /success:enable"),

        Log("LOG-4.4", "Advanced audit: Policy Change audited",
            "Audit policy changes (event IDs 4902, 4907, 4719) record when attackers disable auditing to cover tracks. This is the 'last line of defence' for log integrity.",
            "$r = auditpol /get /subcategory:'Audit Policy Change' 2>$null | Select-String 'Audit Policy Change'; if ($r -match 'Success') { '1' } else { '0' }",
            "auditpol /get /subcategory:'Audit Policy Change'",
            "=", "1", FindingSeverity.High,
            "",
            new[]
            {
                "auditpol /set /subcategory:'Audit Policy Change' /success:enable /failure:enable",
                "GPO: Advanced Audit Policy > Policy Change > Audit Audit Policy Change = Success and Failure"
            },
            "auditpol /set /subcategory:'Audit Policy Change' /success:enable /failure:enable"),

        Log("LOG-4.5", "Advanced audit: Privilege Use audited",
            "Sensitive privilege use (event ID 4673, 4674) — SeDebugPrivilege, SeTakeOwnershipPrivilege — indicates credential dumping tools and privilege escalation attempts.",
            "$r = auditpol /get /subcategory:'Sensitive Privilege Use' 2>$null | Select-String 'Sensitive Privilege Use'; if ($r -match 'Success') { '1' } else { '0' }",
            "auditpol /get /subcategory:'Sensitive Privilege Use'",
            "=", "1", FindingSeverity.High,
            "",
            new[]
            {
                "auditpol /set /subcategory:'Sensitive Privilege Use' /success:enable /failure:enable",
                "GPO: Advanced Audit Policy > Privilege Use > Audit Sensitive Privilege Use = Success and Failure"
            },
            "auditpol /set /subcategory:'Sensitive Privilege Use' /success:enable /failure:enable"),
    };

    private static Finding Log(
        string id, string name, string description,
        string script, string checkSource,
        string op, string expected, FindingSeverity severity,
        string defaultValue,
        string[] steps,
        string remediationPs = "")
    => new()
    {
        Id               = id,
        Module           = FindingModule.Logging,
        Category         = id.StartsWith("LOG-1") ? "PowerShell Logging"
                         : id.StartsWith("LOG-2") ? "Process Auditing"
                         : id.StartsWith("LOG-3") ? "Event Log Sizing"
                         :                          "Advanced Audit Policy",
        Name             = name,
        Description      = description,
        Rationale        = description,
        Benchmark        = "CIS / NIST SP 800-92 / NSA",
        BenchmarkRef     = id,
        Severity         = severity,
        Method           = "ps_script",
        CheckParams      = new() { ["Script"] = script },
        ExpectedValue    = expected,
        DefaultValue     = defaultValue,
        Operator         = op,
        CheckSource      = checkSource,
        RemediationText  = steps[0],
        RemediationScript = remediationPs,
        RemediationSteps = steps.ToList(),
        IsSafeToAutoFix  = !string.IsNullOrEmpty(remediationPs)
    };
}
