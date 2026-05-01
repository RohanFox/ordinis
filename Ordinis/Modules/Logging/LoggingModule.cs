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

    private static List<Finding> GetChecks() => new()
    {
        // ── PowerShell Logging ────────────────────────────────────────────────────
        // All PS logging keys live under HKLM:\SOFTWARE\Policies\... (GPO path).
        // These keys only exist when GPO is applied. Windows default when absent = 0 (disabled).
        Log("LOG-1.1", "PowerShell Script Block Logging enabled",
            "Script Block Logging records the full content of every PowerShell script block executed, including obfuscated/encoded commands. Essential for detecting LOLBin abuse, encoded payloads, and in-memory attacks.",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging",
            @"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging :: EnableScriptBlockLogging",
            "=", "1", FindingSeverity.Critical,
            "0",
            new[]
            {
                "Registry: New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1",
                "GPO: Computer Config > Admin Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging = Enabled",
                "Events logged to: Microsoft-Windows-PowerShell/Operational (Event ID 4104)"
            },
            "$p='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging'; if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }; Set-ItemProperty $p EnableScriptBlockLogging 1"),

        Log("LOG-1.2", "PowerShell Module Logging enabled",
            "Module Logging captures the pipeline execution details of every PowerShell module. Reveals exactly which commands and parameters were used, even without Script Block Logging.",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -Name EnableModuleLogging -ErrorAction SilentlyContinue).EnableModuleLogging",
            @"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging :: EnableModuleLogging",
            "=", "1", FindingSeverity.High,
            "0",
            new[]
            {
                "Registry: New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -Force; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -Name EnableModuleLogging -Value 1",
                "To log all modules, also set ModuleNames = * under the ModuleLogging key",
                "GPO: Computer Config > Admin Templates > Windows Components > Windows PowerShell > Turn on Module Logging = Enabled, ModuleNames = *"
            },
            "$p='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging'; if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }; Set-ItemProperty $p EnableModuleLogging 1"),

        Log("LOG-1.3", "PowerShell Transcription logging enabled",
            "Transcription writes a full record of each PowerShell session input/output to disk. Creates a persistent audit trail even if event logs are cleared.",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' -Name EnableTranscripting -ErrorAction SilentlyContinue).EnableTranscripting",
            @"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription :: EnableTranscripting",
            "=", "1", FindingSeverity.High,
            "0",
            new[]
            {
                "Registry: New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' -Force; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' -Name EnableTranscripting -Value 1",
                "Set a transcript output directory: Set-ItemProperty ... -Name OutputDirectory -Value '\\\\SIEM\\PS-Transcripts'",
                "GPO: Computer Config > Admin Templates > Windows Components > Windows PowerShell > Turn on PowerShell Transcription = Enabled"
            },
            "$p='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription'; if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }; Set-ItemProperty $p EnableTranscripting 1"),

        Log("LOG-1.4", "PowerShell Script Block Logging — suspicious activity logged",
            "EnableScriptBlockInvocationLogging=1 also logs script blocks that execute at invocation time, not just definition time, capturing more attack activity.",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockInvocationLogging -ErrorAction SilentlyContinue).EnableScriptBlockInvocationLogging",
            @"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging :: EnableScriptBlockInvocationLogging",
            "=", "1", FindingSeverity.Medium,
            "0",
            new[]
            {
                "Registry: Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' EnableScriptBlockInvocationLogging 1",
                "Must be set alongside EnableScriptBlockLogging = 1"
            },
            "$p='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging'; if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }; Set-ItemProperty $p EnableScriptBlockInvocationLogging 1"),

        // ── Process Creation Audit (Command Line) ─────────────────────────────────
        // Windows default when Audit key absent: command line not captured (0).
        Log("LOG-2.1", "Process creation command line captured in event logs",
            "Without this, Event ID 4688 (Process Creation) logs only the executable name — not the arguments. Command-line capture reveals LOLBin abuse (e.g., 'cmd.exe /c whoami'), encoded commands, and lateral movement.",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled",
            @"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit :: ProcessCreationIncludeCmdLine_Enabled",
            "=", "1", FindingSeverity.Critical,
            "0",
            new[]
            {
                "Registry: New-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Force; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1",
                "GPO: Computer Config > Admin Templates > System > Audit Process Creation > Include command line in process creation events = Enabled",
                "Requires: Advanced Audit Policy 'Audit Process Creation' must be enabled (Success)"
            },
            "$p='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit'; if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }; Set-ItemProperty $p ProcessCreationIncludeCmdLine_Enabled 1"),

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
