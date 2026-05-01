using Ordinis.Core.Models;

namespace Ordinis.Core.Services;

public class RemediationResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public BackupEntry? Backup { get; set; }
    public string? NewActualValue { get; set; }
}

public class RemediationEngine
{
    private readonly PowerShellRunner _ps;
    private readonly BackupManager    _backup;

    public RemediationEngine(PowerShellRunner ps, BackupManager backup)
    {
        _ps     = ps;
        _backup = backup;
    }

    public async Task<RemediationResult> ApplyFixAsync(
        Finding finding,
        ScanTarget target,
        CancellationToken ct = default)
    {
        // 1. Pre-validate
        var validation = PreValidate(finding);
        if (!validation.valid)
            return new RemediationResult { Success = false, Message = validation.reason };

        // 2. Backup
        BackupEntry? backupEntry = null;
        backupEntry = finding.Method.ToLowerInvariant() switch
        {
            "registry"     => await _backup.BackupRegistryKeyAsync(finding, ct),
            "secedit"      => await _backup.BackupSecurityPolicyAsync(ct),
            "auditpol"     => await _backup.BackupAuditPolicyAsync(ct),
            "accesschk"    => await _backup.BackupSecurityPolicyAsync(ct),
            _              => null
        };

        // 3a. ps_script findings use RemediationScript (actual PS command) when set,
        //     falling back to RemediationText for backward-compatible single-line commands.
        if (finding.Method.Equals("ps_script", StringComparison.OrdinalIgnoreCase))
        {
            string command = !string.IsNullOrWhiteSpace(finding.RemediationScript)
                ? finding.RemediationScript
                : finding.RemediationText;

            if (string.IsNullOrWhiteSpace(command))
                return new RemediationResult { Success = false, Message = "No remediation command defined for this finding.", Backup = backupEntry };

            var inline = await _ps.RunInlineAsync(command, ct: ct);
            return new RemediationResult
            {
                Success        = inline.Success,
                Message        = inline.Success ? "Fix applied successfully." : (inline.Error.Length > 0 ? inline.Error : "Command returned an error."),
                Backup         = backupEntry,
                NewActualValue = inline.Success ? finding.ExpectedValue : null
            };
        }

        // 3b. All other methods use a dedicated PowerShell fix script.
        var (script, parameters) = BuildFixScript(finding, target);
        if (string.IsNullOrEmpty(script))
            return new RemediationResult { Success = false, Message = $"No fix script defined for method '{finding.Method}'." };

        var psResult = await _ps.RunScriptAsync(
            script, parameters,
            target.Type == TargetType.Remote ? target.Hostname : null,
            target.Type == TargetType.Remote ? target.Username  : null,
            target.Type == TargetType.Remote ? target.Password  : null,
            ct);

        if (!psResult.Success)
            return new RemediationResult
            {
                Success = false,
                Message = psResult.Error.Length > 0 ? psResult.Error : "Fix script returned an error.",
                Backup  = backupEntry
            };

        return new RemediationResult
        {
            Success          = true,
            Message          = "Fix applied successfully.",
            Backup           = backupEntry,
            NewActualValue   = finding.ExpectedValue
        };
    }

    private static (bool valid, string reason) PreValidate(Finding finding)
    {
        // Safety checks before applying any fix
        if (!finding.IsSafeToAutoFix)
            return (false, "This finding is marked as not safe for automatic remediation. Apply manually.");

        // Don't touch SA account if it's the only sysadmin
        if (finding.Id.StartsWith("SQL-2.1") || finding.Id.StartsWith("SQL-2.2"))
            return (true, string.Empty); // SQL module handles its own validation

        return (true, string.Empty);
    }

    private static (string script, Dictionary<string, string> parameters) BuildFixScript(
        Finding finding, ScanTarget target)
    {
        var p = finding.CheckParams;
        return finding.Method.ToLowerInvariant() switch
        {
            "registry" => ("Fix/Set-RegistryValue.ps1", new()
            {
                ["RegistryPath"]  = p.GetValueOrDefault("RegistryPath", ""),
                ["RegistryItem"]  = p.GetValueOrDefault("RegistryItem", ""),
                ["RegistryValue"] = finding.ExpectedValue
            }),
            "secedit" => ("Fix/Apply-SecurityPolicy.ps1", new()
            {
                ["PolicyKey"]   = p.GetValueOrDefault("MethodArgument", ""),
                ["PolicyValue"] = finding.ExpectedValue
            }),
            "auditpol" => ("Fix/Apply-AuditPolicy.ps1", new()
            {
                ["Subcategory"] = p.GetValueOrDefault("MethodArgument", ""),
                ["Setting"]     = finding.ExpectedValue
            }),
            "service" => ("Fix/Set-ServiceStartType.ps1", new()
            {
                ["ServiceName"] = p.GetValueOrDefault("ServiceName", ""),
                ["StartType"]   = finding.ExpectedValue
            }),
            "accesschk" => ("Fix/Apply-UserRights.ps1", new()
            {
                ["Privilege"] = p.GetValueOrDefault("MethodArgument", ""),
                ["Accounts"]  = finding.ExpectedValue
            }),
            "ipv6adapter" => ("Fix/Configure-IPv6.ps1", new()
            {
                ["AdapterName"] = p.GetValueOrDefault("AdapterName", "*"),
                ["Action"]      = finding.ExpectedValue
            }),
            _ => (string.Empty, new())
        };
    }
}
