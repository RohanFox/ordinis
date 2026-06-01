using Ordinis.Core.Models;
using Ordinis.Core.Services;
using Ordinis.Modules.Base;
using Ordinis.Modules.Windows;

namespace Ordinis.Modules.NTLM;

public class NtlmModule : IModule
{
    private readonly PowerShellRunner _ps;

    public FindingModule Module  => FindingModule.NTLM;
    public string DisplayName    => "NTLM / Credential Hardening";
    public string Description    => "NTLM downgrade prevention, Credential Guard, LSA protection, WDigest, pass-the-hash mitigations";

    public NtlmModule(PowerShellRunner ps) { _ps = ps; }

    public Task<List<Finding>> GetFindingsAsync(ScanProfile profile, CancellationToken ct = default)
        => Task.FromResult(GetChecks());

    public async Task AuditFindingAsync(Finding finding, ScanTarget target, CancellationToken ct = default)
    {
        finding.CheckParams.TryGetValue("Script", out string? script);

        PsResult result;
        if (!string.IsNullOrEmpty(script))
        {
            result = await _ps.RunInlineAsync(script, ct: ct);
        }
        else
        {
            await new WindowsModule(new CsvFindingLoader(), _ps).AuditFindingAsync(finding, target, ct);
            return;
        }

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

    // Only Credential Guard remains in C# — it is a compound, multi-value check (it reads two
    // DeviceGuard values and ANDs them), which a flat CSV row cannot express. The nine
    // single-value registry checks (NTLM-1.x, 2.1, 2.2, 3.x, 4.x) moved to the community-editable
    // curated list Data/FindingLists/finding_list_ordinis_ntlm_machine.csv, where they audit via
    // the registry method and gain a .reg backup before any fix.
    private static List<Finding> GetChecks() => new()
    {
        // ── Credential Guard ──────────────────────────────────────────────────────
        // Windows default: VBS not enabled (0). Requires hardware + reboot — not auto-fixable.
        Ntlm("NTLM-2.3", "Credential Guard enabled (Virtualization-Based Security)",
            "Credential Guard uses VBS/hypervisor to isolate NTLM hashes and Kerberos TGTs in a separate security context that even a compromised kernel cannot read.",
            "script",
            "$cg = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -ErrorAction SilentlyContinue); if ($cg.EnableVirtualizationBasedSecurity -eq 1 -and $cg.RequirePlatformSecurityFeatures -ge 1) { '1' } else { '0' }",
            @"HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard :: EnableVirtualizationBasedSecurity + RequirePlatformSecurityFeatures",
            "=", "1", FindingSeverity.Critical, "0",
            new[]
            {
                "Registry: Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' EnableVirtualizationBasedSecurity 1",
                "Registry: Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' RequirePlatformSecurityFeatures 1",
                "GPO: Computer Config > Admin Templates > System > Device Guard > Turn On Virtualization Based Security",
                "Requires: UEFI, Secure Boot, TPM 2.0, 64-bit CPU with VT-x/AMD-V + SLAT"
            }),
    };

    private static Finding Ntlm(
        string id, string name, string description,
        string method, string script, string checkSource,
        string op, string expected, FindingSeverity severity,
        string defaultValue,
        string[] steps,
        string remediationPs = "",
        bool requiresRestart = false)
    => new()
    {
        Id               = id,
        Module           = FindingModule.NTLM,
        Category         = id.StartsWith("NTLM-1") ? "LAN Manager / NTLM Version"
                         : id.StartsWith("NTLM-2") ? "Credential Protection"
                         : id.StartsWith("NTLM-3") ? "Anonymous Access"
                         :                           "NTLM Restriction & Audit",
        Name             = name,
        Description      = description,
        Rationale        = description,
        Benchmark        = "CIS / STIG",
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
        IsSafeToAutoFix  = !string.IsNullOrEmpty(remediationPs),
        RequiresRestart  = requiresRestart
    };
}
