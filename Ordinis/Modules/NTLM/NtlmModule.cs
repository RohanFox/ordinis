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

    private static List<Finding> GetChecks() => new()
    {
        // ── LAN Manager / NTLM version ────────────────────────────────────────────
        // Windows default when key absent: 3 (NTLMv2 only; LM & NTLMv1 still accepted).
        Ntlm("NTLM-1.1", "LM Compatibility Level = 5 (NTLMv2 only)",
            "LmCompatibilityLevel=5 refuses LM and NTLMv1 entirely. Anything lower enables downgrade attacks and pass-the-hash.",
            "script",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel",
            @"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa :: LmCompatibilityLevel",
            ">=", "5", FindingSeverity.Critical, "3",
            new[]
            {
                "GPO: Computer Config > Windows Settings > Security Settings > Local Policies > Security Options > Network security: LAN Manager authentication level = Send NTLMv2 response only; refuse LM & NTLM",
                "Registry: Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' LmCompatibilityLevel 5",
                "secedit: LmCompatibilityLevel = 5 in [System Access]"
            },
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' LmCompatibilityLevel 5"),

        // Windows default: 536870912 = 0x20000000 (128-bit required, NTLMv2 bit NOT set).
        Ntlm("NTLM-1.2", "NTLM minimum client security requires NTLMv2 + 128-bit",
            "NtlmMinClientSec should enforce NTLMv2 session security (0x00080000) and 128-bit encryption (0x20000000). Combined = 537395200.",
            "script",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' -Name NtlmMinClientSec -ErrorAction SilentlyContinue).NtlmMinClientSec",
            @"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 :: NtlmMinClientSec",
            ">=", "537395200", FindingSeverity.High, "536870912",
            new[]
            {
                "Registry: Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' NtlmMinClientSec 537395200",
                "GPO: Network security: Minimum session security for NTLM SSP based clients = Require NTLMv2 + 128-bit encryption"
            },
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' NtlmMinClientSec 537395200"),

        // Windows default: 536870912 = 0x20000000 (same as client side).
        Ntlm("NTLM-1.3", "NTLM minimum server security requires NTLMv2 + 128-bit",
            "NtlmMinServerSec=537395200 ensures the server side rejects weak NTLM sessions.",
            "script",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' -Name NtlmMinServerSec -ErrorAction SilentlyContinue).NtlmMinServerSec",
            @"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 :: NtlmMinServerSec",
            ">=", "537395200", FindingSeverity.High, "536870912",
            new[]
            {
                "Registry: Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' NtlmMinServerSec 537395200",
                "GPO: Network security: Minimum session security for NTLM SSP based servers = Require NTLMv2 + 128-bit encryption"
            },
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' NtlmMinServerSec 537395200"),

        // ── WDigest / cleartext passwords ─────────────────────────────────────────
        // Windows default when key absent: WDigest disabled (0) — hardened in Windows 8.1 / KB2871997.
        Ntlm("NTLM-2.1", "WDigest cleartext password caching disabled",
            "UseLogonCredential=1 stores plaintext passwords in LSASS memory. mimikatz sekurlsa::wdigest exploits this. Must be 0.",
            "script",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential",
            @"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest :: UseLogonCredential",
            "=", "0", FindingSeverity.Critical, "0",
            new[]
            {
                "Registry: Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' UseLogonCredential 0",
                "GPO: Computer Config > Policies > Admin Templates > MS Security Guide > WDigest Authentication = Disabled"
            },
            "$p='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest'; if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }; Set-ItemProperty $p UseLogonCredential 0"),

        // ── LSA Protection ────────────────────────────────────────────────────────
        // Windows default when key absent: 0 (not enforced).
        Ntlm("NTLM-2.2", "LSA RunAsPPL (Protected Process Light) enabled",
            "RunAsPPL=1 runs LSASS as a Protected Process. Prevents credential dumping by tools like mimikatz that can't inject into protected processes without a signed driver.",
            "script",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL",
            @"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa :: RunAsPPL",
            "=", "1", FindingSeverity.Critical, "0",
            new[]
            {
                "Registry: Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' RunAsPPL 1",
                "Requires a reboot to take effect. Enable Secure Boot first for Kernel-level protection.",
                "GPO: Computer Config > Windows Settings > Security Settings > Local Policies > Security Options > LSASS.exe as Protected Process"
            },
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' RunAsPPL 1",
            requiresRestart: true),

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

        // ── Anonymous access ──────────────────────────────────────────────────────
        // Windows default: 1 (restricted) on Windows Vista and later.
        Ntlm("NTLM-3.1", "Anonymous SAM enumeration restricted",
            "RestrictAnonymousSAM=1 prevents unauthenticated enumeration of local accounts via the SAM pipe — used by recon tools.",
            "script",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RestrictAnonymousSAM -ErrorAction SilentlyContinue).RestrictAnonymousSAM",
            @"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa :: RestrictAnonymousSAM",
            "=", "1", FindingSeverity.High, "1",
            new[]
            {
                "Registry: Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' RestrictAnonymousSAM 1",
                "GPO: Network access: Do not allow anonymous enumeration of SAM accounts = Enabled"
            },
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' RestrictAnonymousSAM 1"),

        // Windows default: 0 (no restriction on anonymous connections).
        Ntlm("NTLM-3.2", "Anonymous access to named pipes / shares restricted",
            "RestrictAnonymous=1 prevents anonymous connections from enumerating shares and named pipes (used by BloodHound-style recon).",
            "script",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RestrictAnonymous -ErrorAction SilentlyContinue).RestrictAnonymous",
            @"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa :: RestrictAnonymous",
            ">=", "1", FindingSeverity.High, "0",
            new[]
            {
                "Registry: Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' RestrictAnonymous 1",
                "GPO: Network access: Do not allow anonymous enumeration of SAM accounts and shares = Enabled"
            },
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' RestrictAnonymous 1"),

        // ── NTLM Restrict / Audit ─────────────────────────────────────────────────
        // Windows default: 0 (allow all outbound NTLM — no restriction or auditing).
        Ntlm("NTLM-4.1", "Outbound NTLM traffic restricted or audited",
            "RestrictSendingNTLMTraffic=2 blocks all outbound NTLM. Value 1 = audit only. Prevents NTLM relay attacks when an attacker triggers outbound auth.",
            "script",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' -Name RestrictSendingNTLMTraffic -ErrorAction SilentlyContinue).RestrictSendingNTLMTraffic",
            @"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 :: RestrictSendingNTLMTraffic",
            ">=", "1", FindingSeverity.High, "0",
            new[]
            {
                "Registry (audit): Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' RestrictSendingNTLMTraffic 1",
                "Registry (block): Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' RestrictSendingNTLMTraffic 2",
                "GPO: Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers = Audit/Deny all"
            },
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' RestrictSendingNTLMTraffic 1"),

        // Windows default: 0 (no NTLM auditing).
        Ntlm("NTLM-4.2", "NTLM authentication auditing enabled",
            "AuditReceivingNTLMTraffic=2 logs all incoming NTLM auth in the Security event log — essential for detecting NTLM relay/pass-the-hash attempts.",
            "script",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' -Name AuditReceivingNTLMTraffic -ErrorAction SilentlyContinue).AuditReceivingNTLMTraffic",
            @"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 :: AuditReceivingNTLMTraffic",
            ">=", "1", FindingSeverity.Medium, "0",
            new[]
            {
                "Registry: Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' AuditReceivingNTLMTraffic 2",
                "GPO: Network security: Restrict NTLM: Audit incoming NTLM traffic = Enable auditing for all accounts"
            },
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' AuditReceivingNTLMTraffic 2"),
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
