using Ordinis.Core.Models;
using Ordinis.Core.Services;
using Ordinis.Modules.Base;
using Ordinis.Modules.Windows;

namespace Ordinis.Modules.AttackSurface;

public class AttackSurfaceModule : IModule
{
    private readonly PowerShellRunner _ps;

    public FindingModule Module  => FindingModule.AttackSurface;
    public string DisplayName    => "Attack Surface Reduction";
    public string Description    => "Unnecessary services (Print Spooler, Remote Registry), Windows Defender ASR rules, automatic updates, anti-malware health, Principle of Least Privilege";

    public AttackSurfaceModule(PowerShellRunner ps) { _ps = ps; }

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
        // ── Dangerous Services ────────────────────────────────────────────────────
        Asr("ASR-1.1", "Print Spooler service disabled (on servers / DCs)",
            "The Print Spooler running on Domain Controllers is the root cause of PrintNightmare (CVE-2021-1675/34527) and SpoolFool. Any authenticated user can execute code as SYSTEM by abusing the spooler's driver installation API. Must be disabled on all DCs and servers that don't print.",
            "(Get-Service -Name Spooler -ErrorAction SilentlyContinue).StartType",
            "Get-Service -Name Spooler",
            "=", "Disabled", FindingSeverity.Critical,
            "",
            new[]
            {
                "Stop-Service -Name Spooler -Force; Set-Service -Name Spooler -StartupType Disabled",
                "GPO: Computer Config > Windows Settings > Security Settings > System Services > Print Spooler = Disabled",
                "For workstations that must print: set StartType=Manual rather than Disabled. Disable is required on DCs."
            },
            "Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue; Set-Service -Name Spooler -StartupType Disabled"),

        Asr("ASR-1.2", "Remote Registry service disabled",
            "Remote Registry allows any user with network access to read/write registry keys remotely without RDP. Used by attackers for lateral movement, credential harvesting via SAM/SYSTEM hive access, and persistence.",
            "(Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue).StartType",
            "Get-Service -Name RemoteRegistry",
            "=", "Disabled", FindingSeverity.High,
            "",
            new[]
            {
                "Stop-Service -Name RemoteRegistry -Force; Set-Service -Name RemoteRegistry -StartupType Disabled",
                "GPO: Computer Config > Windows Settings > Security Settings > System Services > Remote Registry = Disabled",
                "Note: Some monitoring tools (e.g., SCOM) require Remote Registry. Audit before disabling."
            },
            "Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue; Set-Service -Name RemoteRegistry -StartupType Disabled"),

        Asr("ASR-1.3", "Secondary Logon service disabled (runas elevation vector)",
            "The Secondary Logon service (seclogon) enables 'runas' which can be abused for token impersonation and privilege escalation. Disable unless runas is an operational requirement.",
            "(Get-Service -Name seclogon -ErrorAction SilentlyContinue).StartType",
            "Get-Service -Name seclogon",
            "=", "Disabled", FindingSeverity.Medium,
            "",
            new[]
            {
                "Set-Service -Name seclogon -StartupType Disabled",
                "GPO: System Services > Secondary Logon = Disabled",
                "Verify runas is not used in any admin workflows before disabling"
            },
            "Stop-Service -Name seclogon -Force -ErrorAction SilentlyContinue; Set-Service -Name seclogon -StartupType Disabled"),

        // Windows default when GPO key absent: LLMNR is enabled (1).
        // Source: MS docs — LLMNR on by default; disabled only via GPO/registry.
        Asr("ASR-1.4", "LLMNR disabled via registry",
            "LLMNR (Link-Local Multicast Name Resolution) responds to unauthenticated name queries — a Responder/PetitPotam attack primitive for capturing NTLMv2 hashes. Already in Network module; confirmed here via registry as GPO may lag.",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast",
            @"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient :: EnableMulticast",
            "=", "0", FindingSeverity.High,
            "1",
            new[]
            {
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0",
                "GPO: Computer Config > Admin Templates > Network > DNS Client > Turn off multicast name resolution = Enabled"
            },
            "$p='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient'; if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }; Set-ItemProperty $p EnableMulticast 0"),

        Asr("ASR-1.5", "Telnet client not installed",
            "Telnet sends all data — including credentials — in cleartext. Its presence indicates legacy protocol tolerance or potential misconfiguration.",
            "(Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction SilentlyContinue).State",
            "Get-WindowsOptionalFeature -FeatureName TelnetClient",
            "=", "Disabled", FindingSeverity.Medium,
            "",
            new[]
            {
                "Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart",
                "Use SSH (OpenSSH is built into Windows 10+) or other encrypted alternatives"
            },
            "Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart -ErrorAction SilentlyContinue | Out-Null"),

        // ── Principle of Least Privilege ──────────────────────────────────────────
        Asr("ASR-2.1", "Local Administrators group has ≤ 2 members",
            "Each additional local admin account is an attack surface — compromising any one gives SYSTEM-level access. Workstations should have only: domain-joined LAPS account + one named local admin. More than 2 indicates privilege creep.",
            "(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue).Count",
            "Get-LocalGroupMember -Group Administrators",
            "<=", "2", FindingSeverity.High,
            "",
            new[]
            {
                "Review: Get-LocalGroupMember -Group 'Administrators' | Select Name, ObjectClass, PrincipalSource",
                "Remove unnecessary members: Remove-LocalGroupMember -Group 'Administrators' -Member '<account>'",
                "Use LAPS for the local admin account and remove personal/shared accounts"
            }),

        Asr("ASR-2.2", "No standard users in local Administrators group",
            "Domain user accounts in the local Administrators group enable pass-the-hash lateral movement. If the domain account is compromised anywhere, every machine it admins is owned.",
            "$domainAdmins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Where-Object { $_.PrincipalSource -eq 'ActiveDirectory' -and $_.ObjectClass -eq 'User' }; $domainAdmins.Count",
            "Get-LocalGroupMember -Group Administrators | Where PrincipalSource -eq ActiveDirectory",
            "=", "0", FindingSeverity.Critical,
            "",
            new[]
            {
                "Remove domain users from local Administrators: Remove-LocalGroupMember -Group 'Administrators' -Member 'DOMAIN\\username'",
                "Use Privileged Access Workstations (PAW) and tiered admin model instead",
                "For helpdesk scenarios, use Restricted Admin mode or JEA (Just Enough Administration)"
            }),

        // ── Windows Defender / Anti-Malware ──────────────────────────────────────
        // Wrapped in try-catch: Get-MpComputerStatus throws if Defender feature is not installed.
        Asr("ASR-3.1", "Windows Defender Real-Time Protection enabled",
            "Real-time protection is the primary malware prevention layer. If disabled by policy or tampered with, the machine is completely unprotected from file-based and in-memory threats.",
            "try { (Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled } catch { 'False' }",
            "Get-MpComputerStatus | Select RealTimeProtectionEnabled",
            "=", "True", FindingSeverity.Critical,
            "",
            new[]
            {
                "Set-MpPreference -DisableRealtimeMonitoring $false",
                "GPO: Computer Config > Admin Templates > Windows Components > Microsoft Defender Antivirus > Turn off Microsoft Defender Antivirus = Disabled",
                "Ensure Tamper Protection is also enabled (ASR-3.2) to prevent this being disabled by malware"
            },
            "Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue"),

        Asr("ASR-3.2", "Windows Defender Tamper Protection enabled",
            "Tamper Protection prevents malware, scripts, and even local admins from disabling Defender. Without it, ransomware routinely disables AV before encryption. Requires MDE or Intune for enterprise management.",
            "try { (Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected } catch { 'False' }",
            "Get-MpComputerStatus | Select IsTamperProtected",
            "=", "True", FindingSeverity.Critical,
            "",
            new[]
            {
                "Enable via Windows Security app: Virus & Threat Protection > Manage Settings > Tamper Protection = On",
                "For enterprise: Enable via Microsoft Defender for Endpoint portal or Intune",
                "Cannot be enabled via local script if already disabled — requires interactive or MDM/MDE"
            }),

        Asr("ASR-3.3", "Defender cloud-delivered protection enabled (MAPS)",
            "Cloud protection enables sub-second response to zero-day malware using Microsoft's threat intelligence. Disabling it means relying only on local signatures, which lag by hours to days.",
            "try { ([int](Get-MpPreference -ErrorAction Stop).MAPSReporting) } catch { '0' }",
            "Get-MpPreference | Select MAPSReporting",
            ">=", "1", FindingSeverity.High,
            "",
            new[]
            {
                "Set-MpPreference -MAPSReporting Advanced  # or Basic (1)",
                "GPO: Computer Config > Admin Templates > Windows Components > Microsoft Defender Antivirus > MAPS > Join Microsoft MAPS = Advanced MAPS",
                "Values: 0=disabled, 1=Basic, 2=Advanced"
            },
            "Set-MpPreference -MAPSReporting 2 -ErrorAction SilentlyContinue"),

        Asr("ASR-3.4", "Defender PUA (Potentially Unwanted Application) protection enabled",
            "PUA protection blocks adware, cryptominers, and bundleware that aren't traditional malware but degrade security posture and may be used as initial access vectors.",
            "try { ([int](Get-MpPreference -ErrorAction Stop).PUAProtection) } catch { '0' }",
            "Get-MpPreference | Select PUAProtection",
            ">=", "1", FindingSeverity.Medium,
            "",
            new[]
            {
                "Set-MpPreference -PUAProtection Enabled  # 1=Enabled, 2=Audit",
                "GPO: Computer Config > Admin Templates > Windows Components > Microsoft Defender Antivirus > Configure detection for potentially unwanted applications = Enabled"
            },
            "Set-MpPreference -PUAProtection 1 -ErrorAction SilentlyContinue"),

        Asr("ASR-3.5", "Defender Attack Surface Reduction rules enabled (≥ 1 rule)",
            "ASR rules block specific attack techniques: Office macros spawning child processes, credential theft from LSASS, obfuscated script execution, process injection. CIS recommends enabling all applicable rules in block mode.",
            "try { ([int](Get-MpPreference -ErrorAction Stop).AttackSurfaceReductionRules_Actions.Count) } catch { '0' }",
            "Get-MpPreference | Select AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions",
            ">=", "1", FindingSeverity.High,
            "",
            new[]
            {
                "Enable all recommended ASR rules in block mode (see Microsoft docs for full GUIDs):",
                "Set-MpPreference -AttackSurfaceReductionRules_Ids 'd4f940ab-401b-4efc-aadc-ad5f3c50688a','3b576869-a4ec-4529-8536-b80a7769e899','75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84','d3e037e1-3eb8-44c8-a917-57927947596d','5beb7efe-fd9a-4556-801d-275e5ffc04cc','be9ba2d9-53ea-4cdc-84e5-9b1eeee46550','92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b','e6db77e5-3df2-4cf1-b95a-636979351e5b' -AttackSurfaceReductionRules_Actions 1,1,1,1,1,1,1,1",
                "GPO: Computer Config > Admin Templates > Windows Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Attack Surface Reduction > Configure Attack Surface Reduction rules"
            },
            "Set-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a,3b576869-a4ec-4529-8536-b80a7769e899,75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84,d3e037e1-3eb8-44c8-a917-57927947596d,5beb7efe-fd9a-4556-801d-275e5ffc04cc,be9ba2d9-53ea-4cdc-84e5-9b1eeee46550,92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b,e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions 1,1,1,1,1,1,1,1 -ErrorAction SilentlyContinue"),

        // ── Windows Update ────────────────────────────────────────────────────────
        // Windows default when neither GPO key nor non-GPO key is set: Windows 10/11 auto-updates
        // by default (AUOptions=4). Source: MS docs "Configure Automatic Updates".
        Asr("ASR-4.1", "Automatic Windows Updates enabled (AU option ≥ 3)",
            "Unpatched systems are the primary initial access vector. AUOptions=4 (auto-download and install) ensures security patches are applied without manual intervention. AUOptions=3 = auto-download only.",
            "$au = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name AUOptions -ErrorAction SilentlyContinue).AUOptions; if ($null -eq $au) { $au = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' -Name AUOptions -ErrorAction SilentlyContinue).AUOptions }; $au",
            @"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU :: AUOptions",
            ">=", "3", FindingSeverity.Critical,
            "4",
            new[]
            {
                "GPO: Computer Config > Admin Templates > Windows Components > Windows Update > Configure Automatic Updates = Enabled, AUOptions = 4 (Auto download and schedule the install)",
                "WSUS/SCCM: Managed environments should use WSUS with approval workflow + forced deployment windows",
                "Registry: Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' AUOptions 4"
            },
            "$p='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU'; if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }; Set-ItemProperty $p AUOptions 4"),

        Asr("ASR-4.2", "Windows Update service is running and not disabled",
            "The Windows Update service (wuauserv) must be running. Ransomware and some malware disable this service to prevent AV signature updates and OS patches.",
            "(Get-Service -Name wuauserv -ErrorAction SilentlyContinue).Status",
            "Get-Service -Name wuauserv",
            "=", "Running", FindingSeverity.High,
            "",
            new[]
            {
                "Start-Service -Name wuauserv; Set-Service -Name wuauserv -StartupType Automatic",
                "If stopped by malware, check: Get-WinEvent -LogName System | Where-Object {$_.Id -eq 7036 -and $_.Message -like '*Windows Update*'} | Select -First 10"
            },
            "Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service -Name wuauserv -ErrorAction SilentlyContinue"),
    };

    private static Finding Asr(
        string id, string name, string description,
        string script, string checkSource,
        string op, string expected, FindingSeverity severity,
        string defaultValue,
        string[] steps,
        string remediationPs = "")
    => new()
    {
        Id               = id,
        Module           = FindingModule.AttackSurface,
        Category         = id.StartsWith("ASR-1") ? "Unnecessary Services"
                         : id.StartsWith("ASR-2") ? "Principle of Least Privilege"
                         : id.StartsWith("ASR-3") ? "Windows Defender & Anti-Malware"
                         :                          "Patch Management",
        Name             = name,
        Description      = description,
        Rationale        = description,
        Benchmark        = "CIS / NSA / CISA",
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
