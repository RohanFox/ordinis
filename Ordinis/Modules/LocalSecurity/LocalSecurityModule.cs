using Ordinis.Core.Models;
using Ordinis.Core.Services;
using Ordinis.Modules.Base;
using Ordinis.Modules.Windows;

namespace Ordinis.Modules.LocalSecurity;

public class LocalSecurityModule : IModule
{
    private readonly PowerShellRunner _ps;

    public FindingModule Module  => FindingModule.LocalSecurity;
    public string DisplayName    => "Local Security";
    public string Description    => "BitLocker, local accounts, LAPS, AppLocker/WDAC, UAC, Secure Boot, scheduled task hygiene";

    public LocalSecurityModule(PowerShellRunner ps) { _ps = ps; }

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

        finding.ActualValue = result.Output.Trim();
        finding.Status = WindowsModule.Evaluate(finding.ActualValue, finding.ExpectedValue, finding.Operator)
                         ? FindingStatus.Pass : FindingStatus.Fail;
    }

    private static List<Finding> GetChecks() => new()
    {
        // ── BitLocker ─────────────────────────────────────────────────────────────
        Ls("LS-1.1", "BitLocker enabled on OS drive",
            "The system drive must be encrypted with BitLocker to protect data at rest from offline attacks (Evil Maid, cold boot).",
            "(Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue).VolumeStatus",
            "Get-BitLockerVolume -MountPoint $env:SystemDrive",
            "=", "FullyEncrypted", FindingSeverity.Critical,
            new[]
            {
                "Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -TpmProtector",
                "GPO: Computer Config > Admin Templates > Windows Components > BitLocker > Require BitLocker for fixed drives",
                "Check TPM status first: Get-Tpm"
            }),

        Ls("LS-1.2", "BitLocker uses TPM protector",
            "A TPM key protector ties encryption to hardware, preventing offline key extraction. Password-only BitLocker is vulnerable if the drive is removed.",
            "((Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue).KeyProtector | Where-Object {$_.KeyProtectorType -eq 'Tpm' -or $_.KeyProtectorType -eq 'TpmPin'}).Count",
            "Get-BitLockerVolume | Select KeyProtector",
            ">=", "1", FindingSeverity.High,
            new[]
            {
                "Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector",
                "For higher security: Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmAndPinProtector -Pin (Read-Host -AsSecureString 'PIN')"
            }),

        // ── Local accounts ────────────────────────────────────────────────────────
        Ls("LS-2.1", "Built-in Administrator account is disabled",
            "The built-in Administrator (RID 500) has no lockout policy and is a constant brute-force target. Disable it and use LAPS-managed local admins.",
            "$a = Get-LocalUser | Where-Object {$_.SID -like '*-500'}; if ($a -and $a.Enabled) { 'Enabled' } else { 'Disabled' }",
            "Get-LocalUser | Where SID -like '*-500'",
            "=", "Disabled", FindingSeverity.High,
            new[]
            {
                "Disable-LocalUser -SID (Get-LocalUser | Where-Object {$_.SID -like '*-500'}).SID",
                "GPO: Computer Config > Windows Settings > Security Settings > Local Policies > Security Options > Accounts: Administrator account status = Disabled",
                "First create a named local admin account before disabling the built-in one"
            }),

        Ls("LS-2.2", "Built-in Guest account is disabled",
            "The Guest account provides unauthenticated network access and is a common lateral movement entry point.",
            "(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled",
            "Get-LocalUser -Name Guest",
            "=", "False", FindingSeverity.High,
            new[]
            {
                "Disable-LocalUser -Name 'Guest'",
                "GPO: Computer Config > Windows Settings > Security Settings > Local Policies > Security Options > Accounts: Guest account status = Disabled"
            }),

        Ls("LS-2.3", "No local accounts with blank passwords allowed over network",
            "LimitBlankPasswordUse=1 prevents accounts with blank passwords from being used for network authentication.",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LimitBlankPasswordUse -ErrorAction SilentlyContinue).LimitBlankPasswordUse",
            @"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa :: LimitBlankPasswordUse",
            "=", "1", FindingSeverity.Critical,
            new[]
            {
                "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' LimitBlankPasswordUse 1",
                "GPO: Accounts: Limit local account use of blank passwords to console logon only = Enabled"
            }),

        // ── LAPS ──────────────────────────────────────────────────────────────────
        Ls("LS-3.1", "LAPS (Local Administrator Password Solution) deployed",
            "LAPS rotates the local admin password per machine and stores it in AD/Azure AD. Without it, all machines share the same local admin password — compromise one, compromise all (lateral movement via pass-the-hash).",
            "(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions\\{D76B9641-3288-4f75-942D-087DE603E3EA}' -ErrorAction SilentlyContinue).ToString()",
            @"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}",
            "=", "True", FindingSeverity.Critical,
            new[]
            {
                "Install LAPS: Install-Module -Name LAPS from Microsoft or deploy the LAPS MSI",
                "For Windows 11 22H2+: Windows LAPS is built-in — enable via GPO: Computer Config > Admin Templates > System > LAPS",
                "AD schema must be extended: Update-LapsADSchema (legacy LAPS)"
            }),

        // ── AppLocker / WDAC ──────────────────────────────────────────────────────
        Ls("LS-4.1", "AppLocker or WDAC application control policy active",
            "Application allowlisting prevents execution of unauthorized code including ransomware, LOLBins, and attacker-dropped binaries. Critical defense-in-depth control.",
            "$alp = (Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue).RuleCollections.Count; $wdac = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue).CodeIntegrityPolicyEnforcementStatus; if ($alp -gt 0 -or $wdac -eq 2) { '1' } else { '0' }",
            "Get-AppLockerPolicy -Effective | Select RuleCollections; Get-CimInstance Win32_DeviceGuard",
            "=", "1", FindingSeverity.High,
            new[]
            {
                "AppLocker: GPO > Computer Config > Windows Settings > Security Settings > Application Control Policies > AppLocker",
                "WDAC: New-CIPolicy -Level Publisher -FilePath policy.xml; ConvertFrom-CIPolicy policy.xml policy.bin; Copy to C:\\Windows\\System32\\CodeIntegrity\\",
                "Start with Audit mode before switching to Enforce to identify legitimate binaries"
            }),

        // ── UAC ───────────────────────────────────────────────────────────────────
        Ls("LS-5.1", "UAC enabled (EnableLUA = 1)",
            "User Account Control restricts all users including admins to standard privileges by default. Disabling UAC removes this last line of defence against privilege escalation.",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA",
            @"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System :: EnableLUA",
            "=", "1", FindingSeverity.Critical,
            new[]
            {
                "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' EnableLUA 1",
                "GPO: Computer Config > Windows Settings > Security Settings > Local Policies > Security Options > User Account Control: Run all administrators in Admin Approval Mode = Enabled"
            }),

        Ls("LS-5.2", "UAC prompts for admin credentials (ConsentPromptBehaviorAdmin ≥ 1)",
            "ConsentPromptBehaviorAdmin=0 silently elevates without prompting — any process can gain SYSTEM silently. Must be ≥ 1 (prompt) or 2 (always prompt with credentials).",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin",
            @"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System :: ConsentPromptBehaviorAdmin",
            ">=", "1", FindingSeverity.High,
            new[]
            {
                "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' ConsentPromptBehaviorAdmin 2  # 2 = prompt for credentials, 1 = prompt for consent",
                "GPO: Computer Config > Security Options > User Account Control: Behavior of the elevation prompt for administrators"
            }),

        // ── Secure Boot ───────────────────────────────────────────────────────────
        Ls("LS-6.1", "Secure Boot is enabled",
            "Secure Boot ensures only signed bootloaders and OS kernels load. Without it, a bootkit can persist below the OS, survive reinstalls, and bypass all security software.",
            "Confirm-SecureBootUEFI -ErrorAction SilentlyContinue",
            "Confirm-SecureBootUEFI",
            "=", "True", FindingSeverity.Critical,
            new[]
            {
                "Enable in UEFI/BIOS firmware settings: Security > Secure Boot = Enabled",
                "Ensure all boot drivers are signed. Clear Secure Boot keys if in custom/legacy mode.",
                "Verify: Confirm-SecureBootUEFI should return True"
            }),

        // ── Scheduled Task hygiene ────────────────────────────────────────────────
        Ls("LS-7.1", "Task Scheduler history is enabled",
            "Task history is disabled by default but essential for detecting persistence mechanisms installed via scheduled tasks (common ransomware/APT technique).",
            "$sched = New-Object -ComObject Schedule.Service; $sched.Connect(); $sched.GetFolder('\\').GetTask('\\') 2>$null; $logName='Microsoft-Windows-TaskScheduler/Operational'; (Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue).IsEnabled",
            "Task Scheduler Operational Log",
            "=", "True", FindingSeverity.Medium,
            new[]
            {
                "wevtutil set-log 'Microsoft-Windows-TaskScheduler/Operational' /enabled:true",
                "GPO: Computer Config > Admin Templates > Windows Components > Task Scheduler > Enable Task Scheduler history = Enabled"
            }),

        Ls("LS-7.2", "No tasks running as SYSTEM from user-writable paths",
            "Scheduled tasks running as SYSTEM from writable directories (Temp, AppData, Downloads) indicate persistence or a misconfiguration attackers can hijack.",
            "(Get-ScheduledTask | Where-Object {$_.Principal.RunLevel -eq 'Highest' -or $_.Principal.UserId -eq 'SYSTEM'} | Where-Object {$_.Actions.Execute -match 'Temp|AppData|Downloads|Public'}).Count",
            "Get-ScheduledTask | Where Principal.UserId -eq SYSTEM",
            "=", "0", FindingSeverity.Critical,
            new[]
            {
                "Review and remove suspicious tasks: Get-ScheduledTask | Where-Object {$_.Principal.UserId -eq 'SYSTEM'} | Select TaskName,TaskPath,@{N='Exe';E={$_.Actions.Execute}}",
                "Unregister-ScheduledTask -TaskName 'SuspiciousTask' -Confirm:$false"
            }),

        // ── WMI Subscriptions (persistence detection) ────────────────────────────
        Ls("LS-8.1", "No permanent WMI event subscriptions (persistence backdoors)",
            "WMI event subscriptions (EventFilter + EventConsumer + FilterToConsumerBinding) are a fileless persistence mechanism used by APT groups. Legitimate software rarely uses them.",
            "(Get-WMIObject -Namespace root\\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue).Count",
            "Get-WMIObject -Namespace root\\subscription -Class __FilterToConsumerBinding",
            "=", "0", FindingSeverity.Critical,
            new[]
            {
                "List: Get-WMIObject -Namespace root\\subscription -Class __FilterToConsumerBinding | Select *",
                "Remove suspicious bindings: $filter = Get-WMIObject -Namespace root\\subscription -Class __EventFilter -Filter \"Name='MaliciousFilter'\"; $filter.Delete()",
                "Also check: __EventFilter and CommandLineEventConsumer classes"
            }),
    };

    private static Finding Ls(
        string id, string name, string description,
        string script, string checkSource,
        string op, string expected, FindingSeverity severity,
        string[] steps)
    => new()
    {
        Id               = id,
        Module           = FindingModule.LocalSecurity,
        Category         = id.StartsWith("LS-1") ? "BitLocker"
                         : id.StartsWith("LS-2") ? "Local Accounts"
                         : id.StartsWith("LS-3") ? "LAPS"
                         : id.StartsWith("LS-4") ? "Application Control"
                         : id.StartsWith("LS-5") ? "UAC"
                         : id.StartsWith("LS-6") ? "Secure Boot"
                         : id.StartsWith("LS-7") ? "Scheduled Tasks"
                         :                         "Persistence Detection",
        Name             = name,
        Description      = description,
        Rationale        = description,
        Benchmark        = "CIS / STIG",
        BenchmarkRef     = id,
        Severity         = severity,
        Method           = "ps_script",
        CheckParams      = new() { ["Script"] = script },
        ExpectedValue    = expected,
        Operator         = op,
        CheckSource      = checkSource,
        RemediationText  = steps[0],
        RemediationSteps = steps.ToList(),
        IsSafeToAutoFix  = false
    };
}
