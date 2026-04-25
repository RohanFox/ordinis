using Ordinis.Core.Models;
using Ordinis.Core.Services;
using Ordinis.Modules.Base;
using Ordinis.Modules.Windows;

namespace Ordinis.Modules.AD;

public class AdModule : IModule
{
    private readonly PowerShellRunner _ps;

    public FindingModule Module  => FindingModule.ActiveDirectory;
    public string DisplayName    => "Active Directory";
    public string Description    => "PingCastle-style AD health check — password policy, privileged accounts, stale objects, trusts";

    public AdModule(PowerShellRunner ps) { _ps = ps; }

    public Task<List<Finding>> GetFindingsAsync(ScanProfile profile, CancellationToken ct = default)
        => Task.FromResult(GetAdFindings());

    public async Task AuditFindingAsync(Finding finding, ScanTarget target, CancellationToken ct = default)
    {
        finding.CheckParams.TryGetValue("Script", out string? script);
        if (string.IsNullOrEmpty(script))
        {
            finding.Status = FindingStatus.Skipped;
            return;
        }

        var result = await _ps.RunInlineAsync(script, ct: ct);
        if (!result.Success)
        {
            finding.Status       = FindingStatus.Error;
            finding.ErrorMessage = result.Error.Length > 0 ? result.Error : "AD check failed (is RSAT installed?)";
            return;
        }

        finding.ActualValue = result.Output.Trim();
        finding.Status      = WindowsModule.Evaluate(finding.ActualValue, finding.ExpectedValue, finding.Operator)
                              ? FindingStatus.Pass : FindingStatus.Fail;
    }

    private static List<Finding> GetAdFindings() => new()
    {
        Ad("AD-1.1",  "Password minimum length ≥ 14",
            "Domain password policy should require at least 14 characters.",
            "(Get-ADDefaultDomainPasswordPolicy).MinPasswordLength",
            ">=", "14", FindingSeverity.Critical,
            "Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot -MinPasswordLength 14"),

        Ad("AD-1.2",  "Password maximum age ≤ 60 days",
            "Passwords should expire within 60 days.",
            "([int](Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.TotalDays)",
            "<=", "60", FindingSeverity.High,
            "Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge (New-TimeSpan -Days 60)"),

        Ad("AD-1.3",  "Password history ≥ 24",
            "Password history should prevent reuse of at least the last 24 passwords.",
            "(Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount",
            ">=", "24", FindingSeverity.Medium,
            "Set-ADDefaultDomainPasswordPolicy -PasswordHistoryCount 24"),

        Ad("AD-1.4",  "Account lockout threshold ≤ 5",
            "Accounts should lock after 5 failed attempts to prevent brute force.",
            "(Get-ADDefaultDomainPasswordPolicy).LockoutThreshold",
            "<=", "5", FindingSeverity.Critical,
            "Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5"),

        Ad("AD-1.5",  "Account lockout duration ≥ 30 minutes",
            "Lockout duration should be at least 30 minutes.",
            "([int](Get-ADDefaultDomainPasswordPolicy).LockoutDuration.TotalMinutes)",
            ">=", "30", FindingSeverity.High,
            "Set-ADDefaultDomainPasswordPolicy -LockoutDuration (New-TimeSpan -Minutes 30)"),

        Ad("AD-1.6",  "Password complexity enabled",
            "Password complexity requirements should be enabled.",
            "(Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled",
            "=", "True", FindingSeverity.Critical,
            "Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled $true"),

        Ad("AD-2.1",  "No accounts with non-expiring passwords (except service accounts)",
            "User accounts should not have DONT_EXPIRE_PASSWORD set unless explicitly justified.",
            "(Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true -and ServicePrincipalNames -notlike '*'}).Count",
            "=", "0", FindingSeverity.High,
            "Audit users with: Get-ADUser -Filter {PasswordNeverExpires -eq $true}"),

        Ad("AD-2.2",  "No stale privileged accounts (>90 days inactive)",
            "Privileged accounts that have not logged in for over 90 days should be disabled.",
            "$cutoff = (Get-Date).AddDays(-90); (Get-ADGroupMember 'Domain Admins' | Get-ADUser -Properties LastLogonDate | Where-Object { $_.LastLogonDate -lt $cutoff -and $_.Enabled }).Count",
            "=", "0", FindingSeverity.Critical,
            "Disable stale domain admin accounts in Active Directory Users and Computers."),

        Ad("AD-2.3",  "Administrator account is renamed",
            "The built-in Administrator account should be renamed.",
            "(Get-ADUser -Filter {SID -like '*-500'}).SamAccountName",
            "!=", "Administrator", FindingSeverity.Medium,
            "Rename via ADUC or: Rename-ADObject -Identity (Get-ADUser Administrator).DistinguishedName -NewName 'NewName'"),

        Ad("AD-2.4",  "Guest account is disabled",
            "The built-in Guest account must be disabled.",
            "(Get-ADUser -Filter {SID -like '*-501'}).Enabled",
            "=", "False", FindingSeverity.High,
            "Disable-ADAccount -Identity (Get-ADUser -Filter {SID -like '*-501'})"),

        Ad("AD-3.1",  "Krbtgt password reset < 180 days ago",
            "The krbtgt account password should be rotated every 180 days.",
            "([int]((Get-Date) - (Get-ADUser krbtgt -Properties PasswordLastSet).PasswordLastSet).TotalDays)",
            "<=", "180", FindingSeverity.Critical,
            "Reset krbtgt password using Microsoft's New-KrbtgtKeys.ps1 script (do it twice, 10 hours apart)."),

        Ad("AD-3.2",  "No external domain trusts",
            "External domain trusts should be reviewed and minimised.",
            "(Get-ADTrust -Filter *).Count",
            "=", "0", FindingSeverity.Medium,
            "Review and remove unnecessary trusts: Remove-ADTrust"),

        Ad("AD-4.1",  "LDAP signing required",
            "LDAP signing prevents MITM attacks on LDAP traffic.",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name 'ldapserverintegrity' -ErrorAction SilentlyContinue).'ldapserverintegrity'",
            "=", "2", FindingSeverity.Critical,
            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name 'ldapserverintegrity' -Value 2"),

        Ad("AD-4.2",  "SMB signing required on DCs",
            "SMB signing must be required on domain controllers.",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters' -Name RequireSecuritySignature).RequireSecuritySignature",
            "=", "1", FindingSeverity.Critical,
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters' RequireSecuritySignature 1"),

        // ── Kerberoasting / AS-REP Roasting ───────────────────────────────────────
        AdKrb("KRB-1.1", "No AS-REP Roastable accounts (DONT_REQUIRE_PREAUTH)",
            "Accounts with DONT_REQUIRE_PREAUTH set allow an attacker to request an encrypted TGT without knowing the password, then crack it offline (AS-REP Roasting). All accounts should require pre-auth.",
            "(Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} -ErrorAction SilentlyContinue).Count",
            "=", "0", FindingSeverity.Critical,
            "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} | ForEach-Object { Set-ADAccountControl -Identity $_ -DoesNotRequirePreAuth $false }",
            "Kerberos pre-auth (DONT_REQ_PREAUTH) flag on AD user accounts"),

        AdKrb("KRB-1.2", "No Kerberoastable accounts with RC4 encryption",
            "User accounts with SPNs set can have their Kerberos service ticket requested and cracked offline (Kerberoasting). Accounts supporting only RC4 (bit 4, value 4) are weak targets. AES-only accounts are far harder to crack.",
            "(Get-ADUser -Filter {ServicePrincipalNames -like '*' -and Enabled -eq $true} -Properties ServicePrincipalNames,'msDS-SupportedEncryptionTypes' -ErrorAction SilentlyContinue | Where-Object { ($_.'msDS-SupportedEncryptionTypes' -band 4) -or ($_.'msDS-SupportedEncryptionTypes' -eq 0) }).Count",
            "=", "0", FindingSeverity.Critical,
            "For each SPN account: Set-ADUser -Identity <account> -KerberosEncryptionType AES256,AES128 then run: klist purge; also ensure msDS-SupportedEncryptionTypes = 24 (AES128+AES256)",
            "Get-ADUser with ServicePrincipalNames + msDS-SupportedEncryptionTypes"),

        AdKrb("KRB-1.3", "No computers with unconstrained Kerberos delegation (except DCs)",
            "Unconstrained delegation (TrustedForDelegation=True) means any service on that machine can impersonate any user to any service. If a domain admin connects to the machine, the TGT is cached and stealable (Printer Bug exploit).",
            "(Get-ADComputer -Filter {TrustedForDelegation -eq $true} -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '*DC*' }).Count",
            "=", "0", FindingSeverity.Critical,
            "Get-ADComputer -Filter {TrustedForDelegation -eq $true} | Where-Object {$_.Name -notlike '*DC*'} | ForEach-Object { Set-ADAccountControl -Identity $_ -TrustedForDelegation $false }",
            "Get-ADComputer -Filter {TrustedForDelegation -eq $true}"),

        AdKrb("KRB-1.4", "No user accounts with unconstrained Kerberos delegation",
            "User accounts with TrustedForDelegation are extremely dangerous — any user logging into a service running as that account will have their TGT captured.",
            "(Get-ADUser -Filter {TrustedForDelegation -eq $true -and Enabled -eq $true} -ErrorAction SilentlyContinue).Count",
            "=", "0", FindingSeverity.Critical,
            "Set-ADAccountControl -Identity <account> -TrustedForDelegation $false",
            "Get-ADUser -Filter {TrustedForDelegation -eq $true}"),

        // ── Golden / Diamond ticket defenses ──────────────────────────────────────
        AdKrb("KRB-2.1", "krbtgt password reset ≤ 180 days ago",
            "The krbtgt account's password is used to sign all Kerberos tickets. A stolen krbtgt hash enables Golden Tickets that persist even through password resets. Reset it every 180 days (twice, 10 hours apart to invalidate all TGTs).",
            "([int]((Get-Date) - (Get-ADUser krbtgt -Properties PasswordLastSet -ErrorAction SilentlyContinue).PasswordLastSet).TotalDays)",
            "<=", "180", FindingSeverity.Critical,
            "Use Microsoft New-KrbtgtKeys.ps1 script. Reset TWICE with a 10-hour gap: first reset invalidates old TGTs, second reset cleans up. Monitor for Golden Ticket abuse during the window.",
            "Get-ADUser krbtgt -Properties PasswordLastSet"),

        AdKrb("KRB-2.2", "Privileged accounts are members of Protected Users group",
            "The Protected Users security group disables NTLM, RC4 Kerberos, unconstrained delegation, and credential caching for members. All tier-0 accounts (DA, EA, Schema Admins) should be in this group.",
            "(Get-ADGroupMember 'Domain Admins' -ErrorAction SilentlyContinue | ForEach-Object { (Get-ADUser $_ -Properties MemberOf).MemberOf } | Where-Object { $_ -like '*Protected Users*' }).Count",
            ">=", "1", FindingSeverity.High,
            "Add-ADGroupMember -Identity 'Protected Users' -Members (Get-ADGroupMember 'Domain Admins'). Test carefully — Protected Users breaks NTLM auth, so service accounts must not be members.",
            "Get-ADGroupMember 'Protected Users'"),

        AdKrb("KRB-2.3", "Kerberos ticket lifetime ≤ 10 hours",
            "A maximum ticket lifetime of 10 hours limits how long a stolen TGT (from Golden Ticket or pass-the-ticket) can be used without renewal. Default is 10 hours.",
            "([int](Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue).MaxTicketAge.TotalHours)",
            "<=", "10", FindingSeverity.Medium,
            "GPO: Computer Config > Windows Settings > Security Settings > Account Policies > Kerberos Policy > Maximum lifetime for user ticket = 10 hours",
            "Get-ADDefaultDomainPasswordPolicy MaxTicketAge"),

        AdKrb("KRB-2.4", "Kerberos service ticket lifetime ≤ 600 minutes",
            "Service tickets (TGS) should expire quickly. A stolen service ticket is usable until expiry — shorter lifetime limits the attack window.",
            "([int](Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue).MaxServiceAge.TotalMinutes)",
            "<=", "600", FindingSeverity.Low,
            "GPO: Computer Config > Windows Settings > Security Settings > Account Policies > Kerberos Policy > Maximum lifetime for service ticket = 600 minutes",
            "Get-ADDefaultDomainPasswordPolicy MaxServiceAge"),

        // ── AES encryption enforcement ────────────────────────────────────────────
        AdKrb("KRB-3.1", "DES Kerberos encryption disabled",
            "DES is cryptographically broken (56-bit). DES Kerberos tickets can be cracked in seconds on modern hardware.",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters' -Name 'SupportedEncryptionTypes' -ErrorAction SilentlyContinue).SupportedEncryptionTypes",
            "!=", "3", FindingSeverity.Critical,
            "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters' SupportedEncryptionTypes 2147483640  # AES128+AES256+RC4, no DES. For AES-only use 24.",
            @"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters :: SupportedEncryptionTypes"),
    };

    private static Finding Ad(
        string id, string name, string description,
        string script, string op, string expected,
        FindingSeverity severity, string remediation)
    => new()
    {
        Id              = id,
        Module          = FindingModule.ActiveDirectory,
        Category        = id.StartsWith("AD-1") ? "Password Policy"
                        : id.StartsWith("AD-2") ? "Privileged Accounts"
                        : id.StartsWith("AD-3") ? "Kerberos & Trusts"
                        :                         "Protocol Security",
        Name            = name,
        Description     = description,
        Benchmark       = "CIS AD / PingCastle",
        BenchmarkRef    = id,
        Severity        = severity,
        Method          = "ad_script",
        CheckParams     = new() { ["Script"] = script },
        ExpectedValue   = expected,
        Operator        = op,
        CheckSource     = "Active Directory PowerShell module",
        RemediationText = remediation,
        IsSafeToAutoFix = false
    };

    private static Finding AdKrb(
        string id, string name, string description,
        string script, string op, string expected,
        FindingSeverity severity, string remediation, string checkSource)
    => new()
    {
        Id               = id,
        Module           = FindingModule.Kerberos,
        Category         = id.StartsWith("KRB-1") ? "Kerberoasting / AS-REP Roasting"
                         : id.StartsWith("KRB-2") ? "Golden & Diamond Ticket Defenses"
                         :                          "Encryption Policy",
        Name             = name,
        Description      = description,
        Rationale        = description,
        Benchmark        = "CIS AD / MITRE ATT&CK T1558",
        BenchmarkRef     = id,
        Severity         = severity,
        Method           = "ad_script",
        CheckParams      = new() { ["Script"] = script },
        ExpectedValue    = expected,
        Operator         = op,
        CheckSource      = checkSource,
        RemediationText  = remediation,
        RemediationSteps = new() { remediation },
        IsSafeToAutoFix  = false
    };
}
