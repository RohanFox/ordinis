using Ordinis.Core.Models;
using Ordinis.Core.Services;
using Ordinis.Modules.Base;

namespace Ordinis.Modules.Network;

public class NetworkModule : IModule
{
    private readonly PowerShellRunner _ps;

    public FindingModule Module  => FindingModule.Network;
    public string DisplayName    => "Network & IPv6";
    public string Description    => "SMB, RDP, LLMNR, NetBIOS, IPv6 adapter/protocol checks and anomaly detection";

    // NET-4.x findings are tagged IPv6; this module audits both.
    public IReadOnlySet<FindingModule> Handles { get; } =
        new HashSet<FindingModule> { FindingModule.Network, FindingModule.IPv6 };

    public NetworkModule(PowerShellRunner ps) { _ps = ps; }

    public Task<List<Finding>> GetFindingsAsync(ScanProfile profile, CancellationToken ct = default)
        => Task.FromResult(GetNetworkFindings());

    public async Task AuditFindingAsync(Finding finding, ScanTarget target, CancellationToken ct = default)
    {
        finding.CheckParams.TryGetValue("Script", out string? script);
        if (string.IsNullOrEmpty(script))
        {
            await new Windows.WindowsModule(new CsvFindingLoader(), _ps)
                  .AuditFindingAsync(finding, target, ct);
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
        finding.Status = Windows.WindowsModule.Evaluate(finding.ActualValue, finding.ExpectedValue, finding.Operator)
                         ? FindingStatus.Pass : FindingStatus.Fail;
    }

    private static List<Finding> GetNetworkFindings() => new()
    {
        // ── SMB ──────────────────────────────────────────────────────────────────
        Net("NET-1.1", "SMBv1 is disabled",
            "SMBv1 is vulnerable to EternalBlue/WannaCry. Must be disabled.",
            "((Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State)",
            "=", "Disabled", FindingSeverity.Critical,
            "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"),

        Net("NET-1.2", "SMB signing required (client)",
            "SMB signing prevents MITM attacks on file shares.",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters').RequireSecuritySignature",
            "=", "1", FindingSeverity.High,
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' RequireSecuritySignature 1"),

        Net("NET-1.3", "SMB signing required (server)",
            "SMB signing must be required on the server side.",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters').RequireSecuritySignature",
            "=", "1", FindingSeverity.High,
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters' RequireSecuritySignature 1"),

        // ── RDP ───────────────────────────────────────────────────────────────────
        Net("NET-2.1", "RDP Network Level Authentication (NLA) required",
            "NLA authenticates users before establishing an RDP session.",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication",
            "=", "1", FindingSeverity.Critical,
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' UserAuthentication 1"),

        Net("NET-2.2", "RDP encryption level is High",
            "RDP connections should use the highest encryption level.",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').MinEncryptionLevel",
            "=", "3", FindingSeverity.High,
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' MinEncryptionLevel 3"),

        // ── LLMNR / NetBIOS / mDNS ────────────────────────────────────────────────
        // Windows default when GPO key absent: LLMNR is enabled (1).
        // Source: MS docs "Link-Local Multicast Name Resolution" — enabled by default until disabled via GPO.
        Net("NET-3.1", "LLMNR is disabled",
            "LLMNR can be abused for credential capture (Responder attacks).",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -ErrorAction SilentlyContinue).EnableMulticast",
            "=", "0", FindingSeverity.High,
            "$p='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient'; if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }; Set-ItemProperty $p EnableMulticast 0",
            "1"),

        Net("NET-3.2", "NetBIOS over TCP/IP disabled on all adapters",
            "NetBIOS can be used for credential capture and name poisoning.",
            "$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE; ($adapters | Where-Object {$_.TcpipNetbiosOptions -ne 2}).Count",
            "=", "0", FindingSeverity.High,
            "Set NetBIOS to Disabled on each adapter via Network Adapter Properties > TCP/IPv4 > Advanced > WINS tab."),

        // Windows default when value absent: mDNS is enabled (1).
        // Source: MS KB — EnableMDNS registry value controls mDNS; absent means enabled.
        Net("NET-3.3", "mDNS disabled",
            "mDNS (Bonjour/Zeroconf) can be used for network reconnaissance.",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' -Name 'EnableMDNS' -ErrorAction SilentlyContinue).EnableMDNS",
            "=", "0", FindingSeverity.Medium,
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' EnableMDNS 0",
            "1"),

        Net("NET-3.4", "WPAD disabled (WinHttpAutoProxySvc stopped)",
            "WPAD can be exploited for MITM via spoofed proxy discovery.",
            "(Get-Service -Name 'WinHttpAutoProxySvc' -ErrorAction SilentlyContinue).StartType",
            "=", "Disabled", FindingSeverity.Medium,
            "Set-Service -Name WinHttpAutoProxySvc -StartupType Disabled; Stop-Service WinHttpAutoProxySvc"),

        // ── IPv6 ──────────────────────────────────────────────────────────────────
        Net("NET-4.1", "Teredo disabled",
            "Teredo tunnels IPv6 over IPv4 and can bypass firewall rules.",
            "(netsh interface teredo show state | Select-String 'State').ToString().Trim()",
            "contains", "disabled", FindingSeverity.High,
            "netsh interface teredo set state disabled"),

        Net("NET-4.2", "ISATAP disabled",
            "ISATAP is an IPv6 transition mechanism that can expose the network.",
            "(netsh interface isatap show state | Select-String 'State').ToString().Trim()",
            "contains", "disabled", FindingSeverity.High,
            "netsh interface isatap set state disabled"),

        Net("NET-4.3", "6to4 disabled",
            "6to4 automatic tunneling should be disabled.",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\6to4' -Name 'Start' -ErrorAction SilentlyContinue).Start",
            "=", "4", FindingSeverity.Medium,
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\6to4' Start 4"),

        Net("NET-4.4", "IPv6 privacy extensions enabled",
            "IPv6 privacy extensions generate temporary addresses for outbound connections.",
            "(netsh interface ipv6 show privacy | Select-String 'enabled|disabled').ToString().ToLower().Trim()",
            "contains", "enabled", FindingSeverity.Low,
            "netsh interface ipv6 set privacy state=enabled store=persistent"),

        Net("NET-4.5", "IPv6 firewall is enabled on all profiles",
            "The Windows Firewall must be active for IPv6 on Domain, Private, and Public profiles.",
            "((Get-NetFirewallProfile).Enabled | Where-Object {$_ -ne $true}).Count",
            "=", "0", FindingSeverity.Critical,
            "Set-NetFirewallProfile -All -Enabled True"),

        // ── Firewall ──────────────────────────────────────────────────────────────
        Net("NET-5.1", "Windows Firewall enabled on all profiles",
            "Windows Firewall must be enabled on Domain, Private, and Public profiles.",
            "((Get-NetFirewallProfile | Where-Object {$_.Enabled -ne $true}).Count)",
            "=", "0", FindingSeverity.Critical,
            "Set-NetFirewallProfile -All -Enabled True"),

        Net("NET-5.2", "Outbound connections default to Block (Public profile)",
            "The Public profile should block outbound connections by default.",
            "(Get-NetFirewallProfile -Profile Public).DefaultOutboundAction",
            "=", "Block", FindingSeverity.Medium,
            "Set-NetFirewallProfile -Profile Public -DefaultOutboundAction Block"),
    };

    private static Finding Net(
        string id, string name, string description,
        string script, string op, string expected,
        FindingSeverity severity, string remediation, string defaultValue = "")
    => new()
    {
        Id              = id,
        Module          = id.StartsWith("NET-4") ? FindingModule.IPv6 : FindingModule.Network,
        Category        = id.StartsWith("NET-1") ? "SMB"
                        : id.StartsWith("NET-2") ? "RDP"
                        : id.StartsWith("NET-3") ? "Name Resolution Protocols"
                        : id.StartsWith("NET-4") ? "IPv6 Transition Protocols"
                        :                          "Firewall",
        Name            = name,
        Description     = description,
        Benchmark       = "CIS / STIG",
        BenchmarkRef    = id,
        Severity        = severity,
        Method          = "ps_script",
        CheckParams     = new() { ["Script"] = script },
        ExpectedValue   = expected,
        DefaultValue    = defaultValue,
        Operator        = op,
        RemediationText = remediation,
        IsSafeToAutoFix = true
    };
}
