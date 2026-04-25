namespace Ordinis.Core.Models;

public class ScanProfile
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public List<string> FindingListFiles { get; set; } = new();
    public List<FindingModule> EnabledModules { get; set; } = new();
    public FindingSeverity MinimumSeverity { get; set; } = FindingSeverity.Low;
    public bool IncludeMSSQL { get; set; } = false;
    public bool IncludeIIS { get; set; } = false;
    public bool IncludeAD { get; set; } = false;

    public static ScanProfile CisLevel1Windows => new()
    {
        Name = "CIS Level 1 — Windows",
        Description = "CIS Benchmark Level 1 for Windows 10/11 and Server",
        EnabledModules = new() { FindingModule.Windows, FindingModule.Network, FindingModule.IPv6 },
        MinimumSeverity = FindingSeverity.Low
    };

    public static ScanProfile CisLevel2Windows => new()
    {
        Name = "CIS Level 2 — Windows",
        Description = "CIS Benchmark Level 2 (includes all Level 1 checks)",
        EnabledModules = new() { FindingModule.Windows, FindingModule.Network, FindingModule.IPv6 },
        MinimumSeverity = FindingSeverity.Info
    };

    public static ScanProfile DodStig => new()
    {
        Name = "DoD STIG — Windows",
        Description = "Defense Information Systems Agency STIG for Windows",
        EnabledModules = new() { FindingModule.Windows, FindingModule.Network, FindingModule.IPv6 },
        MinimumSeverity = FindingSeverity.Low
    };

    public static ScanProfile MicrosoftBaseline => new()
    {
        Name = "Microsoft Security Baseline",
        Description = "Microsoft's recommended security baseline settings",
        EnabledModules = new() { FindingModule.Windows, FindingModule.Network },
        MinimumSeverity = FindingSeverity.Low
    };

    public static ScanProfile FullScan => new()
    {
        Name = "Full Scan — All Modules",
        Description = "Runs all available checks across all modules",
        EnabledModules = Enum.GetValues<FindingModule>().ToList(),
        IncludeMSSQL = true,
        IncludeIIS   = true,
        IncludeAD    = true,
        MinimumSeverity = FindingSeverity.Info
    };

    public static List<ScanProfile> Defaults => new()
    {
        CisLevel1Windows, CisLevel2Windows, DodStig, MicrosoftBaseline, FullScan
    };
}
