using CsvHelper;
using CsvHelper.Configuration;
using System.Globalization;
using System.IO;
using Ordinis.Core.Models;

namespace Ordinis.Core.Services;

public class CsvFindingLoader
{
    private readonly string _dataRoot;

    public CsvFindingLoader()
    {
        _dataRoot = Path.Combine(AppContext.BaseDirectory, "Data", "FindingLists");
    }

    public CsvFindingLoader(string dataRoot) { _dataRoot = dataRoot; }

    public List<string> GetAvailableLists()
    {
        if (!Directory.Exists(_dataRoot)) return new();
        return Directory.GetFiles(_dataRoot, "*.csv", SearchOption.TopDirectoryOnly)
                        .Select(Path.GetFileName).Where(f => f != null).Cast<string>().OrderBy(f => f).ToList();
    }

    public List<Finding> LoadFromFile(string fileName)
    {
        string path = Path.Combine(_dataRoot, fileName);
        if (!File.Exists(path)) return new();
        return ParseCsv(path, fileName);
    }

    public List<Finding> LoadFromFiles(IEnumerable<string> fileNames)
    {
        var findings = new List<Finding>();
        foreach (var f in fileNames)
            findings.AddRange(LoadFromFile(f));
        return findings;
    }

    public List<Finding> LoadAll()
    {
        if (!Directory.Exists(_dataRoot)) return new();
        var findings = new List<Finding>();
        foreach (var file in Directory.GetFiles(_dataRoot, "*.csv"))
            findings.AddRange(ParseCsv(file, Path.GetFileName(file)));
        return findings;
    }

    private static List<Finding> ParseCsv(string path, string fileName)
    {
        var findings = new List<Finding>();
        var config = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            HasHeaderRecord = true,
            MissingFieldFound = null,
            BadDataFound = null
        };

        try
        {
            using var reader = new StreamReader(path);
            using var csv    = new CsvReader(reader, config);
            csv.Read();
            csv.ReadHeader();

            // Read by header name only when the column exists — GetField on an absent header
            // throws. This lets the curated Ordinis lists carry extra columns (Module,
            // Rationale, Remediation, RequiresRestart) while the 132 HardeningKitty lists,
            // which lack them, parse exactly as before.
            var headers = new HashSet<string>(csv.HeaderRecord ?? Array.Empty<string>(),
                                              StringComparer.OrdinalIgnoreCase);
            string? Field(string name) => headers.Contains(name) ? csv.GetField(name) : null;

            while (csv.Read())
            {
                string rawId = Field("ID") ?? "0";

                // A non-empty Module column marks an Ordinis curated list: keep the native ID
                // (NTLM-2.1) and its module so it shows and dispatches under that module, and
                // read the richer guidance columns. Standard lists have no Module column and
                // stay WIN-prefixed under the Windows module — unchanged behaviour.
                string? moduleField = Field("Module");
                bool    isCurated   = !string.IsNullOrWhiteSpace(moduleField);

                var finding = new Finding
                {
                    Id             = isCurated ? rawId : $"WIN-{rawId}",
                    Module         = isCurated ? MapModule(moduleField!) : FindingModule.Windows,
                    Category       = Field("Category") ?? string.Empty,
                    Name           = Field("Name") ?? string.Empty,
                    Description    = Field("Description") ?? string.Empty,
                    Rationale      = Field("Rationale") ?? string.Empty,
                    Severity       = MapSeverity(Field("Severity") ?? "Low"),
                    Benchmark      = isCurated ? "Ordinis" : DetectBenchmark(fileName),
                    BenchmarkRef   = rawId,
                    Method         = Field("Method") ?? string.Empty,
                    ExpectedValue  = Field("RecommendedValue") ?? string.Empty,
                    DefaultValue   = Field("DefaultValue") ?? string.Empty,
                    Operator       = Field("Operator") ?? "=",
                    BackupKey      = Field("RegistryPath") ?? string.Empty,
                    RequiresRestart = string.Equals(Field("RequiresRestart"), "true", StringComparison.OrdinalIgnoreCase)
                };

                // Populate check params based on method
                string method = finding.Method.ToLowerInvariant();
                if (method == "registry")
                {
                    finding.CheckParams["RegistryPath"] = Field("RegistryPath") ?? string.Empty;
                    finding.CheckParams["RegistryItem"] = Field("RegistryItem") ?? string.Empty;
                }
                else if (method is "secedit" or "auditpol" or "accountpolicy" or "accesschk"
                              or "localaccount" or "mpcomputerstatus" or "mppreference"
                              or "mppreferenceasr" or "mppreferenceexclusion" or "bitlockervolume"
                              or "windowsoptionalfeature" or "ps_script")
                {
                    // ASR rules carry their GUID, exclusion/bitlocker their property name, all in
                    // MethodArgument — without this, ~650 ASR/Defender/BitLocker rows in the CIS
                    // lists read an empty argument and fail as -NODATA-.
                    finding.CheckParams["MethodArgument"] = Field("MethodArgument") ?? string.Empty;
                }
                else if (method == "service")
                {
                    finding.CheckParams["ServiceName"] = Field("MethodArgument") ?? string.Empty;
                }
                else if (method == "ciminstance")
                {
                    finding.CheckParams["ClassName"]    = Field("ClassName")    ?? string.Empty;
                    finding.CheckParams["Namespace"]    = Field("Namespace")    ?? string.Empty;
                    finding.CheckParams["Property"]     = Field("Property")     ?? string.Empty;
                    finding.CheckParams["MethodArgument"] = Field("MethodArgument") ?? string.Empty;
                }
                else if (method == "registrylist")
                {
                    finding.CheckParams["RegistryPath"] = Field("RegistryPath") ?? string.Empty;
                    finding.CheckParams["RegistryItem"] = Field("RegistryItem") ?? string.Empty;
                }

                // Curated lists may carry hand-written remediation guidance; fall back to the
                // generated "Set X to Y" text when the column is absent or empty.
                string? remediation = Field("Remediation");
                finding.RemediationText = !string.IsNullOrWhiteSpace(remediation)
                    ? remediation
                    : BuildRemediationText(finding);
                findings.Add(finding);
            }
        }
        catch { /* Skip malformed files silently */ }

        return findings;
    }

    // Maps the curated-list Module column to the enum. Only the modules whose checks are
    // declarative enough to live in a CSV are listed; anything else falls back to Windows.
    private static FindingModule MapModule(string raw) => raw.Trim().ToLowerInvariant() switch
    {
        "ntlm"          => FindingModule.NTLM,
        "localsecurity" => FindingModule.LocalSecurity,
        "logging"       => FindingModule.Logging,
        "attacksurface" => FindingModule.AttackSurface,
        "network"       => FindingModule.Network,
        "ipv6"          => FindingModule.IPv6,
        _               => FindingModule.Windows
    };

    private static FindingSeverity MapSeverity(string raw) => raw.ToLowerInvariant() switch
    {
        "critical" => FindingSeverity.Critical,
        "high"     => FindingSeverity.High,
        "medium"   => FindingSeverity.Medium,
        "low"      => FindingSeverity.Low,
        "passed"   => FindingSeverity.Info,
        _          => FindingSeverity.Low
    };

    private static string DetectBenchmark(string fileName)
    {
        if (fileName.Contains("cis"))   return "CIS";
        if (fileName.Contains("stig"))  return "DoD STIG";
        if (fileName.Contains("bsi"))   return "BSI";
        if (fileName.Contains("msft") || fileName.Contains("microsoft")) return "Microsoft Baseline";
        return "Custom";
    }

    private static string BuildRemediationText(Finding f)
    {
        return f.Method.ToLowerInvariant() switch
        {
            "registry" => $"Set registry value '{f.CheckParams.GetValueOrDefault("RegistryItem")}' " +
                          $"at '{f.CheckParams.GetValueOrDefault("RegistryPath")}' to '{f.ExpectedValue}'.",
            "secedit"  => $"Set security policy '{f.CheckParams.GetValueOrDefault("MethodArgument")}' to '{f.ExpectedValue}' via Local Security Policy.",
            "auditpol" => $"Set audit policy subcategory '{f.CheckParams.GetValueOrDefault("MethodArgument")}' to '{f.ExpectedValue}'.",
            "service"  => $"Set service '{f.CheckParams.GetValueOrDefault("ServiceName")}' start type to '{f.ExpectedValue}'.",
            _          => $"Set '{f.Name}' to '{f.ExpectedValue}' according to {f.Benchmark} {f.BenchmarkRef}."
        };
    }
}
