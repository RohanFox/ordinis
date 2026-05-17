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

            while (csv.Read())
            {
                var finding = new Finding
                {
                    Id             = $"WIN-{csv.GetField("ID") ?? "0"}",
                    Module         = FindingModule.Windows,
                    Category       = csv.GetField("Category") ?? string.Empty,
                    Name           = csv.GetField("Name") ?? string.Empty,
                    Severity       = MapSeverity(csv.GetField("Severity") ?? "Low"),
                    Benchmark      = DetectBenchmark(fileName),
                    BenchmarkRef   = csv.GetField("ID") ?? string.Empty,
                    Method         = csv.GetField("Method") ?? string.Empty,
                    ExpectedValue  = csv.GetField("RecommendedValue") ?? string.Empty,
                    DefaultValue   = csv.GetField("DefaultValue") ?? string.Empty,
                    Operator       = csv.GetField("Operator") ?? "=",
                    BackupKey      = csv.GetField("RegistryPath") ?? string.Empty
                };

                // Populate check params based on method
                string method = finding.Method.ToLowerInvariant();
                if (method == "registry")
                {
                    finding.CheckParams["RegistryPath"] = csv.GetField("RegistryPath") ?? string.Empty;
                    finding.CheckParams["RegistryItem"] = csv.GetField("RegistryItem") ?? string.Empty;
                }
                else if (method is "secedit" or "auditpol" or "accountpolicy" or "accesschk"
                              or "localaccount" or "mpcomputerstatus" or "mppreference"
                              or "windowsoptionalfeature" or "ps_script")
                {
                    finding.CheckParams["MethodArgument"] = csv.GetField("MethodArgument") ?? string.Empty;
                }
                else if (method == "service")
                {
                    finding.CheckParams["ServiceName"] = csv.GetField("MethodArgument") ?? string.Empty;
                }
                else if (method == "ciminstance")
                {
                    finding.CheckParams["ClassName"]    = csv.GetField("ClassName")    ?? string.Empty;
                    finding.CheckParams["Namespace"]    = csv.GetField("Namespace")    ?? string.Empty;
                    finding.CheckParams["Property"]     = csv.GetField("Property")     ?? string.Empty;
                    finding.CheckParams["MethodArgument"] = csv.GetField("MethodArgument") ?? string.Empty;
                }
                else if (method == "registrylist")
                {
                    finding.CheckParams["RegistryPath"] = csv.GetField("RegistryPath") ?? string.Empty;
                    finding.CheckParams["RegistryItem"] = csv.GetField("RegistryItem") ?? string.Empty;
                }

                finding.RemediationText = BuildRemediationText(finding);
                findings.Add(finding);
            }
        }
        catch { /* Skip malformed files silently */ }

        return findings;
    }

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
