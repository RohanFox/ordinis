using System.IO;
using Ordinis.Core.Models;
using Ordinis.Core.Services;
using Ordinis.Modules.Base;

namespace Ordinis.Modules.GPO;

public class GpoModule : IModule
{
    private readonly PowerShellRunner _ps;

    public FindingModule Module  => FindingModule.GPO;
    public string DisplayName    => "GPO Manager";
    public string Description    => "Group Policy Object management — export, apply via LGPO, view applied GPOs";

    public GpoModule(PowerShellRunner ps) { _ps = ps; }

    public Task<List<Finding>> GetFindingsAsync(ScanProfile profile, CancellationToken ct = default)
        => Task.FromResult(new List<Finding>());  // GPO module doesn't produce findings directly

    public Task AuditFindingAsync(Finding finding, ScanTarget target, CancellationToken ct = default)
        => Task.CompletedTask;

    /// <summary>Export current audit session failures as an LGPO-compatible .txt file.</summary>
    public async Task<string> ExportAsLgpoAsync(
        IEnumerable<Finding> failedFindings,
        string outputDirectory,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);
        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string outputFile = Path.Combine(outputDirectory, $"Ordinis_LGPO_{timestamp}.txt");

        var lines = new List<string>();
        foreach (var f in failedFindings.Where(f => f.Method.Equals("registry", StringComparison.OrdinalIgnoreCase)))
        {
            if (!f.CheckParams.TryGetValue("RegistryPath", out string? path)) continue;
            if (!f.CheckParams.TryGetValue("RegistryItem", out string? item)) continue;

            // LGPO format: Computer\Software\... → ValueName → type → value
            string hive = path.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase) ? "Computer"
                        : path.StartsWith("HKCU", StringComparison.OrdinalIgnoreCase) ? "User"
                        : "Computer";
            string subPath = path.Contains('\\') ? path[(path.IndexOf('\\') + 1)..] : path;

            bool isNumeric = int.TryParse(f.ExpectedValue, out _);
            string valueType = isNumeric ? "DWORD" : "SZ";

            lines.Add(hive);
            lines.Add(subPath);
            lines.Add(item);
            lines.Add($"{valueType}:{f.ExpectedValue}");
            lines.Add(string.Empty);
        }

        await File.WriteAllLinesAsync(outputFile, lines, System.Text.Encoding.UTF8, ct);
        return outputFile;
    }

    /// <summary>Apply an LGPO .txt file to the local machine using LGPO.exe.</summary>
    public async Task<(bool success, string message)> ApplyLgpoFileAsync(
        string lgpoFilePath,
        CancellationToken ct = default)
    {
        string lgpoExe = Path.Combine(AppContext.BaseDirectory, "Tools", "LGPO.exe");
        if (!File.Exists(lgpoExe))
            return (false, $"LGPO.exe not found at '{lgpoExe}'. Download from Microsoft Security Compliance Toolkit.");

        var result = await _ps.RunInlineAsync(
            $"& '{lgpoExe}' /t '{lgpoFilePath}' 2>&1", ct: ct);

        return (result.Success, result.Success ? "LGPO applied successfully." : result.Error);
    }

    /// <summary>Generate a Group Policy report (RSoP) for the current machine.</summary>
    public async Task<string> GenerateGpoReportAsync(string outputPath, CancellationToken ct = default)
    {
        var result = await _ps.RunInlineAsync(
            $"Get-GPResultantSetOfPolicy -ReportType Html -Path '{outputPath}' 2>&1", ct: ct);

        if (!result.Success)
        {
            // Fallback: use gpresult.exe
            var fallback = await _ps.RunInlineAsync(
                $"gpresult /H '{outputPath}' /F 2>&1", ct: ct);
            return fallback.Success ? outputPath : string.Empty;
        }
        return outputPath;
    }

    /// <summary>List all GPOs applied to the current machine.</summary>
    public async Task<List<GpoInfo>> GetAppliedGposAsync(CancellationToken ct = default)
    {
        var result = await _ps.RunInlineAsync(
            @"Get-GPResultantSetOfPolicy -ReportType Xml -Path $env:TEMP\rsop.xml 2>&1
              if (Test-Path $env:TEMP\rsop.xml) {
                [xml]$rsop = Get-Content $env:TEMP\rsop.xml
                $rsop.Rsop.ComputerResults.GPO | ForEach-Object {
                  [PSCustomObject]@{ Name=$_.Name; Guid=$_.Identifier.Identifier.'#text'; Status=$_.FilterAllowed }
                } | ConvertTo-Json
              } else { '[]' }", ct: ct);

        if (!result.Success || string.IsNullOrWhiteSpace(result.Output)) return new();
        try
        {
            return Newtonsoft.Json.JsonConvert.DeserializeObject<List<GpoInfo>>(result.Output) ?? new();
        }
        catch { return new(); }
    }
}

public class GpoInfo
{
    public string Name   { get; set; } = string.Empty;
    public string Guid   { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
}
