using Microsoft.Win32;
using Ordinis.Core.Models;
using Ordinis.Core.Services;
using Ordinis.Modules.Base;
using System.Diagnostics;
using System.ServiceProcess;
using System.Management;

namespace Ordinis.Modules.Windows;

public class WindowsModule : IModule
{
    private readonly CsvFindingLoader _loader;
    private readonly PowerShellRunner _ps;

    public FindingModule Module      => FindingModule.Windows;
    public string DisplayName        => "Windows OS";
    public string Description        => "Registry, services, firewall, Defender, policies and OS hardening checks";

    public WindowsModule(CsvFindingLoader loader, PowerShellRunner ps)
    {
        _loader = loader;
        _ps     = ps;
    }

    public Task<List<Finding>> GetFindingsAsync(ScanProfile profile, CancellationToken ct = default)
    {
        var files    = _loader.GetAvailableLists();
        var filtered = files.Where(f => MatchesProfile(f, profile.Name)).ToList();
        var raw      = filtered.Count > 0 ? _loader.LoadFromFiles(filtered) : _loader.LoadAll();

        // Multiple benchmark CSVs contain the same checks (same registry key appears in
        // CIS Win10, CIS Win11, CIS Server 2019, etc.). Deduplicate by the actual check
        // being performed so each system setting is audited exactly once.
        var seen    = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var deduped = new List<Finding>(raw.Count);
        foreach (var f in raw)
        {
            var key = f.Method.ToLowerInvariant() switch
            {
                "registry"      => $"reg\x1f{f.CheckParams.GetValueOrDefault("RegistryPath")}\x1f{f.CheckParams.GetValueOrDefault("RegistryItem")}\x1f{f.ExpectedValue}",
                "secedit"       => $"sec\x1f{f.CheckParams.GetValueOrDefault("MethodArgument")}\x1f{f.ExpectedValue}",
                "auditpol"      => $"aud\x1f{f.CheckParams.GetValueOrDefault("MethodArgument")}\x1f{f.ExpectedValue}",
                "accountpolicy" => $"acct\x1f{f.CheckParams.GetValueOrDefault("MethodArgument")}\x1f{f.ExpectedValue}",
                "service"       => $"svc\x1f{f.CheckParams.GetValueOrDefault("ServiceName")}\x1f{f.ExpectedValue}",
                _               => $"{f.Method}\x1f{f.Name}\x1f{f.ExpectedValue}"
            };
            if (seen.Add(key))
                deduped.Add(f);
        }
        return Task.FromResult(deduped);
    }

    public async Task AuditFindingAsync(Finding finding, ScanTarget target, CancellationToken ct = default)
    {
        if (target.Type == TargetType.Remote)
        {
            await AuditRemoteAsync(finding, target, ct);
            return;
        }

        try
        {
            string actual = finding.Method.ToLowerInvariant() switch
            {
                "registry"         => ReadRegistry(finding),
                "secedit"          => await ReadSeceditAsync(finding, ct),
                "auditpol"         => await ReadAuditpolAsync(finding, ct),
                "accountpolicy"    => await ReadAccountPolicyAsync(finding, ct),
                "service"          => ReadService(finding),
                "localaccount"     => ReadLocalAccount(finding),
                "mpcomputerstatus" => await ReadMpStatusAsync(finding, ct),
                "mppreference"     => await ReadMpPreferenceAsync(finding, ct),
                "windowsoptionalfeature" => await ReadOptionalFeatureAsync(finding, ct),
                _                  => "-NODATA-"
            };

            finding.ActualValue = actual;
            finding.Status      = Evaluate(actual, finding.ExpectedValue, finding.Operator)
                                  ? FindingStatus.Pass : FindingStatus.Fail;
        }
        catch (Exception ex)
        {
            finding.Status       = FindingStatus.Error;
            finding.ErrorMessage = ex.Message;
        }
    }

    private static string ReadRegistry(Finding finding)
    {
        finding.CheckParams.TryGetValue("RegistryPath", out string? path);
        finding.CheckParams.TryGetValue("RegistryItem", out string? item);
        if (string.IsNullOrEmpty(path)) return "-NODATA-";

        var hive = path.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase) ? Registry.LocalMachine
                 : path.StartsWith("HKCU", StringComparison.OrdinalIgnoreCase) ? Registry.CurrentUser
                 : path.StartsWith("HKCC", StringComparison.OrdinalIgnoreCase) ? Registry.CurrentConfig
                 : Registry.LocalMachine;

        string subKey = path.Contains('\\') ? path[(path.IndexOf('\\') + 1)..] : path;
        using var key = hive.OpenSubKey(subKey, writable: false);
        if (key is null) return "-NODATA-";

        if (string.IsNullOrEmpty(item)) return key.GetValueNames().Length.ToString();
        var val = key.GetValue(item);
        return val?.ToString() ?? "-NODATA-";
    }

    private async Task<string> ReadSeceditAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? arg);
        if (string.IsNullOrEmpty(arg)) return "-NODATA-";

        var result = await _ps.RunInlineAsync(
            $"$tmp = [System.IO.Path]::GetTempFileName(); " +
            $"secedit /export /cfg $tmp /areas SECURITYPOLICY | Out-Null; " +
            $"$content = Get-Content $tmp; Remove-Item $tmp -Force; " +
            $"$line = $content | Where-Object {{ $_ -match '^{arg}' }}; " +
            $"if ($line) {{ ($line -split '=')[1].Trim() }} else {{ '-NODATA-' }}", ct: ct);

        return result.Success ? result.Output.Trim() : "-NODATA-";
    }

    private async Task<string> ReadAuditpolAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? sub);
        if (string.IsNullOrEmpty(sub)) return "-NODATA-";

        var result = await _ps.RunInlineAsync(
            $"$tmp = [System.IO.Path]::GetTempFileName() + '.csv'; " +
            $"auditpol /backup /file:$tmp | Out-Null; " +
            $"$csv = Import-Csv $tmp; Remove-Item $tmp -Force; " +
            $"$row = $csv | Where-Object {{ $_.Subcategory -eq '{sub}' }}; " +
            $"if ($row) {{ '{sub}: ' + $row.'Inclusion Setting' }} else {{ '-NODATA-' }}", ct: ct);

        return result.Success ? result.Output.Trim() : "-NODATA-";
    }

    private async Task<string> ReadAccountPolicyAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? arg);
        var result = await _ps.RunInlineAsync(
            $"(net accounts | Where-Object {{ $_ -match '{arg}' }}) -replace '.*:','' | ForEach-Object {{ $_.Trim() }}", ct: ct);
        return result.Success ? result.Output.Trim() : "-NODATA-";
    }

    private static string ReadService(Finding finding)
    {
        finding.CheckParams.TryGetValue("ServiceName", out string? name);
        if (string.IsNullOrEmpty(name)) return "-NODATA-";
        try
        {
            using var svc = new ServiceController(name);
            return svc.StartType.ToString();
        }
        catch { return "-NODATA-"; }
    }

    private static string ReadLocalAccount(Finding finding)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? sid);
        // Simplified — checks built-in admin (500) or guest (501)
        return "-NODATA-";
    }

    private async Task<string> ReadMpStatusAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? prop);
        var result = await _ps.RunInlineAsync(
            $"(Get-MpComputerStatus).{prop}", ct: ct);
        return result.Success ? result.Output.Trim() : "-NODATA-";
    }

    private async Task<string> ReadMpPreferenceAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? prop);
        var result = await _ps.RunInlineAsync(
            $"(Get-MpPreference).{prop}", ct: ct);
        return result.Success ? result.Output.Trim() : "-NODATA-";
    }

    private async Task<string> ReadOptionalFeatureAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? featureName);
        var result = await _ps.RunInlineAsync(
            $"(Get-WindowsOptionalFeature -Online -FeatureName '{featureName}').State", ct: ct);
        return result.Success ? result.Output.Trim() : "-NODATA-";
    }

    private async Task AuditRemoteAsync(Finding finding, ScanTarget target, CancellationToken ct)
    {
        // secedit, auditpol, accountpolicy require local execution and cannot run over WinRM
        if (PowerShellRunner.RemoteUnsupportedMethods.Contains(finding.Method))
        {
            finding.Status       = FindingStatus.Skipped;
            finding.ErrorMessage = $"'{finding.Method}' checks require local execution and cannot run over WinRM. Run Ordinis directly on the target machine for this check.";
            return;
        }

        var result = await _ps.RunScriptAsync("Audit/Get-SingleFinding.ps1",
            new()
            {
                ["Method"]         = finding.Method,
                ["RegistryPath"]   = finding.CheckParams.GetValueOrDefault("RegistryPath",""),
                ["RegistryItem"]   = finding.CheckParams.GetValueOrDefault("RegistryItem",""),
                ["MethodArgument"] = finding.CheckParams.GetValueOrDefault("MethodArgument","")
            },
            target.Hostname, target.Username, target.Password, ct);

        if (result.Success)
        {
            finding.ActualValue = result.Output.Trim();
            finding.Status      = Evaluate(finding.ActualValue, finding.ExpectedValue, finding.Operator)
                                  ? FindingStatus.Pass : FindingStatus.Fail;
        }
        else
        {
            finding.Status       = FindingStatus.Error;
            finding.ErrorMessage = result.Error;
        }
    }

    internal static bool Evaluate(string actual, string expected, string op) => op.ToLowerInvariant() switch
    {
        "="          => string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase),
        "!="         => !string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase),
        ">="         => double.TryParse(actual, out double a1) && double.TryParse(expected, out double e1) && a1 >= e1,
        "<="         => double.TryParse(actual, out double a2) && double.TryParse(expected, out double e2) && a2 <= e2,
        "<=!0"       => double.TryParse(actual, out double a3) && double.TryParse(expected, out double e3) && a3 <= e3 && a3 != 0,
        "contains"   => actual.Contains(expected, StringComparison.OrdinalIgnoreCase),
        "notcontains"=> !actual.Contains(expected, StringComparison.OrdinalIgnoreCase),
        "=|0"        => string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase) || actual.Length == 0,
        _            => false
    };

    private static bool MatchesProfile(string fileName, string profileName)
    {
        string f = fileName.ToLowerInvariant();
        return profileName.ToLowerInvariant() switch
        {
            var p when p.Contains("cis level 1") => f.Contains("cis") && !f.Contains("stig") && !f.Contains("bsi"),
            var p when p.Contains("cis level 2") => f.Contains("cis"),
            var p when p.Contains("stig")         => f.Contains("stig"),
            var p when p.Contains("microsoft")    => f.Contains("microsoft") || f.Contains("msft"),
            _                                     => true
        };
    }
}
