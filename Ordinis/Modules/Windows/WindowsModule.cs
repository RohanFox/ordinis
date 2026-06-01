using Microsoft.Win32;
using Ordinis.Core.Models;
using Ordinis.Core.Services;
using Ordinis.Modules.Base;
using System.ServiceProcess;
using System.Text.RegularExpressions;

namespace Ordinis.Modules.Windows;

public class WindowsModule : IModule
{
    private readonly CsvFindingLoader _loader;
    private readonly PowerShellRunner _ps;
    private readonly OsProfile?       _osProfile;

    public FindingModule Module      => FindingModule.Windows;
    public string DisplayName        => "Windows OS";
    public string Description        => "Registry, services, firewall, Defender, policies and OS hardening checks";

    public WindowsModule(CsvFindingLoader loader, PowerShellRunner ps, OsProfile? osProfile = null)
    {
        _loader    = loader;
        _ps        = ps;
        _osProfile = osProfile;
    }

    public Task<List<Finding>> GetFindingsAsync(ScanProfile profile, CancellationToken ct = default)
    {
        var files     = _loader.GetAvailableLists();
        var byProfile = files.Where(f => MatchesProfile(f, profile.Name)).ToList();
        var source    = byProfile.Count > 0 ? byProfile : files;
        var filtered  = source.Where(f => MatchesOs(f, _osProfile)).ToList();
        if (filtered.Count == 0) filtered = source;
        var raw = _loader.LoadFromFiles(filtered);

        var seen    = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var deduped = new List<Finding>(raw.Count);
        foreach (var f in raw)
        {
            var key = f.Method.ToLowerInvariant() switch
            {
                "registry"      => $"reg\x1f{f.CheckParams.GetValueOrDefault("RegistryPath")}\x1f{f.CheckParams.GetValueOrDefault("RegistryItem")}\x1f{f.ExpectedValue}",
                "registrylist"  => $"regl\x1f{f.CheckParams.GetValueOrDefault("RegistryPath")}\x1f{f.CheckParams.GetValueOrDefault("RegistryItem")}\x1f{f.ExpectedValue}",
                "secedit"       => $"sec\x1f{f.CheckParams.GetValueOrDefault("MethodArgument")}\x1f{f.ExpectedValue}",
                "auditpol"      => $"aud\x1f{f.CheckParams.GetValueOrDefault("MethodArgument")}\x1f{f.ExpectedValue}",
                "accountpolicy" => $"acct\x1f{f.CheckParams.GetValueOrDefault("MethodArgument")}\x1f{f.ExpectedValue}",
                "service"       => $"svc\x1f{f.CheckParams.GetValueOrDefault("ServiceName")}\x1f{f.ExpectedValue}",
                "ciminstance"   => $"cim\x1f{f.CheckParams.GetValueOrDefault("ClassName")}\x1f{f.CheckParams.GetValueOrDefault("Property")}\x1f{f.ExpectedValue}",
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
                "registry"               => ReadRegistry(finding),
                "registrylist"           => ReadRegistryList(finding),
                "secedit"                => await ReadSeceditAsync(finding, ct),
                "auditpol"               => await ReadAuditpolAsync(finding, ct),
                "accountpolicy"          => await ReadAccountPolicyAsync(finding, ct),
                "accesschk"              => await ReadAccessChkAsync(finding, ct),
                "service"                => ReadService(finding),
                "localaccount"           => await ReadLocalAccountAsync(finding, ct),
                "mpcomputerstatus"       => await ReadMpStatusAsync(finding, ct),
                "mppreference"           => await ReadMpPreferenceAsync(finding, ct),
                "mppreferenceasr"        => await ReadMpPreferenceAsrAsync(finding, ct),
                "mppreferenceexclusion"  => await ReadMpPreferenceExclusionAsync(finding, ct),
                "windowsoptionalfeature" => await ReadOptionalFeatureAsync(finding, ct),
                "ciminstance"            => await ReadCimInstanceAsync(finding, ct),
                "bitlockervolume"        => await ReadBitLockerVolumeAsync(finding, ct),
                _                        => "-NODATA-"
            };

            finding.ActualValue = actual;

            bool pass = finding.Method.Equals("accesschk", StringComparison.OrdinalIgnoreCase)
                ? EvaluateUserRights(actual, finding.ExpectedValue)
                : Evaluate(actual, finding.ExpectedValue, finding.Operator);

            finding.Status = pass ? FindingStatus.Pass : FindingStatus.Fail;
        }
        catch (Exception ex)
        {
            finding.Status       = FindingStatus.Error;
            finding.ErrorMessage = ex.Message;
        }
    }

    // ── Maps HardeningKitty CSV names → net accounts output label ────────────
    private static readonly Dictionary<string, string> s_netAccountsKeyMap =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["Account lockout duration"]          = "Lockout duration",
            ["Account lockout threshold"]          = "Lockout threshold",
            ["Reset account lockout counter"]      = "Lockout observation window",
            ["Minimum password age"]               = "Minimum password age",
            ["Maximum password age"]               = "Maximum password age",
            ["Minimum password length"]            = "Minimum password length",
            ["Enforce password history"]           = "Length of password history",
            ["Password history"]                   = "Length of password history",
            ["Store passwords using reversible"]   = "Force user logoff",
        };

    // ── Windows OS defaults for GPO-controlled registry paths ────────────────
    // Used when the policy key is absent (GPO "Not Configured") and the CSV
    // DefaultValue column is empty. Keys are {RegistryPath}\{RegistryItem}.
    // Sources: Microsoft Security Update Guide, CIS Benchmark rationale,
    //          Windows release notes for KB5005652, KB5014754, etc.
    private static readonly Dictionary<string, string> s_policyDefaults =
        new(StringComparer.OrdinalIgnoreCase)
        {
            // ── Print Spooler / RPC (hardened by KB5005652, Aug 2021) ─────────
            // When the policy key is absent these reflect post-patch OS behaviour.
            [@"HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC\RpcUseNamedPipeProtocol"]                          = "0",
            [@"HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC\RpcAuthentication"]                                = "0",
            [@"HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC\RpcProtocols"]                                     = "0",
            [@"HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC\ForceKerberosForRpc"]                              = "0",
            [@"HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC\RpcTcpPort"]                                       = "0",
            [@"HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RedirectionGuardPolicy"]                               = "1",
            [@"HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators"] = "1",
            [@"HKLM:\Software\Policies\Microsoft\Windows NT\Printers\CopyFilesPolicy"]                                      = "0",
            [@"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint\PackagePointAndPrintOnly"]        = "0",
            [@"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint\PackagePointAndPrintServerList"]  = "0",
            // RpcAuthnLevelPrivacyEnabled lives outside \Policies\ — KB5005652 set it to 1 by default.
            [@"HKLM:\System\CurrentControlSet\Control\Print\RpcAuthnLevelPrivacyEnabled"]                                   = "1",

            // ── SMB ──────────────────────────────────────────────────────────
            // MinSmb2Dialect absent = no minimum enforced (all dialects allowed).
            [@"HKLM:\Software\Policies\Microsoft\Windows\LanmanServer\MinSmb2Dialect"]                                      = "0",
            [@"HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\MinSmb2Dialect"]                                 = "0",
            // Auth rate-limiter: 2000 ms default since Win11 24H2 / Server 2025;
            // "0" is the conservative default for older builds where the feature is absent.
            [@"HKLM:\Software\Policies\Microsoft\Windows\LanmanServer\InvalidAuthenticationDelayTimeInMs"]                  = "0",

            // ── LSASS / Credential protection ────────────────────────────────
            // RunAsPPL: absent = not enforced (0). Win11 22H2+ new installs default to 2,
            // but the policy key still won't exist unless set explicitly.
            [@"HKLM:\System\CurrentControlSet\Control\Lsa\RunAsPPL"]                                                        = "0",
            // AllowCustomSSPsAPs: absent = custom SSPs allowed (feature ON, hence "0" = not blocked).
            [@"HKLM:\Software\Policies\Microsoft\Windows\System\AllowCustomSSPsAPs"]                                        = "0",

            // ── Windows Defender ─────────────────────────────────────────────
            [@"HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\DisableBlockAtFirstSeen"]                          = "0",
            [@"HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent"]                             = "2",
            [@"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine\EnableFileHashComputation"]                      = "0",
            // Exclusion policy keys absent = no GPO-managed exclusions.
            [@"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Exclusions_Extensions"]                        = "",
            [@"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Exclusions_Paths"]                             = "",
            [@"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Exclusions_Processes"]                         = "",

            // ── Device Guard / VBS ────────────────────────────────────────────
            [@"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HVCIMATRequired"]                                      = "0",

            // ── Biometrics ───────────────────────────────────────────────────
            [@"HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing"]                           = "0",

            // ── Windows 11 features ───────────────────────────────────────────
            [@"HKLM:\Software\Policies\Microsoft\Windows\Sudo\Enabled"]                                                     = "0",

            // ── Telemetry / privacy ───────────────────────────────────────────
            [@"HKLM:\Software\Policies\Microsoft\Windows\CloudContent\DisableConsumerAccountStateContent"]                   = "0",
            [@"HKLM:\Software\Policies\Microsoft\Windows\DataCollection\DisableOneSettingsDownloads"]                       = "0",
            [@"HKLM:\Software\Policies\Microsoft\Windows\DataCollection\LimitDiagnosticLogCollection"]                      = "0",
            [@"HKLM:\Software\Policies\Microsoft\Windows\DataCollection\LimitDumpCollection"]                               = "0",
            [@"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\DisableGraphRecentItems"]                                 = "0",
            [@"HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\DisableInternetExplorerLaunchViaCOM"]               = "0",

            // ── BitLocker ────────────────────────────────────────────────────
            // MinimumPIN absent = OS allows any PIN length ≥ 4; treat as 6 (the documented minimum).
            [@"HKLM:\Software\Policies\Microsoft\FVE\MinimumPIN"]                                                           = "6",
        };

    // Resolve OS default for a registry path when the CSV DefaultValue is empty.
    // Returns true and sets codeDef when a known default exists; false otherwise.
    private static bool TryGetPolicyDefault(string? path, string? item, out string codeDef)
    {
        if (string.IsNullOrEmpty(path)) { codeDef = string.Empty; return false; }
        string lookupKey = string.IsNullOrEmpty(item) ? path : $"{path}\\{item}";
        return s_policyDefaults.TryGetValue(lookupKey, out codeDef!);
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

        if (key is null)
        {
            // Prefer CSV DefaultValue, then code-level policy table, then -NODATA-.
            if (!string.IsNullOrEmpty(finding.DefaultValue))  { finding.IsUsingDefault = true; return finding.DefaultValue; }
            if (TryGetPolicyDefault(path, item, out string def)) { finding.IsUsingDefault = true; return def; }
            return "-NODATA-";
        }

        if (string.IsNullOrEmpty(item)) return key.GetValueNames().Length.ToString();
        var val = key.GetValue(item);

        if (val is null)
        {
            if (!string.IsNullOrEmpty(finding.DefaultValue))  { finding.IsUsingDefault = true; return finding.DefaultValue; }
            if (TryGetPolicyDefault(path, item, out string def)) { finding.IsUsingDefault = true; return def; }
            return "-NODATA-";
        }
        return val.ToString() ?? "-NODATA-";
    }

    private async Task<string> ReadSeceditAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? arg);
        if (string.IsNullOrEmpty(arg)) return "-NODATA-";

        string keyName = arg.Contains('\\') ? arg[(arg.LastIndexOf('\\') + 1)..] : arg;
        string safeKey = keyName.Replace("'", "''");

        var result = await _ps.RunInlineAsync(
            $"$key = '{safeKey}'; " +
            $"$tmp = [System.IO.Path]::GetTempFileName(); " +
            $"secedit /export /cfg $tmp /areas SECURITYPOLICY | Out-Null; " +
            $"$content = Get-Content $tmp; Remove-Item $tmp -Force; " +
            $"$line = $content | Where-Object {{ $_ -match ('^' + [Regex]::Escape($key) + '\\s*=') }}; " +
            $"if ($line) {{ ($line -split '=',2)[1].Trim() }} else {{ '-NOTFOUND-' }}", ct: ct);

        if (!result.Success) return "-NODATA-";
        string seceditResult = result.Output.Trim();
        if (seceditResult == "-NOTFOUND-")
        {
            if (!string.IsNullOrEmpty(finding.DefaultValue)) { finding.IsUsingDefault = true; return finding.DefaultValue; }
            return "-NODATA-";
        }
        return seceditResult;
    }

    private async Task<string> ReadAuditpolAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? sub);
        if (string.IsNullOrEmpty(sub)) return "-NODATA-";
        string safeSub = sub.Replace("'", "''");

        // Quote $tmp to handle temp paths with spaces (e.g. user profiles like "Dmitrii N").
        var result = await _ps.RunInlineAsync(
            $"$sub = '{safeSub}'; " +
            $"$tmp = [System.IO.Path]::GetTempFileName() + '.csv'; " +
            $"auditpol /backup /file:\"$tmp\" | Out-Null; " +
            $"$csv = Import-Csv \"$tmp\"; Remove-Item \"$tmp\" -Force -ErrorAction SilentlyContinue; " +
            $"$row = $csv | Where-Object {{ $_.'Subcategory GUID' -eq $sub }}; " +
            $"if ($row) {{ $row.'Inclusion Setting' }} else {{ '-NOTFOUND-' }}", ct: ct);

        // If the PS command itself failed (e.g. auditpol permissions), fall back to the
        // documented Windows default: all subcategories default to "No Auditing" when the
        // Advanced Audit Policy is not configured.
        if (!result.Success)
        {
            string def = !string.IsNullOrEmpty(finding.DefaultValue) ? finding.DefaultValue : "No Auditing";
            finding.IsUsingDefault = true;
            return def;
        }

        string auditResult = result.Output.Trim();
        if (auditResult == "-NOTFOUND-")
        {
            string def = !string.IsNullOrEmpty(finding.DefaultValue) ? finding.DefaultValue : "No Auditing";
            finding.IsUsingDefault = true;
            return def;
        }
        return auditResult;
    }

    private async Task<string> ReadAccountPolicyAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? arg);

        string searchKey = !string.IsNullOrEmpty(arg) ? arg : finding.Name;
        if (string.IsNullOrEmpty(searchKey)) return "-NODATA-";

        string mappedKey = searchKey;
        foreach (var (k, v) in s_netAccountsKeyMap)
            if (searchKey.Contains(k, StringComparison.OrdinalIgnoreCase)) { mappedKey = v; break; }

        string safeKey = mappedKey.Replace("'", "''");
        var result = await _ps.RunInlineAsync(
            $"$key = '{safeKey}'; " +
            $"$line = (net accounts | Where-Object {{ $_ -match [Regex]::Escape($key) }}); " +
            $"if ($line) {{ ($line -replace '.*:','').Trim() }} else {{ '-NOTFOUND-' }}", ct: ct);

        if (!result.Success) return "-NODATA-";
        string acctResult = result.Output.Trim();
        if (acctResult == "-NOTFOUND-")
        {
            if (!string.IsNullOrEmpty(finding.DefaultValue)) { finding.IsUsingDefault = true; return finding.DefaultValue; }
            return "-NODATA-";
        }
        return acctResult;
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

    private async Task<string> ReadLocalAccountAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? arg);
        if (string.IsNullOrEmpty(arg)) return "-NODATA-";
        string safeArg = arg.Replace("'", "''");
        var result = await _ps.RunInlineAsync(
            $"$sid = '{safeArg}'; " +
            $"$acc = Get-LocalUser | Where-Object {{ $_.SID -like $sid }}; " +
            $"if ($acc) {{ if ($acc.Enabled) {{ '1' }} else {{ '0' }} }} else {{ '-NODATA-' }}", ct: ct);
        return result.Success ? result.Output.Trim() : "-NODATA-";
    }

    private static string ReadRegistryList(Finding finding)
    {
        finding.CheckParams.TryGetValue("RegistryPath", out string? path);
        finding.CheckParams.TryGetValue("RegistryItem", out string? expectedItem);
        if (string.IsNullOrEmpty(path)) return "-NODATA-";

        var hive = path.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase) ? Registry.LocalMachine
                 : path.StartsWith("HKCU", StringComparison.OrdinalIgnoreCase) ? Registry.CurrentUser
                 : path.StartsWith("HKCC", StringComparison.OrdinalIgnoreCase) ? Registry.CurrentConfig
                 : Registry.LocalMachine;

        string subKey = path.Contains('\\') ? path[(path.IndexOf('\\') + 1)..] : path;
        using var key = hive.OpenSubKey(subKey, writable: false);
        if (key is null)
        {
            if (!string.IsNullOrEmpty(finding.DefaultValue)) { finding.IsUsingDefault = true; return finding.DefaultValue; }
            // Policy key absent = restriction not configured; no items in the deny list.
            finding.IsUsingDefault = true;
            return "Not found";
        }

        if (string.IsNullOrEmpty(expectedItem)) return key.GetValueNames().Length.ToString();
        bool found = key.GetValueNames().Any(n => Regex.IsMatch(n, Regex.Escape(expectedItem), RegexOptions.IgnoreCase));
        return found ? expectedItem : "Not found";
    }

    private async Task<string> ReadMpStatusAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? prop);
        if (string.IsNullOrEmpty(prop) || !Regex.IsMatch(prop, @"^[A-Za-z][A-Za-z0-9]*$"))
            return "-NODATA-";
        var result = await _ps.RunInlineAsync(
            $"(Get-MpComputerStatus).{prop}", ct: ct);
        return result.Success ? result.Output.Trim() : "-NODATA-";
    }

    private async Task<string> ReadMpPreferenceAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? prop);
        if (string.IsNullOrEmpty(prop) || !Regex.IsMatch(prop, @"^[A-Za-z][A-Za-z0-9]*$"))
            return "-NODATA-";
        var result = await _ps.RunInlineAsync(
            $"(Get-MpPreference).{prop}", ct: ct);
        return result.Success ? result.Output.Trim() : "-NODATA-";
    }

    // Reads a single Attack Surface Reduction rule action by its GUID.
    // MethodArgument = rule GUID (e.g. be9ba2d9-53ea-4cdc-84e5-9b1eeee46550).
    // Returns the action value (0=off, 1=block, 2=audit, 6=warn) or DefaultValue/0 when not configured.
    private async Task<string> ReadMpPreferenceAsrAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? ruleId);
        if (string.IsNullOrEmpty(ruleId)) return "-NODATA-";

        // GUIDs are compared case-insensitively; normalise to lower for [array]::IndexOf.
        string safeId = ruleId.Replace("'", "''").ToLowerInvariant();
        var result = await _ps.RunInlineAsync(
            $"$id = '{safeId}'; " +
            $"$pref = Get-MpPreference -ErrorAction SilentlyContinue; " +
            $"$ids = @($pref.AttackSurfaceReductionRules_Ids | ForEach-Object {{ $_.ToLower() }}); " +
            $"$actions = @($pref.AttackSurfaceReductionRules_Actions); " +
            $"$idx = [array]::IndexOf($ids, $id); " +
            $"if ($idx -ge 0) {{ $actions[$idx] }} else {{ '-NOTFOUND-' }}", ct: ct);

        if (!result.Success || result.Output.Trim() == "-NOTFOUND-")
        {
            // Rule not configured = disabled (0) by default.
            string def = !string.IsNullOrEmpty(finding.DefaultValue) ? finding.DefaultValue : "0";
            finding.IsUsingDefault = true;
            return def;
        }
        return result.Output.Trim();
    }

    // Reads a Defender preference exclusion list (ExclusionExtension, ExclusionPath, etc.).
    // MethodArgument = the property name on Get-MpPreference (identifier-safe).
    // Returns a comma-separated sorted list, or "" when no exclusions are configured.
    private async Task<string> ReadMpPreferenceExclusionAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? prop);
        if (string.IsNullOrEmpty(prop) || !Regex.IsMatch(prop, @"^[A-Za-z][A-Za-z0-9]*$"))
            return "-NODATA-";

        var result = await _ps.RunInlineAsync(
            $"$excl = (Get-MpPreference -ErrorAction SilentlyContinue).{prop}; " +
            $"if ($excl -eq $null -or @($excl).Count -eq 0) {{ '' }} else {{ ($excl | Sort-Object) -join ',' }}", ct: ct);

        if (!result.Success)
        {
            finding.IsUsingDefault = true;
            return string.Empty; // no exclusions by default
        }
        return result.Output.Trim();
    }

    // Reads a BitLocker volume property (VolumeStatus, EncryptionMethod) for the system drive.
    // MethodArgument = property name on Get-BitLockerVolume (identifier-safe).
    private async Task<string> ReadBitLockerVolumeAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? prop);
        if (string.IsNullOrEmpty(prop) || !Regex.IsMatch(prop, @"^[A-Za-z][A-Za-z0-9]*$"))
            return "-NODATA-";

        var result = await _ps.RunInlineAsync(
            $"$vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue; " +
            $"if ($vol) {{ $vol.{prop} }} else {{ '-NOTFOUND-' }}", ct: ct);

        if (!result.Success) return "-NODATA-";
        string volResult = result.Output.Trim();
        if (volResult == "-NOTFOUND-")
        {
            if (!string.IsNullOrEmpty(finding.DefaultValue)) { finding.IsUsingDefault = true; return finding.DefaultValue; }
            return "-NODATA-";
        }
        return volResult;
    }

    private async Task<string> ReadCimInstanceAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("ClassName",  out string? className);
        finding.CheckParams.TryGetValue("Namespace",  out string? ns);
        finding.CheckParams.TryGetValue("Property",   out string? prop);

        if (string.IsNullOrEmpty(prop))
            finding.CheckParams.TryGetValue("MethodArgument", out prop);

        if (string.IsNullOrEmpty(className) || string.IsNullOrEmpty(prop)) return "-NODATA-";

        if (!Regex.IsMatch(className, @"^[A-Za-z_][A-Za-z0-9_]*$") ||
            !Regex.IsMatch(prop,      @"^[A-Za-z_][A-Za-z0-9_]*$"))
            return "-NODATA-";

        string nsArg = !string.IsNullOrEmpty(ns) ? $" -Namespace '{ns.Replace("'", "''")}'" : "";
        var result = await _ps.RunInlineAsync(
            $"$obj = Get-CimInstance -ClassName {className}{nsArg} -ErrorAction SilentlyContinue; " +
            $"if ($obj) {{ $obj.{prop} }} else {{ '-NODATA-' }}", ct: ct);
        return result.Success ? result.Output.Trim() : "-NODATA-";
    }

    private async Task<string> ReadOptionalFeatureAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? featureName);
        if (string.IsNullOrEmpty(featureName)) return "-NODATA-";
        string safeName = featureName.Replace("'", "''");
        var result = await _ps.RunInlineAsync(
            $"(Get-WindowsOptionalFeature -Online -FeatureName '{safeName}').State", ct: ct);
        return result.Success ? result.Output.Trim() : "-NODATA-";
    }

    private async Task<string> ReadAccessChkAsync(Finding finding, CancellationToken ct)
    {
        finding.CheckParams.TryGetValue("MethodArgument", out string? priv);
        if (string.IsNullOrEmpty(priv)) return "-NODATA-";

        string safePriv = priv.Replace("'", "''");
        var result = await _ps.RunInlineAsync(
            $"$priv = '{safePriv}'; " +
            $"$tmp = [System.IO.Path]::GetTempFileName(); " +
            $"secedit /export /cfg $tmp /areas USER_RIGHTS | Out-Null; " +
            $"$content = Get-Content $tmp; Remove-Item $tmp -Force; " +
            $"$line = $content | Where-Object {{ $_ -match ('^' + [Regex]::Escape($priv) + '\\s*=') }}; " +
            $"if ($line) {{ " +
            $"  $raw = (($line -split '=',2)[1]).Trim(); " +
            $"  if ([string]::IsNullOrWhiteSpace($raw)) {{ '-EMPTY-' }} " +
            $"  else {{ " +
            $"    $sids = $raw -split ',' | Where-Object {{ $_ -ne '' }}; " +
            $"    ($sids | ForEach-Object {{ " +
            $"      $s = $_.Trim().TrimStart('*'); " +
            $"      try {{ ([System.Security.Principal.SecurityIdentifier]$s).Translate([System.Security.Principal.NTAccount]).Value }} " +
            $"      catch {{ $_.Trim() }} " +
            $"    }} | Sort-Object) -join ';' " +
            $"  }} " +
            $"}} else {{ '-NOTFOUND-' }}", ct: ct);

        if (!result.Success) return "-NODATA-";
        string accessResult = result.Output.Trim();

        if (accessResult == "-NOTFOUND-")
        {
            if (!string.IsNullOrEmpty(finding.DefaultValue)) { finding.IsUsingDefault = true; return finding.DefaultValue; }
            return string.Empty;
        }
        if (accessResult == "-EMPTY-") return string.Empty;
        return accessResult;
    }

    private async Task AuditRemoteAsync(Finding finding, ScanTarget target, CancellationToken ct)
    {
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

    private static bool EvaluateUserRights(string actual, string expected)
    {
        if (actual == "-NODATA-") return false;
        var actualSet   = actual.Split(';', StringSplitOptions.RemoveEmptyEntries)
                                .Select(s => s.Trim())
                                .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var expectedSet = expected.Split(';', StringSplitOptions.RemoveEmptyEntries)
                                  .Select(s => s.Trim())
                                  .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return actualSet.SetEquals(expectedSet);
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

        // Ordinis curated lists are the tool's own value-add, not benchmark-specific, so they
        // run under every profile — otherwise a benchmark filter (e.g. "must contain cis")
        // would silently exclude them.
        if (f.Contains("ordinis")) return true;

        return profileName.ToLowerInvariant() switch
        {
            var p when p.Contains("cis level 1") => f.Contains("cis") && !f.Contains("stig") && !f.Contains("bsi"),
            var p when p.Contains("cis level 2") => f.Contains("cis"),
            var p when p.Contains("stig")         => f.Contains("stig"),
            var p when p.Contains("microsoft")    => f.Contains("microsoft") || f.Contains("msft"),
            _                                     => true
        };
    }

    private static bool MatchesOs(string fileName, OsProfile? os)
    {
        if (os is null || os.WindowsVersion == "unknown") return true;
        string f = fileName.ToLowerInvariant();

        bool isServerCsv      = f.Contains("_server_");
        bool isWorkstationCsv = f.Contains("windows_10") || f.Contains("windows_11");

        if (os.IsWorkstation && isServerCsv)      return false;
        if (!os.IsWorkstation && isWorkstationCsv) return false;
        return true;
    }
}
