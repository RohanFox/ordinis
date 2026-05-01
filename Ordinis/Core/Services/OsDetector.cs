using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ordinis.Core.Services;

public enum DomainRole { StandaloneWorkstation = 0, MemberWorkstation = 1, StandaloneServer = 2, MemberServer = 3, BackupDC = 4, PrimaryDC = 5 }

public class OsProfile
{
    public string Caption       { get; set; } = string.Empty;
    public string BuildNumber   { get; set; } = string.Empty;
    public DomainRole DomainRole { get; set; }
    public string Domain        { get; set; } = string.Empty;
    public bool HasSqlServer    { get; set; }
    public bool HasDnsServer    { get; set; }
    public bool HasRsat         { get; set; }

    // Derived helpers
    public bool IsWorkstation   => DomainRole is DomainRole.StandaloneWorkstation or DomainRole.MemberWorkstation;
    public bool IsServer        => !IsWorkstation;
    public bool IsDomainJoined  => DomainRole is DomainRole.MemberWorkstation or DomainRole.MemberServer
                                                or DomainRole.BackupDC or DomainRole.PrimaryDC;
    public bool IsDomainController => DomainRole is DomainRole.BackupDC or DomainRole.PrimaryDC;

    /// <summary>Short version token used for CSV matching: "11", "10", "2025", "2022", "2019", "2016", "unknown".</summary>
    public string WindowsVersion
    {
        get
        {
            string c = Caption.ToLowerInvariant();
            if (c.Contains("2025")) return "2025";
            if (c.Contains("2022")) return "2022";
            if (c.Contains("2019")) return "2019";
            if (c.Contains("2016")) return "2016";
            if (c.Contains("windows 11")) return "11";
            if (c.Contains("windows 10")) return "10";
            // Fallback: use build number
            if (int.TryParse(BuildNumber, out int build))
            {
                if (build >= 22000) return "11";
                if (build >= 10240) return "10";
            }
            return "unknown";
        }
    }

    public static OsProfile Unknown => new()
    {
        Caption = "Unknown",
        DomainRole = DomainRole.StandaloneWorkstation
    };
}

public class OsDetector
{
    private readonly PowerShellRunner _ps;

    public OsDetector(PowerShellRunner ps) { _ps = ps; }

    public async Task<OsProfile> DetectAsync(CancellationToken ct = default)
    {
        const string script = @"
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$os = Get-CimInstance Win32_OperatingSystem  -ErrorAction SilentlyContinue
[PSCustomObject]@{
    Caption     = if ($os) { $os.Caption }     else { 'Unknown' }
    BuildNumber = if ($os) { $os.BuildNumber } else { '0' }
    DomainRole  = if ($cs) { [int]$cs.DomainRole } else { 0 }
    Domain      = if ($cs) { $cs.Domain } else { '' }
    HasSqlServer = ($null -ne (Get-Service -Name 'MSSQLSERVER','MSSQL$*' -ErrorAction SilentlyContinue | Select-Object -First 1))
    HasDnsServer = ($null -ne (Get-Service -Name 'DNS' -ErrorAction SilentlyContinue))
    HasRsat      = ($null -ne (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue))
} | ConvertTo-Json -Compress";

        var result = await _ps.RunInlineAsync(script, ct: ct);
        if (!result.Success || string.IsNullOrWhiteSpace(result.Output))
            return OsProfile.Unknown;

        try
        {
            var dto = JsonSerializer.Deserialize<OsProfileDto>(result.Output,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (dto is null) return OsProfile.Unknown;

            return new OsProfile
            {
                Caption     = dto.Caption,
                BuildNumber = dto.BuildNumber,
                DomainRole  = (DomainRole)Math.Clamp(dto.DomainRole, 0, 5),
                Domain      = dto.Domain,
                HasSqlServer = dto.HasSqlServer,
                HasDnsServer = dto.HasDnsServer,
                HasRsat      = dto.HasRsat
            };
        }
        catch { return OsProfile.Unknown; }
    }

    public async Task<string> DetectAvAsync(CancellationToken ct = default)
    {
        const string script = @"
$result = $null

# 1. SecurityCenter2 WMI namespace — Desktop only (not available on Server SKUs)
# Windows Defender is always registered here; prefer third-party products if also present.
try {
    $avList = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
    $av = $avList | Where-Object { $_.displayName -notmatch 'Windows Defender|Microsoft Defender' } | Select-Object -First 1
    if (-not $av) { $av = $avList | Select-Object -First 1 }
    if ($av) { $result = $av.displayName }
} catch { }

if ($result) { $result; return }

# 2. Well-known EDR/AV service names
$edrs = [ordered]@{
    'CSAgent'           = 'CrowdStrike Falcon'
    'SentinelAgent'     = 'SentinelOne'
    'SentinelStaticEn'  = 'SentinelOne'
    'BDAuxSrv'          = 'Bitdefender'
    'bdredline'         = 'Bitdefender'
    'EPSecurityService' = 'ESET'
    'ekrn'              = 'ESET'
    'TmListen'          = 'Trend Micro'
    'ds_agent'          = 'Trend Micro Deep Security'
    'kavfsslp'          = 'Kaspersky'
    'AVP'               = 'Kaspersky'
    'SAVService'        = 'Sophos'
    'MBAMService'       = 'Malwarebytes'
    'CylanceSvc'        = 'Cylance'
    'cyserver'          = 'Cybereason'
    'xagt'              = 'FireEye / Trellix'
    'cb'                = 'Carbon Black'
}
foreach ($entry in $edrs.GetEnumerator()) {
    if (Get-Service -Name $entry.Key -ErrorAction SilentlyContinue) {
        $result = $entry.Value; break
    }
}

if ($result) { $result; return }

# 3. Windows Defender via Get-MpComputerStatus (works on Server if Defender feature installed)
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    if ($mp -and $mp.AMRunningMode -ne 'Not running') {
        if ($mp.AMRunningMode -eq 'Passive Mode') { 'Windows Defender (Passive)' }
        else { 'Windows Defender' }
        return
    }
} catch { }

'None detected'
";
        var res = await _ps.RunInlineAsync(script, ct: ct);
        return res.Success && !string.IsNullOrWhiteSpace(res.Output)
            ? res.Output.Trim()
            : "Unknown";
    }

    private sealed class OsProfileDto
    {
        public string Caption     { get; set; } = string.Empty;
        public string BuildNumber { get; set; } = string.Empty;
        public int    DomainRole  { get; set; }
        public string Domain      { get; set; } = string.Empty;
        public bool   HasSqlServer { get; set; }
        public bool   HasDnsServer { get; set; }
        public bool   HasRsat     { get; set; }
    }
}
