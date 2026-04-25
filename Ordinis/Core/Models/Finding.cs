using System.ComponentModel;

namespace Ordinis.Core.Models;

public enum FindingStatus { Pending, Pass, Fail, Error, Skipped }
public enum FindingSeverity { Info, Low, Medium, High, Critical }
public enum FindingModule { Windows, MSSQL, IIS, ActiveDirectory, GPO, Network, IPv6, NTLM, LocalSecurity, Kerberos, Logging, AttackSurface }

public class Finding : INotifyPropertyChanged
{
    // Identity
    public string Id { get; set; } = string.Empty;
    public FindingModule Module { get; set; }
    public string Category { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Rationale { get; set; } = string.Empty;

    // Benchmark
    public string Benchmark { get; set; } = string.Empty;
    public string BenchmarkRef { get; set; } = string.Empty;
    public FindingSeverity Severity { get; set; }

    // Check definition
    public string Method { get; set; } = string.Empty;
    public Dictionary<string, string> CheckParams { get; set; } = new();

    // Comparison
    public string ExpectedValue { get; set; } = string.Empty;
    public string Operator { get; set; } = "=";
    public string DefaultValue { get; set; } = string.Empty;

    // Audit results
    private FindingStatus _status = FindingStatus.Pending;
    public FindingStatus Status
    {
        get => _status;
        set { _status = value; OnPropertyChanged(nameof(Status)); OnPropertyChanged(nameof(StatusIcon)); OnPropertyChanged(nameof(StatusColor)); OnPropertyChanged(nameof(FailureReason)); }
    }

    private string _actualValue = string.Empty;
    public string ActualValue
    {
        get => _actualValue;
        set { _actualValue = value; OnPropertyChanged(nameof(ActualValue)); OnPropertyChanged(nameof(FailureReason)); }
    }

    public string ErrorMessage { get; set; } = string.Empty;

    // Why it failed — auto-computed from actual vs expected
    public string FailureReason => Status == FindingStatus.Fail ? Operator switch
    {
        "="           => $"Found \"{ActualValue}\" — must equal \"{ExpectedValue}\"",
        "!="          => $"Found \"{ActualValue}\" — must NOT equal \"{ExpectedValue}\"",
        ">="          => $"Found {ActualValue} — must be ≥ {ExpectedValue}",
        "<="          => $"Found {ActualValue} — must be ≤ {ExpectedValue}",
        "contains"    => $"Found \"{ActualValue}\" — must contain \"{ExpectedValue}\"",
        "notcontains" => $"Found \"{ActualValue}\" — must NOT contain \"{ExpectedValue}\"",
        "<=!0"        => $"Found {ActualValue} — must be ≤ {ExpectedValue} and non-zero",
        _             => $"Found \"{ActualValue}\" — expected \"{ExpectedValue}\""
    } : string.Empty;

    // Where the data came from (registry path, WMI class, PS cmdlet)
    public string CheckSource { get; set; } = string.Empty;

    // Multiple remediation paths: GPO path, PowerShell, registry edit
    public List<string> RemediationSteps { get; set; } = new();

    // Remediation
    public string RemediationText { get; set; } = string.Empty;
    public string RemediationScript { get; set; } = string.Empty;
    public Dictionary<string, string> RemediationParams { get; set; } = new();
    public bool IsSafeToAutoFix { get; set; } = true;
    public bool RequiresRestart { get; set; } = false;

    // Backup
    public string BackupKey { get; set; } = string.Empty;
    public bool BackupTaken { get; set; } = false;

    // Compliance
    public Dictionary<string, List<string>> Compliance { get; set; } = new();

    // Display helpers
    public string StatusIcon => Status switch
    {
        FindingStatus.Pass    => "✔",
        FindingStatus.Fail    => "✖",
        FindingStatus.Error   => "⚠",
        FindingStatus.Skipped => "⊘",
        _                     => "○"
    };

    public string StatusColor => Status switch
    {
        FindingStatus.Pass    => "#22C55E",
        FindingStatus.Fail    => "#EF4444",
        FindingStatus.Error   => "#F59E0B",
        FindingStatus.Skipped => "#6B7280",
        _                     => "#9CA3AF"
    };

    public string SeverityColor => Severity switch
    {
        FindingSeverity.Critical => "#A855F7",
        FindingSeverity.High     => "#EF4444",
        FindingSeverity.Medium   => "#F59E0B",
        FindingSeverity.Low      => "#3B82F6",
        _                        => "#6B7280"
    };

    public string ModuleLabel => Module switch
    {
        FindingModule.Windows         => "Windows",
        FindingModule.MSSQL           => "SQL Server",
        FindingModule.IIS             => "IIS",
        FindingModule.ActiveDirectory => "Active Directory",
        FindingModule.GPO             => "GPO",
        FindingModule.Network         => "Network",
        FindingModule.IPv6            => "IPv6",
        FindingModule.NTLM            => "NTLM / Credential",
        FindingModule.LocalSecurity   => "Local Security",
        FindingModule.Kerberos        => "Kerberos",
        FindingModule.Logging         => "Logging & Audit",
        FindingModule.AttackSurface   => "Attack Surface",
        _                             => "Unknown"
    };

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged(string name) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
