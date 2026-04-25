namespace Ordinis.Core.Models;

public class AuditSession
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTime StartedAt { get; set; } = DateTime.Now;
    public DateTime? CompletedAt { get; set; }
    public ScanTarget Target { get; set; } = new();
    public string ProfileName { get; set; } = string.Empty;
    public List<Finding> Findings { get; set; } = new();
    public bool IsRunning { get; set; } = false;

    public int TotalCount   => Findings.Count(f => f.Status != FindingStatus.Pending);
    public int PassCount    => Findings.Count(f => f.Status == FindingStatus.Pass);
    public int FailCount    => Findings.Count(f => f.Status == FindingStatus.Fail);
    public int ErrorCount   => Findings.Count(f => f.Status == FindingStatus.Error);
    public int SkippedCount => Findings.Count(f => f.Status == FindingStatus.Skipped);

    public int CriticalFails => Findings.Count(f => f.Status == FindingStatus.Fail && f.Severity == FindingSeverity.Critical);
    public int HighFails     => Findings.Count(f => f.Status == FindingStatus.Fail && f.Severity == FindingSeverity.High);
    public int MediumFails   => Findings.Count(f => f.Status == FindingStatus.Fail && f.Severity == FindingSeverity.Medium);
    public int LowFails      => Findings.Count(f => f.Status == FindingStatus.Fail && f.Severity == FindingSeverity.Low);

    public double CompliancePercent
    {
        get
        {
            int scored = PassCount + FailCount;
            return scored == 0 ? 0 : Math.Round((double)PassCount / scored * 100, 1);
        }
    }

    public string Duration => CompletedAt.HasValue
        ? (CompletedAt.Value - StartedAt).ToString(@"mm\:ss")
        : "Running…";
}
