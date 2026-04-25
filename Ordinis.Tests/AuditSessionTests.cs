using Ordinis.Core.Models;

namespace Ordinis.Tests;

public class AuditSessionTests
{
    private static Finding Make(FindingStatus status, FindingSeverity severity = FindingSeverity.Low) => new()
    {
        Id       = Guid.NewGuid().ToString(),
        Name     = "Test",
        Status   = status,
        Severity = severity
    };

    [Fact]
    public void Empty_session_has_zero_counts()
    {
        var s = new AuditSession();
        Assert.Equal(0, s.PassCount);
        Assert.Equal(0, s.FailCount);
        Assert.Equal(0, s.ErrorCount);
        Assert.Equal(0, s.TotalCount);
    }

    [Fact]
    public void TotalCount_excludes_pending()
    {
        var s = new AuditSession();
        s.Findings.Add(Make(FindingStatus.Pending));
        s.Findings.Add(Make(FindingStatus.Pass));
        Assert.Equal(1, s.TotalCount);
    }

    [Fact]
    public void CompliancePercent_is_100_when_all_pass()
    {
        var s = new AuditSession();
        s.Findings.Add(Make(FindingStatus.Pass));
        s.Findings.Add(Make(FindingStatus.Pass));
        Assert.Equal(100.0, s.CompliancePercent);
    }

    [Fact]
    public void CompliancePercent_is_50_with_one_pass_one_fail()
    {
        var s = new AuditSession();
        s.Findings.Add(Make(FindingStatus.Pass));
        s.Findings.Add(Make(FindingStatus.Fail));
        Assert.Equal(50.0, s.CompliancePercent);
    }

    [Fact]
    public void CompliancePercent_is_0_when_no_results()
        => Assert.Equal(0.0, new AuditSession().CompliancePercent);

    [Fact]
    public void CriticalFails_counts_only_failed_critical()
    {
        var s = new AuditSession();
        s.Findings.Add(Make(FindingStatus.Fail,  FindingSeverity.Critical));
        s.Findings.Add(Make(FindingStatus.Pass,  FindingSeverity.Critical));
        s.Findings.Add(Make(FindingStatus.Fail,  FindingSeverity.High));
        Assert.Equal(1, s.CriticalFails);
        Assert.Equal(1, s.HighFails);
    }

    [Fact]
    public void ErrorCount_does_not_affect_compliance()
    {
        var s = new AuditSession();
        s.Findings.Add(Make(FindingStatus.Pass));
        s.Findings.Add(Make(FindingStatus.Error));
        // Error is counted in total but not in pass/fail ratio
        Assert.Equal(2, s.TotalCount);
        Assert.Equal(1, s.ErrorCount);
        // Compliance = pass/(pass+fail) — errors excluded from denominator
        Assert.Equal(100.0, s.CompliancePercent);
    }
}
