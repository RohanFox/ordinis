using Ordinis.Core.Mvvm;

namespace Ordinis.ViewModels;

public class DashboardViewModel : BaseViewModel
{
    private readonly MainViewModel _main;
    public DashboardViewModel(MainViewModel main) { _main = main; }

    public void Refresh()
    {
        OnPropertyChanged(nameof(CompliancePercent));
        OnPropertyChanged(nameof(ComplianceLabel));
        OnPropertyChanged(nameof(PassCount));
        OnPropertyChanged(nameof(FailCount));
        OnPropertyChanged(nameof(ErrorCount));
        OnPropertyChanged(nameof(CriticalCount));
        OnPropertyChanged(nameof(HighCount));
        OnPropertyChanged(nameof(MediumCount));
        OnPropertyChanged(nameof(LowCount));
        OnPropertyChanged(nameof(CriticalBarWidth));
        OnPropertyChanged(nameof(HighBarWidth));
        OnPropertyChanged(nameof(MediumBarWidth));
        OnPropertyChanged(nameof(LowBarWidth));
        OnPropertyChanged(nameof(TotalChecks));
        OnPropertyChanged(nameof(WindowsChecks));
        OnPropertyChanged(nameof(SqlChecks));
        OnPropertyChanged(nameof(NetworkChecks));
        OnPropertyChanged(nameof(AdChecks));
        OnPropertyChanged(nameof(LastScanTime));
        OnPropertyChanged(nameof(ScanTarget));
        OnPropertyChanged(nameof(OsName));
        OnPropertyChanged(nameof(AvProduct));
        OnPropertyChanged(nameof(HasData));
    }

    public double CompliancePercent => _main.Session.CompliancePercent;
    public string ComplianceLabel   => $"{CompliancePercent:F0}%";
    public int PassCount    => _main.Session.PassCount;
    public int FailCount    => _main.Session.FailCount;
    public int ErrorCount   => _main.Session.ErrorCount;
    public int CriticalCount => _main.Session.CriticalFails;
    public int HighCount     => _main.Session.HighFails;
    public int MediumCount   => _main.Session.MediumFails;
    public int LowCount      => _main.Session.LowFails;
    public int TotalChecks   => _main.Session.TotalCount;
    public bool HasData      => TotalChecks > 0;

    public string LastScanTime => _main.Session.CompletedAt.HasValue
        ? _main.Session.CompletedAt.Value.ToString("yyyy-MM-dd HH:mm:ss")
        : "—";

    public string ScanTarget => _main.Session.Target.DisplayName;
    public string OsName     => _main.Session.OsCaption.Length > 0 ? _main.Session.OsCaption : "—";
    public string AvProduct  => _main.Session.AvProduct.Length  > 0 ? _main.Session.AvProduct  : "—";

    // Bar widths (0-200 pixels)
    private double MaxFail => Math.Max(1, new[] { CriticalCount, HighCount, MediumCount, LowCount }.Max());
    public double CriticalBarWidth => CriticalCount / MaxFail * 200;
    public double HighBarWidth     => HighCount     / MaxFail * 200;
    public double MediumBarWidth   => MediumCount   / MaxFail * 200;
    public double LowBarWidth      => LowCount      / MaxFail * 200;

    // Module breakdown
    public int WindowsChecks => _main.Session.Findings.Count(f =>
        f.Module == Core.Models.FindingModule.Windows && f.Status != Core.Models.FindingStatus.Pending);
    public int SqlChecks     => _main.Session.Findings.Count(f =>
        f.Module == Core.Models.FindingModule.MSSQL  && f.Status != Core.Models.FindingStatus.Pending);
    public int NetworkChecks => _main.Session.Findings.Count(f =>
        (f.Module == Core.Models.FindingModule.Network || f.Module == Core.Models.FindingModule.IPv6)
        && f.Status != Core.Models.FindingStatus.Pending);
    public int AdChecks      => _main.Session.Findings.Count(f =>
        f.Module == Core.Models.FindingModule.ActiveDirectory && f.Status != Core.Models.FindingStatus.Pending);
}
