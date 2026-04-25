using System.Collections.ObjectModel;
using System.Windows;
using Ordinis.Core.Models;
using Ordinis.Core.Mvvm;
using Ordinis.Core.Services;
using Ordinis.Modules.AD;
using Ordinis.Modules.AttackSurface;
using Ordinis.Modules.GPO;
using Ordinis.Modules.LocalSecurity;
using Ordinis.Modules.Logging;
using Ordinis.Modules.MSSQL;
using Ordinis.Modules.Network;
using Ordinis.Modules.NTLM;
using Ordinis.Modules.Windows;

namespace Ordinis.ViewModels;

public class MainViewModel : BaseViewModel
{
    // ── Services ────────────────────────────────────────────────────────────────
    public readonly PowerShellRunner  PsRunner;
    public readonly BackupManager     BackupMgr;
    public readonly RemediationEngine Remediation;
    public readonly AuditEngine       Audit;
    public readonly CsvFindingLoader  CsvLoader;
    public readonly ReportGenerator   Reporter;
    public readonly GpoModule         GpoMod;
    public readonly SqlModule         SqlMod;

    // ── Child view-models ───────────────────────────────────────────────────────
    public DashboardViewModel  Dashboard  { get; }
    public FindingsViewModel   Findings   { get; }
    public GpoViewModel        Gpo        { get; }
    public BackupViewModel     Backups    { get; }
    public ReportViewModel     Reports    { get; }
    public SettingsViewModel   Settings   { get; }

    // ── Navigation ──────────────────────────────────────────────────────────────
    private BaseViewModel _currentPage;
    public BaseViewModel CurrentPage
    {
        get => _currentPage;
        set => SetField(ref _currentPage, value);
    }

    // ── Session state ───────────────────────────────────────────────────────────
    private AuditSession _session = new();
    public AuditSession Session
    {
        get => _session;
        set { SetField(ref _session, value); OnPropertyChanged(nameof(HasResults)); }
    }

    private ScanTarget _target = new() { Type = TargetType.Local };
    public ScanTarget Target
    {
        get => _target;
        set => SetField(ref _target, value);
    }

    private ScanProfile _profile = ScanProfile.CisLevel1Windows;
    public ScanProfile SelectedProfile
    {
        get => _profile;
        set => SetField(ref _profile, value);
    }

    public ObservableCollection<ScanProfile> Profiles { get; } = new(ScanProfile.Defaults);

    // ── Status / loading ────────────────────────────────────────────────────────
    private bool _isLoading;
    public bool IsLoading
    {
        get => _isLoading;
        set { SetField(ref _isLoading, value); OnPropertyChanged(nameof(CanScan)); }
    }

    private string _statusText = "Ready";
    public string StatusText
    {
        get => _statusText;
        set => SetField(ref _statusText, value);
    }

    private double _progress;
    public double Progress
    {
        get => _progress;
        set => SetField(ref _progress, value);
    }

    public bool HasResults => Session.TotalCount > 0;
    public bool CanScan    => !IsLoading;

    // ── Commands ─────────────────────────────────────────────────────────────────
    public AsyncRelayCommand RunScanCommand      { get; }
    public AsyncRelayCommand FixSelectedCommand  { get; }
    public RelayCommand      NavigateDashboard   { get; }
    public RelayCommand      NavigateFindings    { get; }
    public RelayCommand      NavigateGpo         { get; }
    public RelayCommand      NavigateBackups     { get; }
    public RelayCommand      NavigateReports     { get; }
    public RelayCommand      NavigateSettings    { get; }

    private CancellationTokenSource? _cts;

    public MainViewModel()
    {
        PsRunner    = new PowerShellRunner();
        BackupMgr   = new BackupManager();
        Remediation = new RemediationEngine(PsRunner, BackupMgr);
        CsvLoader   = new CsvFindingLoader();
        Reporter    = new ReportGenerator();
        GpoMod      = new GpoModule(PsRunner);
        SqlMod      = new SqlModule();

        Audit = new AuditEngine();
        Audit.RegisterModule(new WindowsModule(CsvLoader, PsRunner));
        Audit.RegisterModule(SqlMod);
        Audit.RegisterModule(new NetworkModule(PsRunner));
        Audit.RegisterModule(new AdModule(PsRunner));
        Audit.RegisterModule(new NtlmModule(PsRunner));
        Audit.RegisterModule(new LocalSecurityModule(PsRunner));
        Audit.RegisterModule(new LoggingModule(PsRunner));
        Audit.RegisterModule(new AttackSurfaceModule(PsRunner));

        Dashboard = new DashboardViewModel(this);
        Findings  = new FindingsViewModel(this);
        Gpo       = new GpoViewModel(this);
        Backups   = new BackupViewModel(this);
        Reports   = new ReportViewModel(this);
        Settings  = new SettingsViewModel(this);

        _currentPage = Dashboard;

        RunScanCommand     = new AsyncRelayCommand(RunScanAsync,  () => CanScan);
        FixSelectedCommand = new AsyncRelayCommand(FixSelectedAsync, () => HasResults && !IsLoading);

        NavigateDashboard = new RelayCommand(() => CurrentPage = Dashboard);
        NavigateFindings  = new RelayCommand(() => CurrentPage = Findings);
        NavigateGpo       = new RelayCommand(() => CurrentPage = Gpo);
        NavigateBackups   = new RelayCommand(() => CurrentPage = Backups);
        NavigateReports   = new RelayCommand(() => CurrentPage = Reports);
        NavigateSettings  = new RelayCommand(() => CurrentPage = Settings);
    }

    private async Task RunScanAsync()
    {
        _cts     = new CancellationTokenSource();
        IsLoading = true;
        Progress  = 0;
        StatusText = "Loading finding lists…";

        try
        {
            Session = new AuditSession
            {
                Target      = Target,
                ProfileName = SelectedProfile.Name
            };

            // Load Windows findings from CSV lists
            var winModule   = new WindowsModule(CsvLoader, PsRunner);
            var winFindings = await winModule.GetFindingsAsync(SelectedProfile, _cts.Token);
            Session.Findings.AddRange(winFindings);

            // Load Network/IPv6 findings
            var netModule   = new NetworkModule(PsRunner);
            var netFindings = await netModule.GetFindingsAsync(SelectedProfile, _cts.Token);
            Session.Findings.AddRange(netFindings);

            // SQL Server if configured
            if (SelectedProfile.IncludeMSSQL && Target.HasSqlConnection)
                Session.Findings.AddRange(await SqlMod.GetFindingsAsync(SelectedProfile, _cts.Token));

            // AD + Kerberos attack surface
            if (SelectedProfile.IncludeAD)
            {
                var adModule = new AdModule(PsRunner);
                Session.Findings.AddRange(await adModule.GetFindingsAsync(SelectedProfile, _cts.Token));
            }

            // NTLM hardening + Credential Guard (always included — OS-level registry checks)
            var ntlmModule = new NtlmModule(PsRunner);
            Session.Findings.AddRange(await ntlmModule.GetFindingsAsync(SelectedProfile, _cts.Token));

            // Local security: BitLocker, LAPS, UAC, AppLocker, WMI persistence
            var localSecModule = new LocalSecurityModule(PsRunner);
            Session.Findings.AddRange(await localSecModule.GetFindingsAsync(SelectedProfile, _cts.Token));

            // Logging & audit policy: PS Script Block, Advanced Audit, event log sizing
            var loggingModule = new LoggingModule(PsRunner);
            Session.Findings.AddRange(await loggingModule.GetFindingsAsync(SelectedProfile, _cts.Token));

            // Attack surface: unnecessary services, Defender ASR, Least Privilege, Windows Update
            var asrModule = new AttackSurfaceModule(PsRunner);
            Session.Findings.AddRange(await asrModule.GetFindingsAsync(SelectedProfile, _cts.Token));

            StatusText = $"Running audit — 0 / {Session.Findings.Count}";

            var progress = new Progress<(int current, int total, string message)>(p =>
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    Progress   = p.total > 0 ? (double)p.current / p.total * 100 : 0;
                    StatusText = $"[{p.current}/{p.total}] {p.message}";
                    OnPropertyChanged(nameof(Session));
                    Dashboard.Refresh();
                    Findings.Refresh();
                });
            });

            await Audit.RunAuditAsync(Session, progress, _cts.Token);

            Application.Current.Dispatcher.Invoke(() =>
            {
                OnPropertyChanged(nameof(Session));
                OnPropertyChanged(nameof(HasResults));
                Dashboard.Refresh();
                Findings.Refresh();
                StatusText = $"Scan complete — {Session.PassCount} passed, {Session.FailCount} failed";
                Progress   = 100;
                CurrentPage = Dashboard;
            });
        }
        catch (OperationCanceledException)
        {
            StatusText = "Scan cancelled.";
        }
        catch (Exception ex)
        {
            StatusText = $"Error: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async Task FixSelectedAsync()
    {
        var failedSelected = Findings.SelectedFindings.Where(f => f.Status == FindingStatus.Fail).ToList();
        if (failedSelected.Count == 0) return;

        foreach (var f in failedSelected)
        {
            StatusText = $"Fixing: {f.Name}…";
            var result = await Remediation.ApplyFixAsync(f, Target);
            if (result.Success)
            {
                f.Status = FindingStatus.Pass;
                if (result.NewActualValue is not null) f.ActualValue = result.NewActualValue;
            }
        }

        Dashboard.Refresh();
        Findings.Refresh();
        StatusText = $"Batch fix complete.";
    }

    public void CancelScan() => _cts?.Cancel();
}
