using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using Ordinis.Core.Models;
using Ordinis.Core.Mvvm;
using Ordinis.Modules.GPO;

namespace Ordinis.ViewModels;

public class GpoViewModel : BaseViewModel
{
    private readonly MainViewModel _main;

    public ObservableCollection<GpoInfo> AppliedGpos { get; } = new();

    private bool _isLoading;
    public bool IsLoading
    {
        get => _isLoading;
        set => SetField(ref _isLoading, value);
    }

    private string _statusMessage = string.Empty;
    public string StatusMessage
    {
        get => _statusMessage;
        set => SetField(ref _statusMessage, value);
    }

    private string _lgpoPath = string.Empty;
    public string LgpoFilePath
    {
        get => _lgpoPath;
        set => SetField(ref _lgpoPath, value);
    }

    public AsyncRelayCommand LoadGposCommand    { get; }
    public AsyncRelayCommand ExportLgpoCommand  { get; }
    public AsyncRelayCommand ApplyLgpoCommand   { get; }
    public AsyncRelayCommand GenerateReportCommand { get; }

    public GpoViewModel(MainViewModel main)
    {
        _main = main;
        LoadGposCommand       = new AsyncRelayCommand(LoadGposAsync);
        ExportLgpoCommand     = new AsyncRelayCommand(ExportLgpoAsync,  () => _main.HasResults);
        ApplyLgpoCommand      = new AsyncRelayCommand(ApplyLgpoAsync,   () => !string.IsNullOrEmpty(LgpoFilePath));
        GenerateReportCommand = new AsyncRelayCommand(GenerateGpoReportAsync);
    }

    private async Task LoadGposAsync()
    {
        IsLoading     = true;
        StatusMessage = "Loading applied GPOs…";
        AppliedGpos.Clear();

        var gpos = await _main.GpoMod.GetAppliedGposAsync();
        foreach (var g in gpos) AppliedGpos.Add(g);

        StatusMessage = AppliedGpos.Count > 0
            ? $"{AppliedGpos.Count} GPO(s) applied to this machine."
            : "No GPOs found (or RSAT not installed).";
        IsLoading = false;
    }

    private async Task ExportLgpoAsync()
    {
        var failed  = _main.Session.Findings.Where(f => f.Status == FindingStatus.Fail).ToList();
        if (failed.Count == 0)
        {
            StatusMessage = "No failed findings to export.";
            return;
        }

        IsLoading     = true;
        StatusMessage = "Generating LGPO file…";

        string outDir = Path.Combine(AppContext.BaseDirectory, "Exports");
        string path   = await _main.GpoMod.ExportAsLgpoAsync(failed, outDir);

        LgpoFilePath  = path;
        StatusMessage = $"LGPO file exported: {Path.GetFileName(path)}";
        IsLoading     = false;
    }

    private async Task ApplyLgpoAsync()
    {
        if (string.IsNullOrEmpty(LgpoFilePath)) return;

        var confirm = MessageBox.Show(
            $"Apply LGPO settings from:\n{LgpoFilePath}\n\nThis will modify local group policy on this machine.",
            "Ordinis — Apply LGPO",
            MessageBoxButton.YesNo, MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes) return;

        IsLoading     = true;
        StatusMessage = "Applying LGPO settings…";

        var (success, message) = await _main.GpoMod.ApplyLgpoFileAsync(LgpoFilePath);
        StatusMessage = message;
        IsLoading     = false;
    }

    private async Task GenerateGpoReportAsync()
    {
        IsLoading     = true;
        StatusMessage = "Generating GPO report (gpresult)…";

        string outPath = Path.Combine(AppContext.BaseDirectory, "Exports",
            $"gpo_report_{DateTime.Now:yyyyMMdd_HHmmss}.html");
        Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);

        string result = await _main.GpoMod.GenerateGpoReportAsync(outPath);
        if (!string.IsNullOrEmpty(result) && File.Exists(result))
        {
            StatusMessage = $"GPO report saved: {Path.GetFileName(result)}";
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(result) { UseShellExecute = true });
        }
        else
            StatusMessage = "GPO report generation failed. Ensure RSAT Group Policy tools are installed.";

        IsLoading = false;
    }
}
