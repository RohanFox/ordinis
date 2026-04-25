using System.IO;
using System.Windows;
using Ordinis.Core.Mvvm;

namespace Ordinis.ViewModels;

public class ReportViewModel : BaseViewModel
{
    private readonly MainViewModel _main;

    private string _statusMessage = string.Empty;
    public string StatusMessage
    {
        get => _statusMessage;
        set => SetField(ref _statusMessage, value);
    }

    private bool _isGenerating;
    public bool IsGenerating
    {
        get => _isGenerating;
        set => SetField(ref _isGenerating, value);
    }

    public AsyncRelayCommand GenerateHtmlCommand { get; }
    public AsyncRelayCommand GenerateJsonCommand { get; }
    public AsyncRelayCommand GenerateCsvCommand  { get; }

    public ReportViewModel(MainViewModel main)
    {
        _main = main;
        GenerateHtmlCommand = new AsyncRelayCommand(GenerateHtmlAsync, () => _main.HasResults);
        GenerateJsonCommand = new AsyncRelayCommand(GenerateJsonAsync, () => _main.HasResults);
        GenerateCsvCommand  = new AsyncRelayCommand(GenerateCsvAsync,  () => _main.HasResults);
    }

    private async Task GenerateHtmlAsync()
    {
        IsGenerating  = true;
        StatusMessage = "Generating HTML report…";
        string outDir  = Path.Combine(AppContext.BaseDirectory, "Reports");
        Directory.CreateDirectory(outDir);
        string path = Path.Combine(outDir, $"ordinis_report_{DateTime.Now:yyyyMMdd_HHmmss}.html");
        await _main.Reporter.GenerateHtmlAsync(_main.Session, path);
        StatusMessage = $"HTML report saved: {Path.GetFileName(path)}";
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(path) { UseShellExecute = true });
        IsGenerating = false;
    }

    private async Task GenerateJsonAsync()
    {
        IsGenerating  = true;
        StatusMessage = "Generating JSON report…";
        string outDir  = Path.Combine(AppContext.BaseDirectory, "Reports");
        Directory.CreateDirectory(outDir);
        string path = Path.Combine(outDir, $"ordinis_report_{DateTime.Now:yyyyMMdd_HHmmss}.json");
        await _main.Reporter.GenerateJsonAsync(_main.Session, path);
        StatusMessage = $"JSON report saved: {Path.GetFileName(path)}";
        IsGenerating = false;
    }

    private async Task GenerateCsvAsync()
    {
        IsGenerating  = true;
        StatusMessage = "Generating CSV report…";
        string outDir  = Path.Combine(AppContext.BaseDirectory, "Reports");
        Directory.CreateDirectory(outDir);
        string path = Path.Combine(outDir, $"ordinis_report_{DateTime.Now:yyyyMMdd_HHmmss}.csv");
        await _main.Reporter.GenerateCsvAsync(_main.Session, path);
        StatusMessage = $"CSV report saved: {Path.GetFileName(path)}";
        IsGenerating = false;
    }
}
