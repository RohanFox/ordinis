using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using Ordinis.Core.Models;
using Ordinis.Core.Mvvm;

namespace Ordinis.ViewModels;

public class BackupViewModel : BaseViewModel
{
    private readonly MainViewModel _main;

    public ObservableCollection<BackupEntry> Backups { get; } = new();

    private BackupEntry? _selected;
    public BackupEntry? Selected
    {
        get => _selected;
        set { SetField(ref _selected, value); OnPropertyChanged(nameof(HasSelection)); }
    }
    public bool HasSelection => Selected is not null;

    private string _statusMessage = string.Empty;
    public string StatusMessage
    {
        get => _statusMessage;
        set => SetField(ref _statusMessage, value);
    }

    public AsyncRelayCommand RestoreCommand    { get; }
    public AsyncRelayCommand DeleteCommand     { get; }
    public AsyncRelayCommand BackupAllCommand  { get; }
    public RelayCommand      RefreshCommand    { get; }
    public RelayCommand      OpenFolderCommand { get; }

    public BackupViewModel(MainViewModel main)
    {
        _main = main;
        RestoreCommand   = new AsyncRelayCommand(RestoreAsync,   () => HasSelection);
        DeleteCommand    = new AsyncRelayCommand(DeleteAsync,    () => HasSelection);
        BackupAllCommand = new AsyncRelayCommand(BackupAllAsync, () => _main.HasResults);
        RefreshCommand   = new RelayCommand(LoadBackups);
        OpenFolderCommand = new RelayCommand(OpenFolder);
        LoadBackups();
    }

    public void LoadBackups()
    {
        Backups.Clear();
        foreach (var b in _main.BackupMgr.LoadIndex().OrderByDescending(b => b.CreatedAt))
            Backups.Add(b);
    }

    private async Task RestoreAsync()
    {
        if (Selected is null) return;
        var confirm = MessageBox.Show(
            $"Restore backup:\n{Selected.FindingName}\n({Selected.TypeLabel}, {Selected.CreatedAt:g})\n\nThis will revert the setting to its previous value.",
            "Ordinis — Restore Backup", MessageBoxButton.YesNo, MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes) return;
        StatusMessage = "Restoring…";
        bool ok = await _main.BackupMgr.RestoreAsync(Selected);
        StatusMessage = ok ? "Restore successful." : "Restore failed — see PowerShell error output.";
    }

    private async Task DeleteAsync()
    {
        if (Selected is null) return;
        var confirm = MessageBox.Show(
            $"Delete backup for '{Selected.FindingName}'?\nThis cannot be undone.",
            "Ordinis — Delete Backup", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;
        _main.BackupMgr.DeleteBackup(Selected);
        Backups.Remove(Selected);
        Selected      = null;
        StatusMessage = "Backup deleted.";
        await Task.CompletedTask;
    }

    private async Task BackupAllAsync()
    {
        StatusMessage = "Creating full security policy backup…";
        await _main.BackupMgr.BackupSecurityPolicyAsync();
        await _main.BackupMgr.BackupAuditPolicyAsync();
        LoadBackups();
        StatusMessage = "Full backup complete.";
    }

    private void OpenFolder()
    {
        string dir = Path.Combine(AppContext.BaseDirectory, "Backups");
        Directory.CreateDirectory(dir);
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(dir) { UseShellExecute = true });
    }
}
