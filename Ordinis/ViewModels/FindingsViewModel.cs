using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using Ordinis.Core.Models;
using Ordinis.Core.Mvvm;
using Ordinis.Views.Dialogs;

namespace Ordinis.ViewModels;

public class FindingsViewModel : BaseViewModel
{
    private readonly MainViewModel _main;

    public ObservableCollection<Finding> Displayed { get; } = new();
    public ObservableCollection<Finding> SelectedFindings { get; } = new();

    private Finding? _selected;
    public Finding? Selected
    {
        get => _selected;
        set { SetField(ref _selected, value); OnPropertyChanged(nameof(HasSelection)); }
    }

    public bool HasSelection => Selected is not null;

    // Filters
    private string _searchText = string.Empty;
    public string SearchText
    {
        get => _searchText;
        set { SetField(ref _searchText, value); Refresh(); }
    }

    private string _statusFilter = "All";
    public string StatusFilter
    {
        get => _statusFilter;
        set { SetField(ref _statusFilter, value); Refresh(); }
    }

    private string _severityFilter = "All";
    public string SeverityFilter
    {
        get => _severityFilter;
        set { SetField(ref _severityFilter, value); Refresh(); }
    }

    private string _moduleFilter = "All";
    public string ModuleFilter
    {
        get => _moduleFilter;
        set { SetField(ref _moduleFilter, value); Refresh(); }
    }

    public IEnumerable<string> StatusOptions   => new[] { "All", "Pass", "Fail", "Error", "Skipped" };
    public IEnumerable<string> SeverityOptions => new[] { "All", "Critical", "High", "Medium", "Low", "Info" };
    public IEnumerable<string> ModuleOptions   => new[] { "All", "Windows", "SQL Server", "Network", "IPv6", "Active Directory", "Kerberos", "NTLM / Credential", "Local Security", "Logging & Audit", "Attack Surface", "GPO" };

    public AsyncRelayCommand FixFindingCommand { get; }

    public FindingsViewModel(MainViewModel main)
    {
        _main = main;
        FixFindingCommand = new AsyncRelayCommand(FixSelectedAsync,
            () => Selected?.Status == FindingStatus.Fail && Selected?.IsSafeToAutoFix == true);
    }

    public void Refresh()
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            Displayed.Clear();
            foreach (var f in _main.Session.Findings.Where(Matches).OrderBy(f => f.Status).ThenByDescending(f => f.Severity))
                Displayed.Add(f);
            OnPropertyChanged(nameof(Displayed));
        });
    }

    private bool Matches(Finding f)
    {
        if (StatusFilter != "All" && !f.Status.ToString().Equals(StatusFilter, StringComparison.OrdinalIgnoreCase))
            return false;
        if (SeverityFilter != "All" && !f.Severity.ToString().Equals(SeverityFilter, StringComparison.OrdinalIgnoreCase))
            return false;
        if (ModuleFilter != "All" && !f.ModuleLabel.Equals(ModuleFilter, StringComparison.OrdinalIgnoreCase))
            return false;
        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            string q = SearchText.ToLowerInvariant();
            if (!f.Name.Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !f.Id.Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !f.Category.Contains(q, StringComparison.OrdinalIgnoreCase))
                return false;
        }
        return true;
    }

    private async Task FixSelectedAsync()
    {
        if (Selected is null) return;

        // Show confirmation dialog before touching anything
        string scriptsRoot = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Scripts");
        var dialog = new FixDialog(Selected, scriptsRoot)
        {
            Owner = Application.Current.MainWindow
        };

        if (dialog.ShowDialog() != true) return;

        _main.IsLoading  = true;
        _main.StatusText = $"Applying fix: {Selected.Name}…";

        try
        {
            var result = await _main.Remediation.ApplyFixAsync(Selected, _main.Target);
            if (result.Success)
            {
                Selected.Status = FindingStatus.Pass;
                if (result.NewActualValue is not null) Selected.ActualValue = result.NewActualValue;
                _main.Dashboard.Refresh();
                Refresh();
                _main.StatusText = $"Fix applied: {Selected.Name}";
            }
            else
            {
                MessageBox.Show($"Fix failed:\n{result.Message}", "Ordinis — Fix Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                _main.StatusText = $"Fix failed: {Selected.Name}";
            }
        }
        finally
        {
            _main.IsLoading = false;
        }
    }
}
