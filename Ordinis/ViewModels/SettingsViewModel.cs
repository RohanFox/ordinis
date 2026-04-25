using System.IO;
using Ordinis.Core.Mvvm;

namespace Ordinis.ViewModels;

public class SettingsViewModel : BaseViewModel
{
    private readonly MainViewModel _main;

    public string SqlServer
    {
        get => _main.Target.SqlServer;
        set { _main.Target.SqlServer = value; OnPropertyChanged(); }
    }

    public bool SqlWindowsAuth
    {
        get => _main.Target.SqlWindowsAuth;
        set { _main.Target.SqlWindowsAuth = value; OnPropertyChanged(); OnPropertyChanged(nameof(SqlAuthVisible)); }
    }

    public string SqlUsername
    {
        get => _main.Target.SqlUsername;
        set { _main.Target.SqlUsername = value; OnPropertyChanged(); }
    }

    public string SqlPassword
    {
        get => _main.Target.SqlPassword;
        set { _main.Target.SqlPassword = value; OnPropertyChanged(); }
    }

    public bool SqlAuthVisible => !SqlWindowsAuth;

    public string FindingListsPath
    {
        get => _findingListsPath;
        set => SetField(ref _findingListsPath, value);
    }
    private string _findingListsPath =
        Path.Combine(AppContext.BaseDirectory, "Data", "FindingLists");

    public AsyncRelayCommand TestSqlCommand { get; }

    private string _sqlTestResult = string.Empty;
    public string SqlTestResult
    {
        get => _sqlTestResult;
        set => SetField(ref _sqlTestResult, value);
    }

    public SettingsViewModel(MainViewModel main)
    {
        _main          = main;
        TestSqlCommand = new AsyncRelayCommand(TestSqlConnectionAsync);
    }

    private async Task TestSqlConnectionAsync()
    {
        SqlTestResult = "Testing…";
        bool ok = await _main.SqlMod.TestConnectionAsync(_main.Target);
        if (ok)
        {
            string ver = await _main.SqlMod.GetSqlVersionAsync(_main.Target);
            SqlTestResult = $"Connected: {ver[..Math.Min(ver.Length, 60)]}";
        }
        else
        {
            SqlTestResult = "Connection failed. Check server name and credentials.";
        }
    }
}
