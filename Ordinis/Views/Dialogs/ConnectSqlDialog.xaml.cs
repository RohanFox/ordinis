using System.Windows;
using System.Windows.Controls;
using Ordinis.Core.Models;
using Ordinis.Modules.MSSQL;

namespace Ordinis.Views.Dialogs;

public partial class ConnectSqlDialog : Window
{
    public ScanTarget ResultTarget { get; private set; } = new() { Type = TargetType.Local };

    private readonly SqlModule _sqlModule;

    public ConnectSqlDialog(SqlModule sqlModule, ScanTarget? existing = null)
    {
        InitializeComponent();
        _sqlModule = sqlModule;

        if (existing is not null)
        {
            TxtServer.Text = existing.SqlServer;
            if (!existing.SqlWindowsAuth)
            {
                RbSqlAuth.IsChecked = true;
                TxtUsername.Text    = existing.SqlUsername;
            }
        }
    }

    private void AuthMode_Changed(object sender, RoutedEventArgs e)
    {
        if (PanelSqlCreds is null) return;
        PanelSqlCreds.Visibility = RbSqlAuth.IsChecked == true
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private async void Test_Click(object sender, RoutedEventArgs e)
    {
        var target = BuildTarget();
        TxtTestResult.Visibility = Visibility.Visible;
        TxtTestResult.Foreground = System.Windows.Media.Brushes.Orange;
        TxtTestResult.Text = "Testing connection…";

        try
        {
            bool ok = await _sqlModule.TestConnectionAsync(target);
            if (ok)
            {
                string ver = await _sqlModule.GetSqlVersionAsync(target);
                TxtTestResult.Foreground = new System.Windows.Media.SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#22C55E"));
                TxtTestResult.Text = $"Connected: {ver}";
            }
            else
            {
                TxtTestResult.Foreground = new System.Windows.Media.SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#EF4444"));
                TxtTestResult.Text = "Connection failed. Check server name and credentials.";
            }
        }
        catch (Exception ex)
        {
            TxtTestResult.Foreground = new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#EF4444"));
            TxtTestResult.Text = $"Error: {ex.Message}";
        }
    }

    private void Connect_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(TxtServer.Text))
        {
            TxtTestResult.Visibility = Visibility.Visible;
            TxtTestResult.Foreground = new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#EF4444"));
            TxtTestResult.Text = "Server name is required.";
            return;
        }

        ResultTarget = BuildTarget();
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private ScanTarget BuildTarget()
    {
        bool sqlAuth = RbSqlAuth.IsChecked == true;
        return new ScanTarget
        {
            Type           = TargetType.Local,
            SqlServer      = TxtServer.Text.Trim(),
            SqlWindowsAuth = !sqlAuth,
            SqlUsername    = sqlAuth ? TxtUsername.Text.Trim() : string.Empty,
            SqlPassword    = sqlAuth ? PbPassword.Password    : string.Empty
        };
    }
}
