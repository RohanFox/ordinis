using System.Windows;
using Ordinis.Core.Models;
using Ordinis.Core.Services;

namespace Ordinis.Views.Dialogs;

public partial class RemoteConnectDialog : Window
{
    public ScanTarget ResultTarget { get; private set; } = new() { Type = TargetType.Local };

    private readonly PowerShellRunner _ps;

    public RemoteConnectDialog(PowerShellRunner ps, ScanTarget? existing = null)
    {
        InitializeComponent();
        _ps = ps;

        if (existing?.Type == TargetType.Remote)
        {
            TxtHostname.Text  = existing.Hostname;
            TxtPort.Text      = existing.WinRmPort.ToString();
            ChkHttps.IsChecked = existing.UseHttps;
            TxtUsername.Text  = existing.Username;
        }
    }

    private void Https_Changed(object sender, RoutedEventArgs e)
    {
        if (TxtPort is null) return;
        TxtPort.Text = ChkHttps.IsChecked == true ? "5986" : "5985";
    }

    private async void Test_Click(object sender, RoutedEventArgs e)
    {
        TxtTestResult.Visibility = Visibility.Visible;
        TxtTestResult.Foreground = System.Windows.Media.Brushes.Orange;
        TxtTestResult.Text = "Testing WinRM…";

        try
        {
            var target = BuildTarget();
            var result = await _ps.RunInlineAsync(
                "Write-Output 'OK'",
                target.Hostname, target.Username, target.Password);

            if (result.Success && result.Output.Contains("OK"))
            {
                TxtTestResult.Foreground = new System.Windows.Media.SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#22C55E"));
                TxtTestResult.Text = $"WinRM reachable: {target.Hostname}";
            }
            else
            {
                TxtTestResult.Foreground = new System.Windows.Media.SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#EF4444"));
                TxtTestResult.Text = result.Error.Length > 0
                    ? $"Failed: {result.Error}"
                    : "Could not connect. Check hostname, credentials and WinRM configuration.";
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
        if (string.IsNullOrWhiteSpace(TxtHostname.Text))
        {
            TxtTestResult.Visibility = Visibility.Visible;
            TxtTestResult.Foreground = new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#EF4444"));
            TxtTestResult.Text = "Hostname is required.";
            return;
        }

        ResultTarget = BuildTarget();
        DialogResult = true;
    }

    private void UseLocal_Click(object sender, RoutedEventArgs e)
    {
        ResultTarget = new ScanTarget { Type = TargetType.Local };
        DialogResult = true;
    }

    private ScanTarget BuildTarget()
    {
        int.TryParse(TxtPort.Text, out int port);
        if (port <= 0) port = ChkHttps.IsChecked == true ? 5986 : 5985;

        return new ScanTarget
        {
            Type      = TargetType.Remote,
            Hostname  = TxtHostname.Text.Trim(),
            Username  = TxtUsername.Text.Trim(),
            Password  = PbPassword.Password,
            WinRmPort = port,
            UseHttps  = ChkHttps.IsChecked == true
        };
    }
}
