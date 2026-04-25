using System.Diagnostics;
using System.Windows;
using System.Windows.Navigation;

namespace Ordinis.Views.Dialogs;

public partial class AboutDialog : Window
{
    public AboutDialog() => InitializeComponent();
    private void OnClose(object s, RoutedEventArgs e)   => Close();
    private void OnNavigate(object s, RequestNavigateEventArgs e)
    {
        Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        e.Handled = true;
    }
}
