using System.Windows.Controls;

namespace Ordinis.Views.Pages;

public partial class ReportPage : UserControl
{
    public ReportPage()
    {
        Resources.Add("NotEmptyConv", new NotEmptyToVisibilityConverter());
        InitializeComponent();
    }
}
