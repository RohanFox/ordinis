using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace Ordinis.Views.Pages;

public partial class BackupPage : UserControl
{
    public BackupPage()
    {
        Resources.Add("BoolToVisConverter",  new BooleanToVisibilityConverter());
        Resources.Add("NotEmptyConverter",   new NotEmptyToVisibilityConverter());
        InitializeComponent();
    }
}
