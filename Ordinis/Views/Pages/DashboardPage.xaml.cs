using System.Windows.Controls;
using System.Windows.Data;
using System.Windows;

namespace Ordinis.Views.Pages;

public partial class DashboardPage : UserControl
{
    public DashboardPage()
    {
        Resources.Add("InverseBoolToVisibilityConverter", new InverseBoolToVisibilityConverter());
        Resources.Add("BoolToVisibilityConverter", new BooleanToVisibilityConverter());
        InitializeComponent();
    }
}

public class InverseBoolToVisibilityConverter : System.Windows.Data.IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => value is bool b && b ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => throw new NotImplementedException();
}
