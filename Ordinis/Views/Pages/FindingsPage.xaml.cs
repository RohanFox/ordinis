using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace Ordinis.Views.Pages;

public partial class FindingsPage : UserControl
{
    public FindingsPage()
    {
        Resources.Add("BoolToVisibilityConverter", new BooleanToVisibilityConverter());
        Resources.Add("InverseBoolToVisConverter", new InverseBoolVisConverter());
        InitializeComponent();
    }
}

public class InverseBoolVisConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c)
        => value is bool b && b ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotImplementedException();
}
