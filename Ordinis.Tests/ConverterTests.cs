using System.Globalization;
using System.Windows;
using Ordinis.Core.Mvvm;

namespace Ordinis.Tests;

public class ConverterTests
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    // ── InverseBoolToVisibilityConverter ─────────────────────────────────────
    [Theory]
    [InlineData(true,  Visibility.Collapsed)]
    [InlineData(false, Visibility.Visible)]
    public void InverseBool_converts(bool input, Visibility expected)
    {
        var c = new InverseBoolToVisibilityConverter();
        Assert.Equal(expected, c.Convert(input, typeof(Visibility), null!, Inv));
    }

    // ── StringNotEmptyToVisibilityConverter ──────────────────────────────────
    [Theory]
    [InlineData("hello",   Visibility.Visible)]
    [InlineData("",        Visibility.Collapsed)]
    [InlineData("   ",     Visibility.Collapsed)]
    [InlineData(null,      Visibility.Collapsed)]
    public void StringNotEmpty_converts(string? input, Visibility expected)
    {
        var c = new StringNotEmptyToVisibilityConverter();
        Assert.Equal(expected, c.Convert(input!, typeof(Visibility), null!, Inv));
    }

    // ── IntGreaterThanZeroToVisibilityConverter ───────────────────────────────
    [Theory]
    [InlineData(1,  Visibility.Visible)]
    [InlineData(10, Visibility.Visible)]
    [InlineData(0,  Visibility.Collapsed)]
    [InlineData(-1, Visibility.Collapsed)]
    public void IntGtZero_converts(int input, Visibility expected)
    {
        var c = new IntGreaterThanZeroToVisibilityConverter();
        Assert.Equal(expected, c.Convert(input, typeof(Visibility), null!, Inv));
    }
}
