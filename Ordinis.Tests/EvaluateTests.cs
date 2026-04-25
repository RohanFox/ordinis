using Ordinis.Modules.Windows;

namespace Ordinis.Tests;

public class EvaluateTests
{
    // ── Equality ─────────────────────────────────────────────────────────────
    [Theory]
    [InlineData("1",   "1",  true)]
    [InlineData("0",   "1",  false)]
    [InlineData("yes", "yes", true)]
    [InlineData("Yes", "yes", true)]    // = is case-insensitive (registry values)
    public void Equals_operator(string actual, string expected, bool pass)
        => Assert.Equal(pass, WindowsModule.Evaluate(actual, expected, "="));

    [Theory]
    [InlineData("sa",   "sa",  false)]
    [InlineData("admin","sa",  true)]
    public void NotEquals_operator(string actual, string expected, bool pass)
        => Assert.Equal(pass, WindowsModule.Evaluate(actual, expected, "!="));

    // ── Numeric comparisons ───────────────────────────────────────────────────
    [Theory]
    [InlineData("14", "14", true)]
    [InlineData("15", "14", true)]
    [InlineData("13", "14", false)]
    public void GreaterOrEqual_operator(string actual, string expected, bool pass)
        => Assert.Equal(pass, WindowsModule.Evaluate(actual, expected, ">="));

    [Theory]
    [InlineData("60", "60", true)]
    [InlineData("59", "60", true)]
    [InlineData("61", "60", false)]
    public void LessOrEqual_operator(string actual, string expected, bool pass)
        => Assert.Equal(pass, WindowsModule.Evaluate(actual, expected, "<="));

    // ── Contains ─────────────────────────────────────────────────────────────
    [Theory]
    [InlineData("state disabled", "disabled", true)]
    [InlineData("state enabled",  "disabled", false)]
    [InlineData("DISABLED",       "disabled", true)]   // case-insensitive
    public void Contains_operator(string actual, string expected, bool pass)
        => Assert.Equal(pass, WindowsModule.Evaluate(actual, expected, "contains"));

    // ── Edge cases ────────────────────────────────────────────────────────────
    [Fact]
    public void NonNumeric_GreaterOrEqual_returns_false()
        => Assert.False(WindowsModule.Evaluate("abc", "14", ">="));

    [Fact]
    public void Unknown_operator_returns_false()
        => Assert.False(WindowsModule.Evaluate("1", "1", "???"));
}
