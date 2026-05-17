namespace Ordinis.Core;

// Single source of truth for the application version and branding strings.
// On release, bump Version here and the <Version> element in Ordinis.csproj.
public static class AppInfo
{
    public const string Version = "1.3.1";

    // "1.3.0" → "1.3" — short form used in the sidebar and report footers.
    public static string ShortVersion => Version[..Version.LastIndexOf('.')];

    public static string Edition  => $"Ordinis v{ShortVersion} · MIT";
    public static string Branding => $"Ordinis v{ShortVersion} · Free & Open Source (MIT) · github.com/RohanFox";
}
