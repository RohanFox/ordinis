namespace Ordinis.Core.Models;

public enum TargetType { Local, Remote }

public class ScanTarget
{
    public TargetType Type { get; set; } = TargetType.Local;
    public string DisplayName => Type == TargetType.Local
        ? $"Local — {Environment.MachineName}"
        : $"Remote — {Hostname}";

    // Remote fields
    public string Hostname { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public int WinRmPort { get; set; } = 5985;
    public bool UseHttps { get; set; } = false;

    // SQL Server fields
    public string SqlServer { get; set; } = string.Empty;
    public string SqlDatabase { get; set; } = "master";
    public bool SqlWindowsAuth { get; set; } = true;
    public string SqlUsername { get; set; } = string.Empty;
    public string SqlPassword { get; set; } = string.Empty;

    public bool HasSqlConnection => !string.IsNullOrWhiteSpace(SqlServer);

    public string SqlConnectionString
    {
        get
        {
            string server = string.IsNullOrWhiteSpace(SqlServer) ? "localhost" : SqlServer;
            if (SqlWindowsAuth)
                return $"Server={server};Database={SqlDatabase};Integrated Security=True;TrustServerCertificate=True;";
            return $"Server={server};Database={SqlDatabase};User Id={SqlUsername};Password={SqlPassword};TrustServerCertificate=True;";
        }
    }
}
