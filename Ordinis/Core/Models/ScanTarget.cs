using Microsoft.Data.SqlClient;

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
            var builder = new SqlConnectionStringBuilder
            {
                DataSource             = string.IsNullOrWhiteSpace(SqlServer) ? "localhost" : SqlServer,
                InitialCatalog         = SqlDatabase,
                TrustServerCertificate = true
            };
            if (SqlWindowsAuth)
            {
                builder.IntegratedSecurity = true;
            }
            else
            {
                builder.UserID   = SqlUsername;
                builder.Password = SqlPassword;
            }
            return builder.ConnectionString;
        }
    }
}
