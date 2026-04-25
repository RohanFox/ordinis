using Microsoft.Data.SqlClient;
using Ordinis.Core.Models;
using Ordinis.Modules.Base;
using Ordinis.Modules.Windows;
using Newtonsoft.Json;

namespace Ordinis.Modules.MSSQL;

public class SqlModule : IModule
{
    public FindingModule Module  => FindingModule.MSSQL;
    public string DisplayName    => "SQL Server";
    public string Description    => "CIS SQL Server benchmark — authentication, surface area, auditing, encryption";

    public Task<List<Finding>> GetFindingsAsync(ScanProfile profile, CancellationToken ct = default)
    {
        return Task.FromResult(SqlChecks.GetAll());
    }

    public async Task AuditFindingAsync(Finding finding, ScanTarget target, CancellationToken ct = default)
    {
        if (!target.HasSqlConnection)
        {
            finding.Status       = FindingStatus.Skipped;
            finding.ErrorMessage = "No SQL Server connection configured.";
            return;
        }

        try
        {
            using var conn = new SqlConnection(target.SqlConnectionString);
            await conn.OpenAsync(ct);

            finding.CheckParams.TryGetValue("Query", out string? query);
            if (string.IsNullOrEmpty(query))
            {
                finding.Status = FindingStatus.Skipped;
                return;
            }

            using var cmd    = new SqlCommand(query, conn) { CommandTimeout = 30 };
            var result       = await cmd.ExecuteScalarAsync(ct);
            finding.ActualValue = result?.ToString() ?? "-NODATA-";

            finding.Status = WindowsModule.Evaluate(finding.ActualValue, finding.ExpectedValue, finding.Operator)
                             ? FindingStatus.Pass : FindingStatus.Fail;
        }
        catch (SqlException ex)
        {
            finding.Status       = FindingStatus.Error;
            finding.ErrorMessage = $"SQL error: {ex.Message}";
        }
        catch (Exception ex)
        {
            finding.Status       = FindingStatus.Error;
            finding.ErrorMessage = ex.Message;
        }
    }

    public async Task<bool> TestConnectionAsync(ScanTarget target, CancellationToken ct = default)
    {
        try
        {
            using var conn = new SqlConnection(target.SqlConnectionString);
            await conn.OpenAsync(ct);
            return true;
        }
        catch { return false; }
    }

    public async Task<string> GetSqlVersionAsync(ScanTarget target, CancellationToken ct = default)
    {
        try
        {
            using var conn = new SqlConnection(target.SqlConnectionString);
            await conn.OpenAsync(ct);
            using var cmd  = new SqlCommand("SELECT @@VERSION", conn);
            var result     = await cmd.ExecuteScalarAsync(ct);
            return result?.ToString() ?? "Unknown";
        }
        catch { return "Unknown"; }
    }
}
