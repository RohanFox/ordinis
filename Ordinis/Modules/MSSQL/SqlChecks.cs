using Ordinis.Core.Models;

namespace Ordinis.Modules.MSSQL;

public static class SqlChecks
{
    public static List<Finding> GetAll() => new()
    {
        // ── Authentication & Access ──────────────────────────────────────────────
        Sql("SQL-2.1", "SA account is disabled",
            "The built-in SA account should be disabled.",
            "SELECT is_disabled FROM sys.server_principals WHERE name = 'sa'",
            "1", FindingSeverity.Critical,
            "DISABLE the SA account: ALTER LOGIN [sa] DISABLE;"),

        Sql("SQL-2.2", "SA account has been renamed",
            "The SA account should be renamed to reduce attack surface.",
            "SELECT name FROM sys.server_principals WHERE sid = 0x01",
            "sa", FindingSeverity.High,
            "Rename SA: ALTER LOGIN [sa] WITH NAME = [SysAdmin_Renamed];",
            "!="),

        Sql("SQL-2.3", "Windows-only authentication mode",
            "Mixed-mode authentication enables SQL logins which are weaker than Windows authentication.",
            "SELECT SERVERPROPERTY('IsIntegratedSecurityOnly')",
            "1", FindingSeverity.Critical,
            "Switch to Windows-only auth in SQL Server Properties > Security."),

        Sql("SQL-2.4", "BUILTIN\\Administrators not a SQL login",
            "The BUILTIN\\Administrators group should not be a SQL Server login.",
            "SELECT COUNT(*) FROM sys.server_principals WHERE name = 'BUILTIN\\Administrators'",
            "0", FindingSeverity.High,
            "DROP LOGIN [BUILTIN\\Administrators];"),

        Sql("SQL-2.5", "Guest user CONNECT revoked in all databases",
            "The guest user should not have CONNECT permission in user databases.",
            "SELECT COUNT(*) FROM sys.databases d INNER JOIN sys.database_permissions p ON p.grantee_principal_id = DATABASE_PRINCIPAL_ID('guest') WHERE p.permission_name = 'CONNECT' AND d.name NOT IN ('master','tempdb','msdb')",
            "0", FindingSeverity.High,
            "For each affected DB: REVOKE CONNECT FROM guest;"),

        Sql("SQL-2.6", "xp_cmdshell is disabled",
            "xp_cmdshell allows OS command execution from SQL Server.",
            "SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'",
            "0", FindingSeverity.Critical,
            "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;"),

        // ── Surface Area Reduction ────────────────────────────────────────────────
        Sql("SQL-3.1", "Ad Hoc Distributed Queries disabled",
            "Ad hoc queries should be disabled to reduce attack surface.",
            "SELECT value_in_use FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries'",
            "0", FindingSeverity.High,
            "EXEC sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE;"),

        Sql("SQL-3.2", "CLR enabled is 0",
            "CLR integration should be disabled unless explicitly required.",
            "SELECT value_in_use FROM sys.configurations WHERE name = 'clr enabled'",
            "0", FindingSeverity.Medium,
            "EXEC sp_configure 'clr enabled', 0; RECONFIGURE;"),

        Sql("SQL-3.3", "Cross DB Ownership Chaining disabled",
            "Cross-database ownership chaining can lead to privilege escalation.",
            "SELECT value_in_use FROM sys.configurations WHERE name = 'cross db ownership chaining'",
            "0", FindingSeverity.High,
            "EXEC sp_configure 'cross db ownership chaining', 0; RECONFIGURE;"),

        Sql("SQL-3.4", "Database Mail XPs disabled",
            "Database Mail should be disabled unless required.",
            "SELECT value_in_use FROM sys.configurations WHERE name = 'Database Mail XPs'",
            "0", FindingSeverity.Medium,
            "EXEC sp_configure 'Database Mail XPs', 0; RECONFIGURE;"),

        Sql("SQL-3.5", "Ole Automation Procedures disabled",
            "OLE Automation allows execution of COM objects from SQL Server.",
            "SELECT value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures'",
            "0", FindingSeverity.High,
            "EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;"),

        Sql("SQL-3.6", "Remote Access disabled",
            "Remote access allows execution of stored procedures on remote SQL Servers.",
            "SELECT value_in_use FROM sys.configurations WHERE name = 'remote access'",
            "0", FindingSeverity.High,
            "EXEC sp_configure 'remote access', 0; RECONFIGURE WITH OVERRIDE;"),

        Sql("SQL-3.7", "Scan For Startup Procs disabled",
            "Startup procedures run automatically at SQL Server startup.",
            "SELECT value_in_use FROM sys.configurations WHERE name = 'scan for startup procs'",
            "0", FindingSeverity.Medium,
            "EXEC sp_configure 'scan for startup procs', 0; RECONFIGURE WITH OVERRIDE;"),

        Sql("SQL-3.8", "No TRUSTWORTHY databases",
            "TRUSTWORTHY database property can be used to elevate privileges.",
            "SELECT COUNT(*) FROM sys.databases WHERE is_trustworthy_on = 1 AND name != 'msdb'",
            "0", FindingSeverity.Critical,
            "ALTER DATABASE [YourDB] SET TRUSTWORTHY OFF;"),

        Sql("SQL-3.9", "Remote Admin Connections limited",
            "The Dedicated Admin Connection should be restricted to local connections.",
            "SELECT value_in_use FROM sys.configurations WHERE name = 'remote admin connections'",
            "0", FindingSeverity.Medium,
            "EXEC sp_configure 'remote admin connections', 0; RECONFIGURE;"),

        // ── Auditing ─────────────────────────────────────────────────────────────
        Sql("SQL-4.1", "Login audit level captures failed and successful logins",
            "SQL Server should log both successful and failed login attempts.",
            "SELECT CAST(value_in_use AS VARCHAR) FROM sys.configurations WHERE name = 'audit level'",
            "3", FindingSeverity.High,
            "Set login auditing to 'Both failed and successful logins' in SQL Server Properties > Security."),

        Sql("SQL-4.2", "SQL Server Audit object exists and is enabled",
            "A SQL Server Audit should be in place to capture security events.",
            "SELECT COUNT(*) FROM sys.server_audits WHERE is_state_enabled = 1",
            "1", FindingSeverity.High,
            "Create a SQL Server Audit via SSMS > Security > Audits.",
            ">="),

        Sql("SQL-4.3", "Error log retention at least 12 files",
            "SQL Server error logs should be retained for forensic purposes.",
            "SELECT CAST(value_in_use AS INT) FROM sys.configurations WHERE name = 'number of files for SQL Server error log'",
            "12", FindingSeverity.Low,
            "EXEC sp_configure 'number of files for SQL Server error log', 12; RECONFIGURE;",
            ">="),

        // ── Encryption ────────────────────────────────────────────────────────────
        Sql("SQL-5.1", "Force Encryption = 1 (TLS required)",
            "SQL Server should require encrypted connections.",
            "SELECT CAST(value AS NVARCHAR) FROM sys.dm_server_registry WHERE registry_key LIKE '%SuperSocketNetLib%' AND value_name = 'Encrypt'",
            "1", FindingSeverity.Critical,
            "Enable 'Force Encryption' in SQL Server Configuration Manager > Network Configuration > Protocols."),

        Sql("SQL-5.2", "No databases without TDE (production)",
            "Transparent Data Encryption should be enabled on databases containing sensitive data.",
            "SELECT COUNT(*) FROM sys.databases WHERE is_encrypted = 0 AND name NOT IN ('master','tempdb','model','msdb')",
            "0", FindingSeverity.High,
            "ALTER DATABASE [YourDB] SET ENCRYPTION ON; (Requires a DEK and master key setup.)"),

        // ── Jobs & Agent ──────────────────────────────────────────────────────────
        Sql("SQL-6.1", "SQL Agent jobs not owned by SA",
            "SQL Agent jobs should not be owned by the SA account.",
            "SELECT COUNT(*) FROM msdb.dbo.sysjobs WHERE owner_sid = (SELECT sid FROM sys.server_principals WHERE name = 'sa')",
            "0", FindingSeverity.Medium,
            "Update job ownership: EXEC msdb.dbo.sp_update_job @job_name=N'YourJob', @owner_login_name=N'domain\\svc_sqlagent';"),

        Sql("SQL-6.2", "SQL Server Agent not running as Local System",
            "The SQL Server Agent service should not run under LocalSystem.",
            "SELECT service_account FROM sys.dm_server_services WHERE servicename LIKE '%Agent%'",
            "LocalSystem", FindingSeverity.High,
            "Change SQL Server Agent service account to a least-privilege domain account.",
            "!="),
    };

    private static Finding Sql(
        string id, string name, string description,
        string query, string expected, FindingSeverity severity,
        string remediation, string op = "=")
    => new()
    {
        Id              = id,
        Module          = FindingModule.MSSQL,
        Category        = id.StartsWith("SQL-2") ? "Authentication & Access"
                        : id.StartsWith("SQL-3") ? "Surface Area Reduction"
                        : id.StartsWith("SQL-4") ? "Auditing & Logging"
                        : id.StartsWith("SQL-5") ? "Encryption"
                        :                          "Agent & Jobs",
        Name            = name,
        Description     = description,
        Benchmark       = "CIS SQL Server",
        BenchmarkRef    = id,
        Severity        = severity,
        Method          = "sql_query",
        CheckParams     = new() { ["Query"] = query },
        ExpectedValue   = expected,
        Operator        = op,
        RemediationText = remediation,
        IsSafeToAutoFix = false  // SQL changes always require manual confirmation
    };
}
