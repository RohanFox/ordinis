namespace Ordinis.Core.Models;

public enum BackupType { Registry, SecurityPolicy, AuditPolicy, IIS, MSSQL, SystemRestore }

public class BackupEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public BackupType Type { get; set; }
    public string FindingId { get; set; } = string.Empty;
    public string FindingName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string OldValue { get; set; } = string.Empty;
    public string NewValue { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public string MachineName { get; set; } = Environment.MachineName;

    public string TypeLabel => Type switch
    {
        BackupType.Registry      => "Registry",
        BackupType.SecurityPolicy=> "Security Policy",
        BackupType.AuditPolicy   => "Audit Policy",
        BackupType.IIS           => "IIS Config",
        BackupType.MSSQL         => "SQL Server",
        BackupType.SystemRestore => "System Restore",
        _                        => "Unknown"
    };

    public string TypeIcon => Type switch
    {
        BackupType.Registry       => "RegistryEditorIcon",
        BackupType.SecurityPolicy => "ShieldAccount",
        BackupType.AuditPolicy    => "ClipboardCheck",
        BackupType.IIS            => "Web",
        BackupType.MSSQL          => "Database",
        BackupType.SystemRestore  => "RestoreAlert",
        _                         => "ContentSave"
    };
}
