using System.IO;
using Newtonsoft.Json;
using Ordinis.Core.Models;

namespace Ordinis.Core.Services;

public class BackupManager
{
    private readonly string _backupRoot;
    private readonly PowerShellRunner _ps;
    private readonly string _indexFile;

    public BackupManager()
    {
        _backupRoot = Path.Combine(AppContext.BaseDirectory, "Backups");
        _indexFile  = Path.Combine(_backupRoot, "index.json");
        _ps         = new PowerShellRunner();
        Directory.CreateDirectory(_backupRoot);
    }

    public List<BackupEntry> LoadIndex()
    {
        if (!File.Exists(_indexFile)) return new();
        try
        {
            var json = File.ReadAllText(_indexFile);
            return JsonConvert.DeserializeObject<List<BackupEntry>>(json) ?? new();
        }
        catch { return new(); }
    }

    private void SaveIndex(List<BackupEntry> entries)
    {
        File.WriteAllText(_indexFile, JsonConvert.SerializeObject(entries, Formatting.Indented));
    }

    public async Task<BackupEntry?> BackupRegistryKeyAsync(Finding finding, CancellationToken ct = default)
    {
        if (!finding.CheckParams.TryGetValue("RegistryPath", out string? regPath) || string.IsNullOrEmpty(regPath))
            return null;

        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string fileName  = $"reg_{finding.Id}_{timestamp}.reg";
        string filePath  = Path.Combine(_backupRoot, fileName);

        var result = await _ps.RunScriptAsync("Backup/Backup-Registry.ps1",
            new() { ["RegistryPath"] = regPath, ["OutputFile"] = filePath }, ct: ct);

        if (!result.Success) return null;

        var entry = new BackupEntry
        {
            Type        = BackupType.Registry,
            FindingId   = finding.Id,
            FindingName = finding.Name,
            FilePath    = filePath,
            OldValue    = finding.ActualValue
        };
        AppendToIndex(entry);
        finding.BackupTaken = true;
        return entry;
    }

    public async Task<BackupEntry?> BackupSecurityPolicyAsync(CancellationToken ct = default)
    {
        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string fileName  = $"secedit_{timestamp}.ini";
        string filePath  = Path.Combine(_backupRoot, fileName);

        var result = await _ps.RunScriptAsync("Backup/Backup-SecurityPolicy.ps1",
            new() { ["OutputFile"] = filePath }, ct: ct);

        if (!result.Success) return null;

        var entry = new BackupEntry
        {
            Type        = BackupType.SecurityPolicy,
            FindingName = "Full Security Policy Export",
            FilePath    = filePath
        };
        AppendToIndex(entry);
        return entry;
    }

    public async Task<BackupEntry?> BackupAuditPolicyAsync(CancellationToken ct = default)
    {
        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string fileName  = $"auditpol_{timestamp}.csv";
        string filePath  = Path.Combine(_backupRoot, fileName);

        var result = await _ps.RunScriptAsync("Backup/Backup-AuditPolicy.ps1",
            new() { ["OutputFile"] = filePath }, ct: ct);

        if (!result.Success) return null;

        var entry = new BackupEntry
        {
            Type        = BackupType.AuditPolicy,
            FindingName = "Full Audit Policy Export",
            FilePath    = filePath
        };
        AppendToIndex(entry);
        return entry;
    }

    public async Task<bool> RestoreAsync(BackupEntry entry, CancellationToken ct = default)
    {
        if (!File.Exists(entry.FilePath)) return false;

        var (script, param) = entry.Type switch
        {
            BackupType.Registry       => ("Backup/Restore-Registry.ps1",       "RegFile"),
            BackupType.SecurityPolicy => ("Backup/Restore-SecurityPolicy.ps1",  "IniFile"),
            BackupType.AuditPolicy    => ("Backup/Restore-AuditPolicy.ps1",     "CsvFile"),
            _                         => (string.Empty, string.Empty)
        };

        if (string.IsNullOrEmpty(script)) return false;

        var result = await _ps.RunScriptAsync(script, new() { [param] = entry.FilePath }, ct: ct);
        return result.Success;
    }

    public void DeleteBackup(BackupEntry entry)
    {
        if (File.Exists(entry.FilePath))
            try { File.Delete(entry.FilePath); } catch { }

        var index = LoadIndex();
        index.RemoveAll(e => e.Id == entry.Id);
        SaveIndex(index);
    }

    private void AppendToIndex(BackupEntry entry)
    {
        var index = LoadIndex();
        index.Add(entry);
        SaveIndex(index);
    }
}
