using System.IO;
using System.Windows;
using Ordinis.Core.Models;

namespace Ordinis.Views.Dialogs;

public partial class FixDialog : Window
{
    public bool Confirmed { get; private set; }

    public FixDialog(Finding finding, string scriptsRoot)
    {
        InitializeComponent();
        DataContext = new FixDialogViewModel(finding, scriptsRoot);
    }

    private void Apply_Click(object sender, RoutedEventArgs e)
    {
        Confirmed = true;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        Confirmed = false;
        DialogResult = false;
    }
}

internal class FixDialogViewModel
{
    public string FindingId   { get; }
    public string FindingName { get; }
    public string Method      { get; }
    public string SettingPath { get; }
    public string CurrentValue { get; }
    public string NewValue    { get; }
    public bool   RequiresRestart { get; }
    public string BackupDescription { get; }
    public string ReversibleText   { get; }
    public string ScriptPreview    { get; }

    public FixDialogViewModel(Finding finding, string scriptsRoot)
    {
        FindingId   = finding.Id;
        FindingName = finding.Name;
        Method      = finding.Method;
        CurrentValue = finding.ActualValue ?? "(not set)";
        NewValue     = finding.ExpectedValue ?? "";
        RequiresRestart = finding.RequiresRestart;

        SettingPath = BuildSettingPath(finding);
        BackupDescription = BuildBackupDescription(finding);
        ReversibleText = BuildReversibleText(finding);
        ScriptPreview  = LoadScriptPreview(finding, scriptsRoot);
    }

    private static string BuildSettingPath(Finding f)
    {
        var p = f.CheckParams;
        return f.Method.ToLowerInvariant() switch
        {
            "registry"  => $"{p.GetValueOrDefault("RegistryPath", "")}\\{p.GetValueOrDefault("RegistryItem", "")}",
            "secedit"   => p.GetValueOrDefault("MethodArgument", f.Name),
            "auditpol"  => p.GetValueOrDefault("MethodArgument", f.Name),
            "accesschk" => p.GetValueOrDefault("MethodArgument", f.Name),
            "service"   => p.GetValueOrDefault("ServiceName", f.Name),
            _           => f.Name
        };
    }

    private static string BuildBackupDescription(Finding f)
    {
        return f.Method.ToLowerInvariant() switch
        {
            "registry"  => "A .reg backup of the registry key will be created before applying.",
            "secedit"   => "A full security policy backup (.ini) will be created before applying.",
            "auditpol"  => "An audit policy backup (.csv) will be created before applying.",
            "accesschk" => "A security policy backup will be created before applying.",
            _           => "Backup will be created in the Backups panel before applying."
        };
    }

    private static string BuildReversibleText(Finding f)
    {
        bool reversible = f.Method.ToLowerInvariant() is "registry" or "secedit" or "auditpol" or "accesschk";
        return reversible
            ? "Yes — restore from the Backups panel at any time."
            : "Manual restoration may be required. Review the fix script before applying.";
    }

    private static string LoadScriptPreview(Finding f, string scriptsRoot)
    {
        string scriptName = f.Method.ToLowerInvariant() switch
        {
            "registry"  => "Fix/Set-RegistryValue.ps1",
            "secedit"   => "Fix/Apply-SecurityPolicy.ps1",
            "auditpol"  => "Fix/Apply-AuditPolicy.ps1",
            "accesschk" => "Fix/Apply-UserRights.ps1",
            "service"   => "Fix/Set-ServiceStartType.ps1",
            "ipv6adapter" => "Fix/Configure-IPv6.ps1",
            _           => string.Empty
        };

        if (string.IsNullOrEmpty(scriptName)) return "(No fix script available for this method.)";

        string path = Path.Combine(scriptsRoot, scriptName);
        if (!File.Exists(path)) return $"Script not found: {path}";

        try { return File.ReadAllText(path); }
        catch { return $"Could not read script: {path}"; }
    }
}
