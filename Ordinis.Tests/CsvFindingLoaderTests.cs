using System.IO;
using Ordinis.Core.Models;
using Ordinis.Core.Services;

namespace Ordinis.Tests;

// Exercises the two CSV schemas the loader must support side by side: the upstream
// HardeningKitty lists (no Module column) and the curated Ordinis lists (Module + guidance
// columns). A temp directory is used as the data root so no real finding lists are touched.
public class CsvFindingLoaderTests : IDisposable
{
    private readonly string _dir;
    private readonly CsvFindingLoader _loader;

    public CsvFindingLoaderTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "ordinis_csv_tests_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_dir);
        _loader = new CsvFindingLoader(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private string Write(string name, string content)
    {
        File.WriteAllText(Path.Combine(_dir, name), content);
        return name;
    }

    // ── Standard HardeningKitty schema (no Module column) ─────────────────────────
    [Fact]
    public void Standard_list_keeps_WIN_prefix_and_Windows_module()
    {
        var file = Write("finding_list_cis_demo_machine.csv",
            "ID,Category,Name,Method,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity\n" +
            "1.1,Account,Demo,registry,HKLM:\\SOFTWARE\\Demo,Flag,0,1,=,High\n");

        var f = _loader.LoadFromFile(file).Single();

        Assert.Equal("WIN-1.1", f.Id);
        Assert.Equal(FindingModule.Windows, f.Module);
        Assert.Equal("HKLM:\\SOFTWARE\\Demo", f.CheckParams["RegistryPath"]);
        Assert.Equal("Flag", f.CheckParams["RegistryItem"]);
        Assert.Equal("1", f.ExpectedValue);
    }

    // ── ASR regression: MethodArgument must be populated for mppreferenceasr ───────
    [Fact]
    public void Asr_method_populates_MethodArgument()
    {
        var file = Write("finding_list_cis_asr_machine.csv",
            "ID,Category,Name,Method,MethodArgument,DefaultValue,RecommendedValue,Operator,Severity\n" +
            "18.1,Defender,Block credential stealing,MpPreferenceAsr,9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2,0,1,=,High\n");

        var f = _loader.LoadFromFile(file).Single();

        Assert.Equal("mppreferenceasr", f.Method.ToLowerInvariant());
        Assert.Equal("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", f.CheckParams["MethodArgument"]);
    }

    // ── Curated Ordinis schema (Module + Rationale + Remediation + RequiresRestart) ─
    [Fact]
    public void Curated_list_keeps_native_id_module_and_guidance()
    {
        var file = Write("finding_list_ordinis_demo_machine.csv",
            "ID,Module,Category,Name,Description,Rationale,Method,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity,RequiresRestart,Remediation\n" +
            "NTLM-2.2,NTLM,Credential Protection,RunAsPPL,desc,rationale text,registry,HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa,RunAsPPL,0,1,=,Critical,true,Set RunAsPPL to 1\n");

        var f = _loader.LoadFromFile(file).Single();

        Assert.Equal("NTLM-2.2", f.Id);                 // native id — not WIN-prefixed
        Assert.Equal(FindingModule.NTLM, f.Module);     // dispatched under its own module
        Assert.Equal("rationale text", f.Rationale);
        Assert.Equal("Set RunAsPPL to 1", f.RemediationText);
        Assert.True(f.RequiresRestart);
        Assert.Equal("RunAsPPL", f.CheckParams["RegistryItem"]);
    }

    [Fact]
    public void Curated_severity_critical_is_mapped()
    {
        var file = Write("finding_list_ordinis_sev_machine.csv",
            "ID,Module,Category,Name,Method,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity\n" +
            "NTLM-2.1,NTLM,Cred,WDigest,registry,HKLM:\\SYSTEM\\X,UseLogonCredential,0,0,=,Critical\n");

        var f = _loader.LoadFromFile(file).Single();
        Assert.Equal(FindingSeverity.Critical, f.Severity);
    }
}
