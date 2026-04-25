using System.IO;
using Ordinis.Core.Models;
using Ordinis.Core.Services;

namespace Ordinis.Tests;

public class ReportGeneratorTests : IDisposable
{
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), $"OrdiniTests_{Guid.NewGuid():N}");
    private readonly ReportGenerator _gen = new();
    private readonly AuditSession _session;

    public ReportGeneratorTests()
    {
        Directory.CreateDirectory(_tempDir);
        _session = new AuditSession
        {
            ProfileName = "CIS Level 1",
            Target      = new ScanTarget { Type = TargetType.Local }
        };
        _session.Findings.Add(new Finding
        {
            Id = "WIN-1.1", Name = "Test finding", Module = FindingModule.Windows,
            Status = FindingStatus.Pass, Severity = FindingSeverity.High,
            ActualValue = "1", ExpectedValue = "1", BenchmarkRef = "1.1"
        });
        _session.Findings.Add(new Finding
        {
            Id = "WIN-1.2", Name = "Failed finding", Module = FindingModule.Windows,
            Status = FindingStatus.Fail, Severity = FindingSeverity.Critical,
            ActualValue = "0", ExpectedValue = "1",
            RemediationText = "Set the value to 1."
        });
    }

    [Fact]
    public async Task GenerateHtml_creates_file()
    {
        string path = Path.Combine(_tempDir, "report.html");
        await _gen.GenerateHtmlAsync(_session, path);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task GenerateHtml_contains_finding_names()
    {
        string path = Path.Combine(_tempDir, "report2.html");
        await _gen.GenerateHtmlAsync(_session, path);
        string html = await File.ReadAllTextAsync(path);
        Assert.Contains("Test finding", html);
        Assert.Contains("Failed finding", html);
    }

    [Fact]
    public async Task GenerateHtml_escapes_html_chars()
    {
        _session.Findings[0].Name = "Finding <b>bold</b> & more";
        string path = Path.Combine(_tempDir, "report3.html");
        await _gen.GenerateHtmlAsync(_session, path);
        string html = await File.ReadAllTextAsync(path);
        Assert.Contains("&lt;b&gt;", html);
        Assert.Contains("&amp;", html);
        Assert.DoesNotContain("<b>bold</b>", html);
    }

    [Fact]
    public async Task GenerateJson_creates_valid_json()
    {
        string path = Path.Combine(_tempDir, "report.json");
        await _gen.GenerateJsonAsync(_session, path);
        string json = await File.ReadAllTextAsync(path);
        // Must be valid JSON with expected fields
        var obj = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>(json);
        Assert.NotNull(obj);
        Assert.Equal("CIS Level 1", (string)obj!.Profile);
    }

    [Fact]
    public async Task GenerateCsv_creates_file_with_header()
    {
        string path = Path.Combine(_tempDir, "report.csv");
        await _gen.GenerateCsvAsync(_session, path);
        string[] lines = await File.ReadAllLinesAsync(path);
        Assert.StartsWith("ID,Module", lines[0]);
        Assert.Equal(3, lines.Length); // header + 2 findings
    }

    public void Dispose() => Directory.Delete(_tempDir, recursive: true);
}
