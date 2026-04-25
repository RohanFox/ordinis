using System.IO;
using System.Text;
using Ordinis.Core.Models;
using Newtonsoft.Json;

namespace Ordinis.Core.Services;

public class ReportGenerator
{
    public async Task<string> GenerateHtmlAsync(AuditSession session, string outputPath)
    {
        var sb = new StringBuilder();
        sb.AppendLine(BuildHtml(session));
        await File.WriteAllTextAsync(outputPath, sb.ToString(), Encoding.UTF8);
        return outputPath;
    }

    public async Task<string> GenerateJsonAsync(AuditSession session, string outputPath)
    {
        var report = new
        {
            session.Id,
            session.StartedAt,
            session.CompletedAt,
            Target         = session.Target.DisplayName,
            Profile        = session.ProfileName,
            Compliance     = session.CompliancePercent,
            session.PassCount,
            session.FailCount,
            session.ErrorCount,
            Findings       = session.Findings.Select(f => new
            {
                f.Id, f.Module, f.Category, f.Name, f.Severity,
                f.Status, f.ActualValue, f.ExpectedValue, f.BenchmarkRef, f.RemediationText
            })
        };
        await File.WriteAllTextAsync(outputPath,
            JsonConvert.SerializeObject(report, Formatting.Indented), Encoding.UTF8);
        return outputPath;
    }

    public async Task<string> GenerateCsvAsync(AuditSession session, string outputPath)
    {
        var lines = new List<string>
        {
            "ID,Module,Category,Name,Severity,Status,ActualValue,ExpectedValue,BenchmarkRef,RemediationText"
        };
        foreach (var f in session.Findings)
        {
            lines.Add(string.Join(",",
                CsvEscape(f.Id), CsvEscape(f.ModuleLabel), CsvEscape(f.Category),
                CsvEscape(f.Name), f.Severity, f.Status,
                CsvEscape(f.ActualValue), CsvEscape(f.ExpectedValue),
                CsvEscape(f.BenchmarkRef), CsvEscape(f.RemediationText)));
        }
        await File.WriteAllLinesAsync(outputPath, lines, Encoding.UTF8);
        return outputPath;
    }

    private static string CsvEscape(string value) =>
        $"\"{value.Replace("\"", "\"\"")}\"";

    private static string BuildHtml(AuditSession session)
    {
        string date    = session.StartedAt.ToString("yyyy-MM-dd HH:mm");
        double pct     = session.CompliancePercent;
        string color   = pct >= 80 ? "#22C55E" : pct >= 50 ? "#F59E0B" : "#EF4444";

        var rows = new StringBuilder();
        foreach (var f in session.Findings.OrderBy(f => f.Severity).ThenBy(f => f.Status))
        {
            string rowClass = f.Status == FindingStatus.Pass ? "pass" : f.Status == FindingStatus.Fail ? "fail" : "warn";
            string statusBadge = f.Status == FindingStatus.Pass
                ? "<span class=\"badge pass-badge\">PASS</span>"
                : f.Status == FindingStatus.Fail
                    ? "<span class=\"badge fail-badge\">FAIL</span>"
                    : "<span class=\"badge warn-badge\">ERROR</span>";

            rows.AppendLine($@"
            <tr class=""{rowClass}"">
                <td><code>{f.Id}</code></td>
                <td><span class=""module-tag"">{f.ModuleLabel}</span></td>
                <td>{EscHtml(f.Category)}</td>
                <td>{EscHtml(f.Name)}</td>
                <td><span class=""sev-{f.Severity.ToString().ToLower()}"">{f.Severity}</span></td>
                <td>{statusBadge}</td>
                <td><code>{EscHtml(f.ActualValue)}</code></td>
                <td><code>{EscHtml(f.ExpectedValue)}</code></td>
                <td>
                    <button class=""expand-btn"" onclick=""toggleRow(this)"">+</button>
                    <div class=""details"" style=""display:none"">
                        <p><strong>Rationale:</strong> {EscHtml(f.Rationale)}</p>
                        <p><strong>Remediation:</strong> {EscHtml(f.RemediationText)}</p>
                        <p><strong>Benchmark:</strong> {EscHtml(f.Benchmark)} {EscHtml(f.BenchmarkRef)}</p>
                    </div>
                </td>
            </tr>");
        }

        return $@"<!DOCTYPE html>
<html lang=""en"">
<head>
<meta charset=""UTF-8""/>
<meta name=""viewport"" content=""width=device-width, initial-scale=1.0""/>
<title>Ordinis Security Report — {EscHtml(session.Target.DisplayName)}</title>
<style>
  :root {{ --pass:#22C55E; --fail:#EF4444; --warn:#F59E0B; --bg:#0F1117; --surface:#1A1B2E; --card:#22243A; --text:#E5E7EB; --muted:#6B7280; }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif; padding:24px; }}
  h1 {{ font-size:28px; font-weight:700; margin-bottom:4px; }}
  .subtitle {{ color:var(--muted); font-size:14px; margin-bottom:24px; }}
  .cards {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:24px; }}
  .card {{ background:var(--card); border-radius:10px; padding:20px 28px; min-width:140px; }}
  .card .label {{ font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.05em; }}
  .card .value {{ font-size:32px; font-weight:700; margin-top:4px; }}
  .score-circle {{ width:100px; height:100px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:22px; font-weight:700; border:6px solid {color}; color:{color}; }}
  table {{ width:100%; border-collapse:collapse; background:var(--surface); border-radius:10px; overflow:hidden; }}
  th {{ background:var(--card); padding:10px 14px; text-align:left; font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); }}
  td {{ padding:10px 14px; border-bottom:1px solid #2A2A3E; font-size:13px; vertical-align:top; }}
  tr.pass td {{ border-left:3px solid var(--pass); }}
  tr.fail td {{ border-left:3px solid var(--fail); }}
  tr.warn td {{ border-left:3px solid var(--warn); }}
  .badge {{ padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; }}
  .pass-badge {{ background:#14532d; color:var(--pass); }}
  .fail-badge {{ background:#450a0a; color:var(--fail); }}
  .warn-badge {{ background:#451a03; color:var(--warn); }}
  .module-tag {{ background:#1e1b4b; color:#a5b4fc; padding:2px 7px; border-radius:4px; font-size:11px; }}
  .sev-critical {{ color:#d946ef; }} .sev-high {{ color:#EF4444; }} .sev-medium {{ color:#F59E0B; }} .sev-low {{ color:#3B82F6; }} .sev-info {{ color:var(--muted); }}
  code {{ font-family:'Cascadia Code','Consolas',monospace; font-size:12px; color:#a5b4fc; }}
  .expand-btn {{ background:none; border:none; color:var(--muted); cursor:pointer; font-size:16px; }}
  .details {{ margin-top:8px; color:var(--muted); font-size:12px; line-height:1.6; }}
  .footer {{ margin-top:32px; text-align:center; color:var(--muted); font-size:12px; }}
  input[type=text] {{ background:var(--card); border:1px solid #374151; color:var(--text); padding:7px 12px; border-radius:6px; width:280px; margin-bottom:16px; }}
</style>
</head>
<body>
<h1>Ordinis Security Report</h1>
<div class=""subtitle"">Target: {EscHtml(session.Target.DisplayName)} &nbsp;·&nbsp; Profile: {EscHtml(session.ProfileName)} &nbsp;·&nbsp; Generated: {date}</div>

<div class=""cards"">
  <div class=""card""><div class=""score-circle"">{pct:F0}%</div><div class=""label"" style=""margin-top:8px"">Compliance</div></div>
  <div class=""card""><div class=""value"" style=""color:var(--pass)"">{session.PassCount}</div><div class=""label"">Passed</div></div>
  <div class=""card""><div class=""value"" style=""color:var(--fail)"">{session.FailCount}</div><div class=""label"">Failed</div></div>
  <div class=""card""><div class=""value"" style=""color:#A855F7"">{session.CriticalFails}</div><div class=""label"">Critical</div></div>
  <div class=""card""><div class=""value"" style=""color:var(--fail)"">{session.HighFails}</div><div class=""label"">High</div></div>
  <div class=""card""><div class=""value"" style=""color:var(--warn)"">{session.MediumFails}</div><div class=""label"">Medium</div></div>
  <div class=""card""><div class=""value"" style=""color:#3B82F6"">{session.LowFails}</div><div class=""label"">Low</div></div>
  <div class=""card""><div class=""value"" style=""color:var(--muted)"">{session.ErrorCount}</div><div class=""label"">Errors</div></div>
</div>

<input type=""text"" id=""search"" placeholder=""Filter findings…"" oninput=""filterRows(this.value)""/>

<table id=""findings"">
<thead><tr>
  <th>ID</th><th>Module</th><th>Category</th><th>Name</th>
  <th>Severity</th><th>Status</th><th>Actual</th><th>Expected</th><th>Detail</th>
</tr></thead>
<tbody>
{rows}
</tbody>
</table>

<div class=""footer"">Ordinis v1.0 &nbsp;·&nbsp; Free &amp; Open Source (MIT) &nbsp;·&nbsp; github.com/RohanFox</div>

<script>
function toggleRow(btn) {{
  var d = btn.nextElementSibling;
  d.style.display = d.style.display === 'none' ? 'block' : 'none';
  btn.textContent = d.style.display === 'none' ? '+' : '−';
}}
function filterRows(q) {{
  q = q.toLowerCase();
  document.querySelectorAll('#findings tbody tr').forEach(function(r) {{
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  }});
}}
</script>
</body>
</html>";
    }

    private static string EscHtml(string s) =>
        s.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;").Replace("\"","&quot;");
}
