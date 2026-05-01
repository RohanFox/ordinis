using System.IO;
using System.Text;
using Ordinis.Core.Models;

namespace Ordinis.Core.Services;

public sealed class DiagnosticLogger : IDisposable
{
    private readonly StreamWriter _writer;
    private readonly object       _lock = new();
    private int _pass, _fail, _error, _skipped, _noData;

    public string LogPath { get; }

    public DiagnosticLogger(string sessionId)
    {
        string dir = AppContext.BaseDirectory;
        LogPath    = Path.Combine(dir, $"ordinis_debug_{sessionId}.log");
        _writer    = new StreamWriter(LogPath, append: false, Encoding.UTF8) { AutoFlush = true };
        var ver    = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        _writer.WriteLine($"# Ordinis v{ver} — audit diagnostic log");
        _writer.WriteLine($"# Session : {sessionId}");
        _writer.WriteLine($"# Started : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        _writer.WriteLine($"# Columns : time | id | method | param | actual | expected | op | status [| error]");
        _writer.WriteLine(new string('=', 160));
    }

    public void Log(Finding f)
    {
        string param = f.Method.ToLowerInvariant() switch
        {
            "registry"    => $"{f.CheckParams.GetValueOrDefault("RegistryPath")}\\{f.CheckParams.GetValueOrDefault("RegistryItem")}",
            "secedit" or "auditpol" or "accountpolicy" or "accesschk"
                          => f.CheckParams.GetValueOrDefault("MethodArgument", "") is { Length: > 0 } ma ? ma : f.Name,
            "service"     => f.CheckParams.GetValueOrDefault("ServiceName", ""),
            "ps_script"   => Truncate(f.CheckParams.GetValueOrDefault("Script", ""), 70),
            _             => f.Name
        };

        string actualDisplay = f.IsUsingDefault ? $"{f.ActualValue} [def]" : f.ActualValue;
        string line = $"{DateTime.Now:HH:mm:ss.fff} | {f.Id,-12} | {f.Method,-22} | {param,-70} | " +
                      $"act={actualDisplay,-26} | exp={f.ExpectedValue,-20} | {f.Operator,-6} | {f.Status}" +
                      (f.Status == FindingStatus.Error ? $" | {f.ErrorMessage}" : "");

        lock (_lock)
        {
            _writer.WriteLine(line);
            switch (f.Status)
            {
                case FindingStatus.Pass:    _pass++;    break;
                case FindingStatus.Fail:    _fail++;
                    if (f.ActualValue == "-NODATA-") _noData++; break;
                case FindingStatus.Error:   _error++;   break;
                case FindingStatus.Skipped: _skipped++; break;
            }
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            _writer.WriteLine(new string('=', 160));
            _writer.WriteLine($"# Completed : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            _writer.WriteLine($"# Summary   : PASS={_pass}  FAIL={_fail} (of which -NODATA-={_noData})  ERROR={_error}  SKIPPED={_skipped}");
        }
        _writer.Dispose();
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
