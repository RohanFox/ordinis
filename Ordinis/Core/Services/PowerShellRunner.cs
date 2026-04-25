using System.Diagnostics;
using System.IO;
using System.Text;
using Newtonsoft.Json;

namespace Ordinis.Core.Services;

public class PsResult
{
    public bool Success { get; set; }
    public string Output { get; set; } = string.Empty;
    public string Error  { get; set; } = string.Empty;
    public int ExitCode  { get; set; }

    public T? Deserialize<T>() => JsonConvert.DeserializeObject<T>(Output);
}

public class PowerShellRunner
{
    private readonly string _scriptsRoot;

    public PowerShellRunner()
    {
        _scriptsRoot = Path.Combine(AppContext.BaseDirectory, "Scripts");
    }

    public async Task<PsResult> RunScriptAsync(
        string scriptRelativePath,
        Dictionary<string, string>? parameters = null,
        string? remoteHost = null,
        string? remoteUser = null,
        string? remotePass = null,
        CancellationToken ct = default)
    {
        string scriptPath = Path.Combine(_scriptsRoot, scriptRelativePath);
        if (!File.Exists(scriptPath))
            return new PsResult { Error = $"Script not found: {scriptPath}" };

        var args = BuildArguments(scriptPath, parameters, remoteHost, remoteUser, remotePass);
        return await ExecuteAsync(args, ct);
    }

    public async Task<PsResult> RunInlineAsync(
        string script,
        string? remoteHost = null,
        string? remoteUser = null,
        string? remotePass = null,
        CancellationToken ct = default)
    {
        string actualScript = script;
        if (!string.IsNullOrEmpty(remoteHost))
        {
            actualScript =
                $"$pw = ConvertTo-SecureString '{EscapePs(remotePass ?? "")}' -AsPlainText -Force; " +
                $"$cred = New-Object PSCredential('{EscapePs(remoteUser ?? "")}', $pw); " +
                $"Invoke-Command -ComputerName '{EscapePs(remoteHost)}' -Credential $cred -ScriptBlock {{ {script} }}";
        }

        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(actualScript));
        string args = $"-NonInteractive -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}";
        return await ExecuteAsync(args, ct);
    }

    private static string BuildArguments(
        string scriptPath,
        Dictionary<string, string>? parameters,
        string? remoteHost,
        string? remoteUser,
        string? remotePass)
    {
        var sb = new StringBuilder();
        sb.Append("-NonInteractive -NoProfile -ExecutionPolicy Bypass ");

        if (!string.IsNullOrEmpty(remoteHost))
        {
            // Wrap in Invoke-Command for remote execution
            sb.Append("-Command \"");
            sb.Append($"$pw = ConvertTo-SecureString '{EscapePs(remotePass ?? "")}' -AsPlainText -Force; ");
            sb.Append($"$cred = New-Object PSCredential('{EscapePs(remoteUser ?? "")}', $pw); ");
            sb.Append($"Invoke-Command -ComputerName '{EscapePs(remoteHost)}' -Credential $cred ");
            sb.Append($"-FilePath '{EscapePs(scriptPath)}'");
            if (parameters?.Count > 0)
            {
                sb.Append(" -ArgumentList ");
                sb.Append(string.Join(",", parameters.Values.Select(v => $"'{EscapePs(v)}'")));
            }
            sb.Append("\"");
        }
        else
        {
            sb.Append($"-File \"{scriptPath}\"");
            if (parameters != null)
                foreach (var kv in parameters)
                    sb.Append($" -{kv.Key} \"{EscapePs(kv.Value)}\"");
        }

        return sb.ToString();
    }

    private static async Task<PsResult> ExecuteAsync(string arguments, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName               = "powershell.exe",
            Arguments              = arguments,
            UseShellExecute        = false,
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            CreateNoWindow         = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding  = Encoding.UTF8
        };

        using var process = new Process { StartInfo = psi };
        process.Start();

        var outputTask = process.StandardOutput.ReadToEndAsync(ct);
        var errorTask  = process.StandardError.ReadToEndAsync(ct);

        await process.WaitForExitAsync(ct);

        return new PsResult
        {
            Success  = process.ExitCode == 0,
            Output   = await outputTask,
            Error    = await errorTask,
            ExitCode = process.ExitCode
        };
    }

    // WinRM capability probe — returns true if the target responds to PS remoting.
    // Methods that can NOT run over WinRM: secedit, auditpol, accountpolicy (require local exec).
    public static readonly IReadOnlySet<string> RemoteUnsupportedMethods =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "secedit", "auditpol", "accountpolicy" };

    public async Task<(bool reachable, string error)> TestWinRmAsync(
        string host, string user, string pass,
        CancellationToken ct = default)
    {
        string script =
            $"$pw = ConvertTo-SecureString '{EscapePs(pass)}' -AsPlainText -Force; " +
            $"$cred = New-Object PSCredential('{EscapePs(user)}', $pw); " +
            $"Invoke-Command -ComputerName '{EscapePs(host)}' -Credential $cred " +
            $"-ScriptBlock {{ $env:COMPUTERNAME }} -ErrorAction Stop";
        var result = await RunInlineAsync(script, ct: ct);
        return (result.Success && !string.IsNullOrWhiteSpace(result.Output),
                result.Success ? string.Empty : result.Error);
    }

    private static string EscapePs(string value) => value.Replace("'", "''").Replace("\"", "`\"");
}
