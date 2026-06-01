using Ordinis.Core.Models;
using Ordinis.Modules.Base;

namespace Ordinis.Core.Services;

public class AuditEngine
{
    private readonly List<IModule> _modules = new();
    public IReadOnlyList<IModule> Modules => _modules;

    public void RegisterModule(IModule module) => _modules.Add(module);

    public async Task RunAuditAsync(
        AuditSession session,
        IProgress<(int current, int total, string message)>? progress = null,
        CancellationToken ct = default)
    {
        session.IsRunning = true;
        using var logger = new DiagnosticLogger(session.Id.ToString("N")[..8]);
        session.DiagnosticLogPath = logger.LogPath;

        var pending = session.Findings.Where(f => f.Status == FindingStatus.Pending).ToList();
        int total   = pending.Count;
        int current = 0;

        foreach (var finding in pending)
        {
            ct.ThrowIfCancellationRequested();

            var module = _modules.FirstOrDefault(m => m.Handles.Contains(finding.Module));
            if (module is null)
            {
                finding.Status       = FindingStatus.Skipped;
                finding.ErrorMessage = "No module registered for this finding type.";
            }
            else
            {
                try
                {
                    await module.AuditFindingAsync(finding, session.Target, ct);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    finding.Status       = FindingStatus.Error;
                    finding.ErrorMessage = ex.Message;
                }
            }

            logger.Log(finding);
            current++;
            progress?.Report((current, total, $"[{finding.ModuleLabel}] {finding.Name}"));
        }

        session.CompletedAt = DateTime.Now;
        session.IsRunning   = false;
    }

    // Re-audits a single finding in place — used to verify that a fix actually took effect.
    // Resets prior audit state so the result reflects the current system, not the last scan.
    public async Task AuditSingleAsync(
        Finding finding,
        ScanTarget target,
        CancellationToken ct = default)
    {
        var module = _modules.FirstOrDefault(m => m.Handles.Contains(finding.Module));
        if (module is null)
        {
            finding.Status       = FindingStatus.Skipped;
            finding.ErrorMessage = "No module registered for this finding type.";
            return;
        }

        finding.IsUsingDefault = false;
        finding.ErrorMessage   = string.Empty;

        try
        {
            await module.AuditFindingAsync(finding, target, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            finding.Status       = FindingStatus.Error;
            finding.ErrorMessage = ex.Message;
        }
    }
}
