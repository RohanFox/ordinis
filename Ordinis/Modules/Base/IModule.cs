using Ordinis.Core.Models;

namespace Ordinis.Modules.Base;

public interface IModule
{
    FindingModule Module { get; }
    string DisplayName  { get; }
    string Description  { get; }

    // Every FindingModule this module audits. Defaults to its own Module, but a module may
    // emit findings under a finer-grained label than it registers under — NetworkModule also
    // owns IPv6, AdModule also owns Kerberos. The audit engine dispatches on this set, so
    // those findings are no longer left without a handler (silently Skipped).
    IReadOnlySet<FindingModule> Handles => new HashSet<FindingModule> { Module };

    Task<List<Finding>> GetFindingsAsync(ScanProfile profile, CancellationToken ct = default);
    Task AuditFindingAsync(Finding finding, ScanTarget target, CancellationToken ct = default);
}
