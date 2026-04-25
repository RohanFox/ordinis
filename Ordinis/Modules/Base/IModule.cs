using Ordinis.Core.Models;

namespace Ordinis.Modules.Base;

public interface IModule
{
    FindingModule Module { get; }
    string DisplayName  { get; }
    string Description  { get; }

    Task<List<Finding>> GetFindingsAsync(ScanProfile profile, CancellationToken ct = default);
    Task AuditFindingAsync(Finding finding, ScanTarget target, CancellationToken ct = default);
}
