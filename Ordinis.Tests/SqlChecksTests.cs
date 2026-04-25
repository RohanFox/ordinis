using Ordinis.Core.Models;
using Ordinis.Modules.MSSQL;

namespace Ordinis.Tests;

public class SqlChecksTests
{
    private readonly List<Finding> _checks = SqlChecks.GetAll();

    [Fact]
    public void Returns_expected_check_count()
        => Assert.Equal(22, _checks.Count);   // update if checks are added

    [Fact]
    public void No_duplicate_ids()
    {
        var ids = _checks.Select(f => f.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
    }

    [Fact]
    public void All_checks_have_query()
        => Assert.All(_checks, f => Assert.False(string.IsNullOrWhiteSpace(f.CheckParams["Query"])));

    [Fact]
    public void All_checks_are_MSSQL_module()
        => Assert.All(_checks, f => Assert.Equal(FindingModule.MSSQL, f.Module));

    [Fact]
    public void All_checks_not_safe_to_auto_fix()
        => Assert.All(_checks, f => Assert.False(f.IsSafeToAutoFix));

    [Fact]
    public void SA_disabled_check_is_critical()
    {
        var check = _checks.Single(f => f.Id == "SQL-2.1");
        Assert.Equal(FindingSeverity.Critical, check.Severity);
    }

    [Fact]
    public void SA_renamed_check_uses_not_equal_operator()
    {
        var check = _checks.Single(f => f.Id == "SQL-2.2");
        Assert.Equal("!=", check.Operator);
        Assert.Equal("sa", check.ExpectedValue);
    }

    [Fact]
    public void Audit_count_check_uses_gte_operator()
    {
        var check = _checks.Single(f => f.Id == "SQL-4.2");
        Assert.Equal(">=", check.Operator);
    }

    [Fact]
    public void Agent_account_check_uses_not_equal_operator()
    {
        var check = _checks.Single(f => f.Id == "SQL-6.2");
        Assert.Equal("!=", check.Operator);
        Assert.Equal("LocalSystem", check.ExpectedValue);
    }
}
