using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class RealTimeWatchPathsTests
{
    [Fact]
    public void GetWatchFolders_includes_quick_scan_targets_when_present()
    {
        var folders = RealTimeWatchPaths.GetWatchFolders();
        var quick = ScanTargets.QuickScanTargets();

        Assert.NotEmpty(folders);
        Assert.Contains(folders, f => quick.Any(q => string.Equals(q, f, StringComparison.OrdinalIgnoreCase)));
    }
}
