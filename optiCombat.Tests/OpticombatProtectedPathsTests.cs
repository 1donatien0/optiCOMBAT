using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class OpticombatProtectedPathsTests
{
    [Fact]
    public void LocalAppData_optiCombat_tree_is_protected()
    {
        var root = OpticombatProtectedPaths.GetLocalAppDataRoot();
        var dbFile = Path.Combine(root, "clamav", "database", "daily.cvd");
        var updateStaging = Path.Combine(root, "Updates", "optiCombat.exe");

        Assert.True(OpticombatProtectedPaths.IsUnderProtectedPath(root));
        Assert.True(OpticombatProtectedPaths.IsUnderProtectedPath(dbFile));
        Assert.True(OpticombatProtectedPaths.IsUnderProtectedPath(updateStaging));
        Assert.True(OpticombatProtectedPaths.IsMandatoryExcludedFolder(root));
    }

    [Fact]
    public void Process_install_directory_is_protected()
    {
        var root = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var exe = Path.Combine(root, "optiCombat.exe");

        Assert.True(OpticombatProtectedPaths.IsUnderProtectedPath(exe));
        Assert.Contains(OpticombatProtectedPaths.GetProtectedRoots(),
            r => string.Equals(r, Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ClamScan_exclude_patterns_are_nonempty()
    {
        var patterns = AppInstallPaths.GetClamScanExcludePatterns().ToList();
        Assert.NotEmpty(patterns);
        Assert.All(patterns, p => Assert.StartsWith("^", p));
    }

    [Fact]
    public void Mandatory_folder_cannot_be_removed_from_exclusions()
    {
        var settings = new ExclusionSettings();
        var protectedRoot = OpticombatProtectedPaths.GetLocalAppDataRoot();
        settings.ExcludedFolders.Add(protectedRoot);

        Assert.False(settings.RemoveFolder(protectedRoot));
        Assert.Contains(settings.ExcludedFolders,
            f => string.Equals(f.TrimEnd('\\'), protectedRoot.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase));
    }
}
