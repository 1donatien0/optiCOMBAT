using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class WindowsDefenderExclusionServiceTests
{
    [Fact]
    public void CollectExclusionPaths_includes_install_and_localappdata()
    {
        var paths = WindowsDefenderExclusionService.CollectExclusionPaths();

        Assert.NotEmpty(paths);
        Assert.Contains(paths, p =>
            p.Equals(OpticombatProtectedPaths.GetLocalAppDataRoot(), StringComparison.OrdinalIgnoreCase));
        Assert.Contains(paths, p =>
            p.Equals(Path.GetFullPath(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)),
                StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void IsWindowsDefenderPresent_matches_mpcmdrun_on_windows()
    {
        var mpcmd = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Windows Defender",
            "MpCmdRun.exe");

        Assert.Equal(File.Exists(mpcmd), WindowsDefenderExclusionService.IsWindowsDefenderPresent());
    }
}
