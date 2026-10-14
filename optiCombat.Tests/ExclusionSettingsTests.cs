using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ExclusionSettingsTests
{
    [Fact]
    public void IsFolderExcluded_requires_directory_boundary()
    {
        var settings = new ExclusionSettings
        {
            ExcludedFolders = { @"C:\Users\Alice" },
        };

        Assert.True(settings.IsFolderExcluded(@"C:\Users\Alice"));
        Assert.True(settings.IsFolderExcluded(@"C:\Users\Alice\Documents\file.txt"));
        Assert.False(settings.IsFolderExcluded(@"C:\Users\AliceBackup\file.txt"));
    }
}
