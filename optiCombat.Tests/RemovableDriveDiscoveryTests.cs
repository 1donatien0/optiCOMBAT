using optiCombat.Services;

namespace optiCombat.Tests;

public class RemovableDriveDiscoveryTests
{
    [Theory]
    [InlineData(0, 100_000_000_000L, true)]
    [InlineData(64, 32L * 1024 * 1024 * 1024, true)]
    [InlineData(64, 65L * 1024 * 1024 * 1024, false)]
    [InlineData(32, 40L * 1024 * 1024 * 1024, false)]
    public void IsWithinSizeLimit_respects_max_gb(int maxGb, long totalBytes, bool expected) =>
        Assert.Equal(expected, RemovableDriveDiscovery.IsWithinSizeLimit(totalBytes, maxGb));

    [Theory]
    [InlineData("E:", "E:\\")]
    [InlineData("F:\\", "F:\\")]
    [InlineData("", null)]
    public void NormalizeRootFromDriveName_maps_letters(string input, string? expected) =>
        Assert.Equal(expected, RemovableDriveDiscovery.NormalizeRootFromDriveName(input));

    [Fact]
    public void FindNewRemovableRoots_skips_known()
    {
        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"E:\" };
        var found = RemovableDriveDiscovery.FindNewRemovableRoots(known);
        Assert.DoesNotContain(@"E:\", found, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void CollectRiskyFiles_skips_non_executable_extensions()
    {
        var dir = Path.Combine(Path.GetTempPath(), "opticombat_usb_risky_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var doc = Path.Combine(dir, "readme.txt");
            var exe = Path.Combine(dir, "app.exe");
            File.WriteAllText(doc, "test");
            File.WriteAllText(exe, "MZ");

            var files = RemovableDriveDiscovery.CollectRiskyFiles(dir, 10, CancellationToken.None);
            Assert.Contains(exe, files);
            Assert.DoesNotContain(doc, files);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void ShouldSkipUsbScanPath_skips_recycle_and_system_folders()
    {
        Assert.True(RemovableDriveDiscovery.ShouldSkipUsbScanPath(@"F:\$RECYCLE.BIN\file.exe"));
        Assert.True(RemovableDriveDiscovery.ShouldSkipUsbScanPath(@"F:\System Volume Information\idx"));
        Assert.False(RemovableDriveDiscovery.ShouldSkipUsbScanPath(@"F:\tools\setup.exe"));
    }

    [Fact]
    public void EnumerateRiskyFiles_includes_non_executable_extensions()
    {
        var dir = Path.Combine(Path.GetTempPath(), "opticombat_usb_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var doc = Path.Combine(dir, "readme.txt");
            File.WriteAllText(doc, "test");
            var files = RemovableDriveDiscovery.EnumerateAllFiles(dir, 10).ToList();
            Assert.Contains(doc, files);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }
}
