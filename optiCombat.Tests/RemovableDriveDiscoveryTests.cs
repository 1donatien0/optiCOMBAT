using optiCombat.Services;

namespace optiCombat.Tests;

public class RemovableDriveDiscoveryTests
{
    [Theory]
    [InlineData(0, 100_000_000_000L, true)]
    [InlineData(64, 32L * 1024 * 1024 * 1024, true)]
    [InlineData(64, 65L * 1024 * 1024 * 1024, false)]
    [InlineData(32, 40L * 1024 * 1024 * 1024, false)]
    [InlineData(64, 0L, true)]
    [InlineData(64, -1L, true)]
    public void IsWithinSizeLimit_respects_max_gb(int maxGb, long totalBytes, bool expected) =>
        Assert.Equal(expected, RemovableDriveDiscovery.IsWithinSizeLimit(totalBytes, maxGb));

    [Theory]
    [InlineData("E:", "E:\\")]
    [InlineData("F:\\", "F:\\")]
    [InlineData("  E:\\ ", "E:\\")]
    [InlineData("", null)]
    [InlineData("   ", null)]
    [InlineData("C", null)]
    [InlineData("not-a-drive", null)]
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

    [Fact]
    public void EnumerateAllFiles_stops_at_the_cap_and_skips_a_missing_root()
    {
        Assert.Empty(RemovableDriveDiscovery.EnumerateAllFiles(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")), 10));

        var dir = Path.Combine(Path.GetTempPath(), "opticombat_usb_cap_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "a.txt"), "a");
            File.WriteAllText(Path.Combine(dir, "b.txt"), "b");
            var nested = Path.Combine(dir, "sub");
            Directory.CreateDirectory(nested);
            File.WriteAllText(Path.Combine(nested, "c.txt"), "c");

            Assert.Single(RemovableDriveDiscovery.EnumerateAllFiles(dir, 1));
            Assert.Equal(3, RemovableDriveDiscovery.EnumerateAllFiles(dir, 10).Count());
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void EnumerateAllFiles_does_not_follow_a_reparse_point()
    {
        var dir = Path.Combine(Path.GetTempPath(), "opticombat_usb_reparse_" + Guid.NewGuid().ToString("N"));
        var outside = Path.Combine(Path.GetTempPath(), "opticombat_usb_out_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        Directory.CreateDirectory(outside);
        var hidden = Path.Combine(outside, "secret.exe");
        File.WriteAllText(hidden, "MZ");
        var link = Path.Combine(dir, "link");
        try
        {
            Directory.CreateSymbolicLink(link, outside);
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        try
        {
            var files = RemovableDriveDiscovery.EnumerateAllFiles(dir, 20).ToList();
            Assert.DoesNotContain(hidden, files);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
            try { Directory.Delete(outside, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void CollectRiskyFiles_honours_cap_cancellation_exclusion_and_skipped_folders()
    {
        var missing = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Assert.Empty(RemovableDriveDiscovery.CollectRiskyFiles(missing, 10, CancellationToken.None));
        Assert.Empty(RemovableDriveDiscovery.CollectRiskyFiles(Path.GetTempPath(), 0, CancellationToken.None));

        var dir = Path.Combine(Path.GetTempPath(), "opticombat_usb_risk2_" + Guid.NewGuid().ToString("N"));
        var recycle = Path.Combine(dir, "$RECYCLE.BIN");
        Directory.CreateDirectory(recycle);
        try
        {
            var exe = Path.Combine(dir, "a.exe");
            var second = Path.Combine(dir, "b.exe");
            var recycled = Path.Combine(recycle, "old.exe");
            File.WriteAllText(exe, "MZ");
            File.WriteAllText(second, "MZ");
            File.WriteAllText(recycled, "MZ");

            using var cts = new CancellationTokenSource();
            cts.Cancel();
            Assert.Empty(RemovableDriveDiscovery.CollectRiskyFiles(dir, 10, cts.Token));

            var expired = RemovableDriveDiscovery.CollectRiskyFiles(dir, 10, CancellationToken.None, TimeSpan.Zero);
            Assert.Empty(expired);

            var excl = new TestSupport.FixedExclusionsAccessor(new ExclusionSettings());
            excl.Current.ExcludedFilePaths.Add(exe);
            var kept = RemovableDriveDiscovery.CollectRiskyFiles(dir, 1, CancellationToken.None, exclusions: excl);
            Assert.Single(kept);
            Assert.DoesNotContain(exe, kept);
            Assert.DoesNotContain(recycled, kept);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Drive_helpers_reject_a_short_root_and_describe_a_real_volume()
    {
        Assert.False(RemovableDriveDiscovery.TryGetDriveInfo("C", out _));
        Assert.False(RemovableDriveDiscovery.TryGetDriveInfo(@"\\?\bad", out _));
        Assert.Equal("X", RemovableDriveDiscovery.GetDriveDisplayLabel("X"));

        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        if (system.Length >= 2)
        {
            var root = system[..2];
            var label = RemovableDriveDiscovery.GetDriveDisplayLabel(root + "\\");
            Assert.StartsWith(root, label, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(@"F:\RECYCLER\a.exe")]
    [InlineData(@"F:\RECYCLED\a.exe")]
    public void ShouldSkipUsbScanPath_skips_blank_and_legacy_recycle_names(string? path) =>
        Assert.True(RemovableDriveDiscovery.ShouldSkipUsbScanPath(path!));
}
