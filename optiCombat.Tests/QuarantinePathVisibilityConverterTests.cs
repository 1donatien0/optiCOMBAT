using optiCombat.Converters;
using optiCombat.Models;
using optiCombat.Services;
using System.Globalization;
using System.Windows;

namespace optiCombat.Tests;

public sealed class QuarantinePathVisibilityConverterTests
{
    [Fact]
    public void Convert_visible_when_path_is_quarantined()
    {
        var root = Path.Combine(Path.GetTempPath(), "opticombat_qvis_" + Guid.NewGuid().ToString("N"));
        var qDir = Path.Combine(root, "quarantine");
        var sample = Path.Combine(root, "file.bin");
        Directory.CreateDirectory(root);
        File.WriteAllBytes(sample, [1, 2, 3]);

        try
        {
            var qm = new QuarantineManager(qDir);
            qm.Quarantine(new ThreatInfo { FilePath = sample, VirusName = "Test" }, Guid.NewGuid());

            var converter = new QuarantinePathVisibilityConverter { Quarantine = qm };
            var result = converter.Convert(sample, typeof(Visibility), parameter: null!, CultureInfo.InvariantCulture);

            Assert.Equal(Visibility.Visible, result);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void Convert_collapsed_for_NotQuarantined_when_path_is_quarantined()
    {
        var root = Path.Combine(Path.GetTempPath(), "opticombat_qvis2_" + Guid.NewGuid().ToString("N"));
        var qDir = Path.Combine(root, "quarantine");
        var sample = Path.Combine(root, "file.bin");
        Directory.CreateDirectory(root);
        File.WriteAllBytes(sample, [1]);

        try
        {
            var qm = new QuarantineManager(qDir);
            qm.Quarantine(new ThreatInfo { FilePath = sample, VirusName = "Test" }, Guid.NewGuid());

            var converter = new QuarantinePathVisibilityConverter { Quarantine = qm };
            var result = converter.Convert(sample, typeof(Visibility), "NotQuarantined", CultureInfo.InvariantCulture);

            Assert.Equal(Visibility.Collapsed, result);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void Convert_collapsed_when_quarantine_not_bound()
    {
        var converter = new QuarantinePathVisibilityConverter();
        var result = converter.Convert(@"C:\temp\file.exe", typeof(Visibility), parameter: null!, CultureInfo.InvariantCulture);

        Assert.Equal(Visibility.Collapsed, result);
    }

    [Fact]
    public void Convert_collapsed_for_NotQuarantined_when_quarantine_not_bound()
    {
        var converter = new QuarantinePathVisibilityConverter();
        var result = converter.Convert(@"C:\temp\file.exe", typeof(Visibility), "NotQuarantined", CultureInfo.InvariantCulture);

        Assert.Equal(Visibility.Collapsed, result);
    }

    [Fact]
    public void RefreshCache_updates_visibility_after_quarantine_changes()
    {
        var root = Path.Combine(Path.GetTempPath(), "opticombat_qvis3_" + Guid.NewGuid().ToString("N"));
        var qDir = Path.Combine(root, "quarantine");
        var sample = Path.Combine(root, "file.bin");
        Directory.CreateDirectory(root);
        File.WriteAllBytes(sample, [1]);

        try
        {
            var qm = new QuarantineManager(qDir);
            var converter = new QuarantinePathVisibilityConverter { Quarantine = qm };

            Assert.Equal(Visibility.Collapsed, converter.Convert(sample, typeof(Visibility), parameter: null!, CultureInfo.InvariantCulture));

            qm.Quarantine(new ThreatInfo { FilePath = sample, VirusName = "Test" }, Guid.NewGuid());
            converter.RefreshCache();

            Assert.Equal(Visibility.Visible, converter.Convert(sample, typeof(Visibility), parameter: null!, CultureInfo.InvariantCulture));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }
}
