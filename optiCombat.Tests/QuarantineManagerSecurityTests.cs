using optiCombat.Models;
using optiCombat.Services;
using System.Text;
using System.Text.Json;

namespace optiCombat.Tests;

public sealed class QuarantineManagerSecurityTests
{
    [Theory]
    [InlineData("ProgramData")]
    public void IsSensitivePath_blocks_extended_folders(string folder)
    {
        var basePath = folder switch
        {
            "ProgramData" => Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            _ => throw new ArgumentOutOfRangeException(nameof(folder)),
        };

        if (string.IsNullOrWhiteSpace(basePath))
            return;

        var target = Path.Combine(basePath, "opticombat_test_restore.exe");
        Assert.True(QuarantineManager.IsSensitivePath(target));
    }

    [Theory]
    [InlineData("System32")]
    [InlineData("Windows")]
    public void IsSensitivePath_blocks_critical_folders(string folder)
    {
        var basePath = folder switch
        {
            "System32" => Environment.GetFolderPath(Environment.SpecialFolder.System),
            "Windows" => Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            _ => throw new ArgumentOutOfRangeException(nameof(folder)),
        };

        if (string.IsNullOrWhiteSpace(basePath))
            return;

        var target = Path.Combine(basePath, "opticombat_test_restore.exe");
        Assert.True(QuarantineManager.IsSensitivePath(target));
    }

    [Fact]
    public void IsSensitivePath_allows_user_profile_path()
    {
        var user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var target = Path.Combine(user, "Downloads", "sample.exe");
        Assert.False(QuarantineManager.IsSensitivePath(target));
    }

    [Fact]
    public void IsSensitivePath_does_not_block_sibling_with_shared_prefix()
    {
        // Régression : « C:\WindowsApps\… » ne doit PAS être considéré comme
        // étant sous « C:\Windows » (comparaison par segment de chemin, pas par préfixe brut).
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(windows))
            return;

        var sibling = Path.Combine(Path.TrimEndingDirectorySeparator(windows) + "Apps", "sample.exe");
        Assert.False(QuarantineManager.IsSensitivePath(sibling));
    }

    [Fact]
    public void IsSensitivePath_blocks_exact_system_root()
    {
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        if (string.IsNullOrWhiteSpace(system))
            return;

        // L'égalité exacte avec un dossier interdit doit être bloquée.
        Assert.True(QuarantineManager.IsSensitivePath(system));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void IsSensitivePath_returns_false_for_blank(string path)
    {
        // La garde évite que Path.GetFullPath ne lève sur une chaîne vide.
        Assert.False(QuarantineManager.IsSensitivePath(path));
    }

    [Fact]
    public void LoadManifest_rejects_tampered_hmac()
    {
        var root = Path.Combine(Path.GetTempPath(), "opticombat_ut_hmac_" + Guid.NewGuid().ToString("N"));
        var qDir = Path.Combine(root, "q");
        var sample = Path.Combine(root, "sample.bin");
        Directory.CreateDirectory(root);

        try
        {
            File.WriteAllBytes(sample, [0xAB, 0xCD]);
            var qm = new QuarantineManager(qDir);
            Assert.True(qm.Quarantine(new ThreatInfo
            {
                FilePath = sample,
                VirusName = "Test",
                FileSize = 2,
                DetectedAt = DateTime.UtcNow,
            }));

            var manifestPath = Path.Combine(qDir, "manifest.json");
            var text = File.ReadAllText(manifestPath);
            text = text.Replace("\"Hmac\": \"", "\"Hmac\": \"ZZZZ");
            File.WriteAllText(manifestPath, text);

            var reloaded = new QuarantineManager(qDir);
            Assert.Empty(reloaded.GetEntries());
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void LoadManifest_rejects_unsigned_v2_with_entries()
    {
        var root = Path.Combine(Path.GetTempPath(), "opticombat_ut_unsigned_" + Guid.NewGuid().ToString("N"));
        var qDir = Path.Combine(root, "q");
        Directory.CreateDirectory(qDir);

        try
        {
            var doc = new QuarantineDocument
            {
                Version = 2,
                Hmac = string.Empty,
                Entries =
                [
                    new QuarantineEntry
                    {
                        Id = "deadbeef",
                        OriginalPath = @"C:\Users\test\evil.exe",
                        QuarantinePath = Path.Combine(qDir, "deadbeef.quar"),
                        VirusName = "Fake",
                        QuarantinedAt = DateTime.UtcNow,
                    }
                ]
            };
            File.WriteAllText(
                Path.Combine(qDir, "manifest.json"),
                JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true }));

            var qm = new QuarantineManager(qDir);
            Assert.Empty(qm.GetEntries());
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void IsResolvedPathUnderDirectory_allows_file_inside_folder()
    {
        var root = Path.Combine(Path.GetTempPath(), "opticombat_ut_scope_" + Guid.NewGuid().ToString("N"));
        var inside = Path.Combine(root, "subdir", "file.bin");
        Assert.True(QuarantineManager.IsResolvedPathUnderDirectory(inside, Path.Combine(root, "subdir")));
    }

    [Fact]
    public void IsResolvedPathUnderDirectory_blocks_parent_escape()
    {
        var root = Path.Combine(Path.GetTempPath(), "opticombat_ut_scope2_" + Guid.NewGuid().ToString("N"));
        var escaped = Path.GetFullPath(Path.Combine(root, "..", "outside.bin"));
        Assert.False(QuarantineManager.IsResolvedPathUnderDirectory(escaped, root));
    }

    [Fact]
    public void IsResolvedPathUnderDirectory_blocks_prefix_folder_trick()
    {
        var root = Path.Combine(Path.GetTempPath(), "opticombat_restore");
        var sibling = Path.Combine(Path.GetTempPath(), "opticombat_restore-evil", "file.bin");
        Assert.False(QuarantineManager.IsResolvedPathUnderDirectory(sibling, root));
    }

    [Fact]
    public void RestoreTo_refuses_path_outside_destination_folder()
    {
        var root = Path.Combine(Path.GetTempPath(), "opticombat_ut_restoreto_" + Guid.NewGuid().ToString("N"));
        var qDir = Path.Combine(root, "q");
        var destDir = Path.Combine(root, "dest");
        var sample = Path.Combine(root, "sample.bin");
        Directory.CreateDirectory(root);

        try
        {
            File.WriteAllBytes(sample, [1, 2, 3]);
            var qm = new QuarantineManager(qDir);
            Assert.True(qm.Quarantine(new ThreatInfo
            {
                FilePath = sample,
                VirusName = "Test",
                FileSize = 3,
                DetectedAt = DateTime.UtcNow,
            }));

            var entry = qm.GetEntries()[0];
            entry.OriginalPath = "..";

            Directory.CreateDirectory(destDir);
            Assert.False(qm.RestoreTo(entry.Id, destDir));
            Assert.Single(qm.GetEntries());
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void Restore_refuses_system32_destination()
    {
        var root = Path.Combine(Path.GetTempPath(), "opticombat_ut_restore_" + Guid.NewGuid().ToString("N"));
        var qDir = Path.Combine(root, "q");
        var sample = Path.Combine(root, "sample.bin");
        Directory.CreateDirectory(root);

        try
        {
            File.WriteAllBytes(sample, [1, 2, 3]);
            var qm = new QuarantineManager(qDir);
            var threat = new ThreatInfo
            {
                FilePath = sample,
                VirusName = "Test",
                FileSize = 3,
                DetectedAt = DateTime.UtcNow,
            };
            Assert.True(qm.Quarantine(threat));
            var id = qm.GetEntries()[0].Id;

            var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.System);
            if (string.IsNullOrWhiteSpace(systemRoot))
                return;

            var entry = qm.GetEntries()[0];
            var method = typeof(QuarantineManager).GetMethod(
                "RestoreToPath",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance,
                binder: null,
                types: [typeof(QuarantineEntry), typeof(string), typeof(bool)],
                modifiers: null);
            Assert.NotNull(method);

            var dest = Path.Combine(systemRoot, "opticombat_restore_test.bin");
            var ok = (bool)method.Invoke(qm, [entry, dest, false])!;
            Assert.False(ok);
            Assert.Single(qm.GetEntries());
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }
}
