using System.Text.Json;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

/// <summary>
/// Chemins d'échec de la quarantaine : un fichier utilisateur ne doit jamais être perdu
/// (ni original ni blob), et un manifeste rejeté doit rester récupérable.
/// </summary>
[Collection("OpticombatPrefs")]
public sealed class QuarantineManagerRobustnessTests : IDisposable
{
    private readonly string _root;
    private readonly string _qDir;

    public QuarantineManagerRobustnessTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "opticombat_qrob_" + Guid.NewGuid().ToString("N"));
        _qDir = Path.Combine(_root, "q");
        Directory.CreateDirectory(_root);
        OpticombatDataRoots.TestRootOverride = Path.Combine(_root, "data");
    }

    public void Dispose()
    {
        OpticombatDataRoots.TestRootOverride = TestDataRoot.Session;
        try { Directory.Delete(_root, recursive: true); } catch { /* best effort */ }
    }

    private string Sample(string name, byte[] content)
    {
        var dir = Path.Combine(_root, "samples");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, name);
        File.WriteAllBytes(path, content);
        return path;
    }

    private static ThreatInfo Threat(string path) => new()
    {
        FilePath = path,
        VirusName = "UnitTest.Robustness",
        FileSize = new FileInfo(path).Length,
        DetectedAt = DateTime.UtcNow,
    };

    private static byte[] Xor(byte[] data) => data.Select(b => (byte)(b ^ 0x5A)).ToArray();

    private static bool HasV2Header(string path)
    {
        var head = File.ReadAllBytes(path).Take(4).ToArray();
        return head.SequenceEqual("OPTQ"u8.ToArray());
    }

    private QuarantineEntry QuarantineOne(QuarantineManager qm, byte[] payload, string name = "s.bin")
    {
        var path = Sample(name, payload);
        Assert.True(qm.Quarantine(Threat(path)));
        return qm.GetEntries().Single(e => e.OriginalPath == path);
    }

    [Fact]
    public void Manifest_write_failure_keeps_the_original_file_and_removes_the_blob()
    {
        var qm = new QuarantineManager(_qDir);
        var payload = "contenu à protéger"u8.ToArray();
        var sample = Sample("keep.bin", payload);
        // Le manifeste s'écrit via « manifest.json.tmp » : un dossier à ce nom fait échouer l'écriture.
        Directory.CreateDirectory(Path.Combine(_qDir, "manifest.json.tmp"));

        Assert.False(qm.Quarantine(Threat(sample)));

        Assert.True(File.Exists(sample));
        Assert.Equal(payload, File.ReadAllBytes(sample));
        Assert.Empty(qm.GetEntries());
        Assert.Empty(Directory.GetFiles(_qDir, "*.quar"));
    }

    [Fact]
    public void Original_that_cannot_be_deleted_rolls_back_entry_and_blob()
    {
        var qm = new QuarantineManager(_qDir);
        var payload = new byte[] { 9, 8, 7 };
        var sample = Sample("locked.bin", payload);
        var dir = Path.GetDirectoryName(sample)!;

        FileStream? lockHandle = null;
        UnixFileMode? previousMode = null;
        if (OperatingSystem.IsWindows())
            lockHandle = new FileStream(sample, FileMode.Open, FileAccess.Read, FileShare.Read);
        else
        {
            previousMode = File.GetUnixFileMode(dir);
            File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserExecute);
        }

        bool ok;
        try
        {
            ok = qm.Quarantine(Threat(sample));
        }
        finally
        {
            lockHandle?.Dispose();
            if (previousMode is { } mode && !OperatingSystem.IsWindows())
                File.SetUnixFileMode(dir, mode);
        }

        if (ok)
            return; // compte root sous Linux : les droits du dossier ne bloquent pas la suppression

        Assert.True(File.Exists(sample));
        Assert.Empty(qm.GetEntries());
        Assert.Empty(Directory.GetFiles(_qDir, "*.quar"));
        // Le retrait de l'entrée est persisté : un rechargement ne la ressuscite pas.
        Assert.Empty(new QuarantineManager(_qDir).GetEntries());
    }

    [Fact]
    public void Missing_file_or_folder_is_not_quarantined()
    {
        var qm = new QuarantineManager(_qDir);
        Assert.False(qm.Quarantine(new ThreatInfo { FilePath = Path.Combine(_root, "absent.bin") }));
        Assert.False(qm.Quarantine(new ThreatInfo { FilePath = Path.Combine(_root, "no-dir", "x.bin") }));
        Assert.Equal(0, qm.Count);
    }

    [Fact]
    public void Tampered_manifest_is_preserved_before_new_entries_overwrite_it()
    {
        var qm = new QuarantineManager(_qDir);
        QuarantineOne(qm, [1, 2, 3], "first.bin");
        var manifest = Path.Combine(_qDir, "manifest.json");
        var original = File.ReadAllText(manifest);
        var tampered = original.Replace("UnitTest.Robustness", "Forged.Name", StringComparison.Ordinal);
        File.WriteAllText(manifest, tampered);
        File.Delete(manifest + ".bak");

        var reloaded = new QuarantineManager(_qDir);
        Assert.Empty(reloaded.GetEntries());

        // Deux enregistrements écrasaient autrefois manifest.json puis manifest.json.bak.
        QuarantineOne(reloaded, [4], "second.bin");
        QuarantineOne(reloaded, [5], "third.bin");

        var kept = Directory.GetFiles(_qDir, "manifest.json.rejected-*");
        var copy = Assert.Single(kept);
        Assert.Equal(tampered, File.ReadAllText(copy));
    }

    [Fact]
    public void Unreadable_master_key_is_set_aside_and_previous_manifest_kept()
    {
        var qm = new QuarantineManager(_qDir);
        QuarantineOne(qm, [1, 2, 3, 4], "k.bin");
        var keyPath = Path.Combine(_qDir, ".key");
        File.SetAttributes(keyPath, FileAttributes.Normal);
        File.WriteAllBytes(keyPath, [0xDE, 0xAD, 0xBE, 0xEF]);

        var reloaded = new QuarantineManager(_qDir);

        Assert.Single(Directory.GetFiles(_qDir, ".key.unreadable-*"));
        Assert.True(File.Exists(keyPath));
        // Nouvelle clé : le manifeste signé avec l'ancienne est rejeté, mais conservé.
        Assert.Empty(reloaded.GetEntries());
        Assert.NotEmpty(Directory.GetFiles(_qDir, "manifest.json*.rejected-*"));
        // La nouvelle clé fonctionne.
        var entry = QuarantineOne(reloaded, [7, 7], "after.bin");
        Assert.True(reloaded.Restore(entry.Id));
    }

    [Fact]
    public async Task Legacy_xor_blob_is_migrated_to_authenticated_format_and_restorable()
    {
        var payload = "ancien format XOR"u8.ToArray();
        var qm = new QuarantineManager(_qDir);
        var entry = QuarantineOne(qm, payload, "legacy.bin");
        File.WriteAllBytes(entry.QuarantinePath, Xor(payload));

        var reloaded = new QuarantineManager(_qDir);
        await Eventually.TrueAsync(() => HasV2Header(entry.QuarantinePath));

        Assert.True(reloaded.Restore(entry.Id));
        Assert.Equal(payload, File.ReadAllBytes(entry.OriginalPath));
    }

    [Fact]
    public async Task Legacy_blob_with_wrong_hash_is_left_untouched_and_never_restored()
    {
        var qm = new QuarantineManager(_qDir);
        var entry = QuarantineOne(qm, [1, 2, 3], "bad.bin");
        var forged = Xor([6, 6, 6]);
        File.WriteAllBytes(entry.QuarantinePath, forged);

        var reloaded = new QuarantineManager(_qDir);
        await Task.Delay(300); // laisse passer l'alignement en arrière-plan

        Assert.Equal(forged, File.ReadAllBytes(entry.QuarantinePath));
        Assert.False(reloaded.Restore(entry.Id));
        Assert.False(File.Exists(entry.OriginalPath));
        Assert.Single(reloaded.GetEntries());
    }

    [Fact]
    public void Blob_with_unknown_format_version_is_refused()
    {
        var qm = new QuarantineManager(_qDir);
        var entry = QuarantineOne(qm, new byte[40], "ver.bin");
        var blob = File.ReadAllBytes(entry.QuarantinePath);
        blob[4] = 0x07;
        File.WriteAllBytes(entry.QuarantinePath, blob);

        Assert.False(qm.Restore(entry.Id));
        Assert.True(File.Exists(entry.QuarantinePath));
    }

    [Fact]
    public void Tampered_ciphertext_fails_authentication()
    {
        var qm = new QuarantineManager(_qDir);
        var entry = QuarantineOne(qm, new byte[64], "gcm.bin");
        var blob = File.ReadAllBytes(entry.QuarantinePath);
        blob[^1] ^= 0x01;
        File.WriteAllBytes(entry.QuarantinePath, blob);

        Assert.False(qm.Restore(entry.Id));
        Assert.False(File.Exists(entry.OriginalPath));
    }

    [Fact]
    public void Entry_without_hash_or_with_foreign_blob_path_is_refused()
    {
        var qm = new QuarantineManager(_qDir);
        var a = QuarantineOne(qm, [1], "nohash.bin");
        var b = QuarantineOne(qm, [2], "foreign.bin");

        a.Sha256 = string.Empty;
        Assert.False(qm.Restore(a.Id));

        var outside = Path.Combine(_root, "outside.quar");
        File.Copy(b.QuarantinePath, outside);
        b.QuarantinePath = outside;
        Assert.False(qm.Restore(b.Id));
        // Suppression : le chemin étranger n'est jamais effacé, l'entrée est retirée.
        Assert.True(qm.DeletePermanently(b.Id));
        Assert.True(File.Exists(outside));
    }

    [Fact]
    public void Restore_with_missing_blob_or_unknown_id_returns_false()
    {
        var qm = new QuarantineManager(_qDir);
        var entry = QuarantineOne(qm, [3, 3], "missing.bin");
        File.Delete(entry.QuarantinePath);

        Assert.False(qm.Restore(entry.Id));
        Assert.False(qm.Restore("inconnu"));
        Assert.False(qm.RestoreAdministrative("inconnu"));
        Assert.False(qm.RestoreTo("inconnu", _root));
        Assert.False(qm.DeletePermanently("inconnu"));
    }

    [Fact]
    public void RestoreTo_creates_folder_and_avoids_overwriting()
    {
        var qm = new QuarantineManager(_qDir);
        var payload = new byte[] { 4, 2 };
        var entry = QuarantineOne(qm, payload, "dest.bin");
        var target = Path.Combine(_root, "restore", "here");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "dest.bin"), "déjà là");

        Assert.True(qm.RestoreTo(entry.Id, target));

        Assert.Equal("déjà là", File.ReadAllText(Path.Combine(target, "dest.bin")));
        Assert.Equal(payload, File.ReadAllBytes(Path.Combine(target, "dest_restored.bin")));
        Assert.Equal(0, qm.Count);
    }

    [Fact]
    public void Restore_recreates_missing_parent_folder()
    {
        var qm = new QuarantineManager(_qDir);
        var payload = new byte[] { 5, 5, 5 };
        var entry = QuarantineOne(qm, payload, "parent.bin");
        Directory.Delete(Path.GetDirectoryName(entry.OriginalPath)!, recursive: true);

        Assert.True(qm.RestoreAdministrative(entry.Id));
        Assert.Equal(payload, File.ReadAllBytes(entry.OriginalPath));
    }

    [Fact]
    public void Interface_methods_totals_and_purge()
    {
        IThreatStore store = new QuarantineManager(_qDir);
        var qm = (QuarantineManager)store;
        var t1 = Threat(Sample("i1.bin", [1, 2]));
        var t2 = Threat(Sample("i2.bin", [3, 4, 5]));

        Assert.True(store.Quarantine(t1));
        Assert.Equal(ThreatStatus.Quarantined, t1.Status);
        Assert.Equal(1, store.QuarantineAll([t2, new ThreatInfo { FilePath = Path.Combine(_root, "none") }]));
        Assert.Equal(5, qm.TotalSize);
        Assert.Equal(2, qm.PurgeAll());
        Assert.Equal(0, qm.TotalSize);
        Assert.Empty(Directory.GetFiles(_qDir, "*.quar"));
    }

    [Fact]
    public void Backup_before_quarantine_writes_a_safety_copy()
    {
        var prefs = new FixedPreferencesAccessor(new UserPreferences { BackupBeforeQuarantine = true });
        var qm = new QuarantineManager(_qDir, prefs);
        var payload = new byte[] { 1, 9, 8, 4 };

        QuarantineOne(qm, payload, "backup.bin");

        var copy = Assert.Single(Directory.GetFiles(ThreatRemediationService.BackupRoot));
        // Copie neutralisée : ni l'extension ni le contenu d'origine (jamais exécutable telle quelle).
        Assert.EndsWith("_backup.bin" + ThreatRemediationService.SafetyCopyExtension, copy, StringComparison.Ordinal);
        Assert.NotEqual(payload, File.ReadAllBytes(copy));
        Assert.Equal(payload, ThreatRemediationService.DecodeSafetyCopy(copy));
    }

    [Fact]
    public void Safety_copy_skips_missing_and_blank_paths()
    {
        Assert.False(ThreatRemediationService.TryCreateSafetyCopy(new ThreatInfo { FilePath = " " }));
        Assert.False(ThreatRemediationService.TryCreateSafetyCopy(new ThreatInfo { FilePath = Path.Combine(_root, "nope") }));
    }
}
