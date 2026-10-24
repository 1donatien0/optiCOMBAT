using optiCombat.Tests.TestSupport;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using optiCombat.Services;

namespace optiCombat.Tests;

/// <summary>Chemins de migration et de refus de <see cref="SecureStore"/> (enveloppes forgées).</summary>
[Collection("OpticombatPrefs")]
public sealed class SecureStoreMigrationTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "oc_ss_" + Guid.NewGuid().ToString("N"));

    public SecureStoreMigrationTests()
    {
        Directory.CreateDirectory(_dir);
        OpticombatDataRoots.TestRootOverride = Path.Combine(_dir, "roots");
    }

    public void Dispose()
    {
        OpticombatDataRoots.TestRootOverride = TestDataRoot.Session;
        try { Directory.Delete(_dir, true); } catch { }
    }

    [Fact]
    public void First_save_creates_the_hmac_key_under_the_data_root()
    {
        Assert.False(File.Exists(SecureStore.HmacKeyPath));
        var path = Path.Combine(_dir, "first.dat");

        SecureStore.Save(path, new Payload { Name = "a", Count = 1 });

        Assert.True(File.Exists(SecureStore.HmacKeyPath));
        Assert.StartsWith(_dir, SecureStore.HmacKeyPath, StringComparison.Ordinal);
        Assert.Equal(1, SecureStore.Load<Payload>(path)!.Count);
    }

    [Fact]
    public void Unreadable_hmac_key_is_never_rotated()
    {
        var signed = Path.Combine(_dir, "signed.dat");
        SecureStore.Save(signed, new Payload { Name = "avant", Count = 2 });
        var goodKey = File.ReadAllBytes(SecureStore.HmacKeyPath);
        File.SetAttributes(SecureStore.HmacKeyPath, FileAttributes.Normal);
        File.WriteAllBytes(SecureStore.HmacKeyPath, [1, 2, 3, 4]);

        var other = Path.Combine(_dir, "other.dat");
        SecureStore.Save(other, new Payload { Name = "après" });

        // Enregistrement refusé plutôt qu'une nouvelle clé qui invaliderait les fichiers signés.
        Assert.False(File.Exists(other));
        Assert.Equal([1, 2, 3, 4], File.ReadAllBytes(SecureStore.HmacKeyPath));
        Assert.Null(SecureStore.Load<Payload>(signed));

        File.WriteAllBytes(SecureStore.HmacKeyPath, goodKey);
        Assert.Equal("avant", SecureStore.Load<Payload>(signed)!.Name);
    }

    [Fact]
    public void Hmac_key_with_wrong_length_is_ignored()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(SecureStore.HmacKeyPath)!);
        File.WriteAllBytes(SecureStore.HmacKeyPath,
            ProtectedData.Protect(new byte[16], null, DataProtectionScope.CurrentUser));
        var path = WriteEnvelope(Json, Sign(Json, new byte[16]));

        Assert.Null(SecureStore.Load<Payload>(path));
    }

    [Fact]
    public void Garbage_or_unprotected_content_loads_as_null()
    {
        var notDpapi = Path.Combine(_dir, "raw.dat");
        File.WriteAllBytes(notDpapi, [0, 1, 2, 3, 4, 5]);
        Assert.Null(SecureStore.Load<Payload>(notDpapi));

        var notJson = Path.Combine(_dir, "notjson.dat");
        File.WriteAllBytes(notJson, ProtectedData.Protect("{pas du json"u8.ToArray(), null, DataProtectionScope.CurrentUser));
        Assert.Null(SecureStore.Load<Payload>(notJson));

        Assert.Null(SecureStore.Load<Payload>(WriteEnvelope("", "")));
    }

    [Fact]
    public void Save_into_an_unwritable_location_is_logged_not_thrown()
    {
        var blocker = Path.Combine(_dir, "blocker");
        File.WriteAllText(blocker, "fichier, pas dossier");
        SecureStore.Save(Path.Combine(blocker, "x.dat"), new Payload());
        Assert.False(File.Exists(Path.Combine(blocker, "x.dat")));
    }

    [Fact]
    public void Plaintext_migration_handles_missing_null_and_invalid_files()
    {
        Assert.Null(SecureStore.MigrateFromPlaintext<Payload>(Path.Combine(_dir, "absent.json"), Path.Combine(_dir, "s.dat")));

        var nul = Path.Combine(_dir, "null.json");
        File.WriteAllText(nul, "null");
        Assert.Null(SecureStore.MigrateFromPlaintext<Payload>(nul, Path.Combine(_dir, "s.dat")));

        var bad = Path.Combine(_dir, "bad.json");
        File.WriteAllText(bad, "{ invalide");
        Assert.Null(SecureStore.MigrateFromPlaintext<Payload>(bad, Path.Combine(_dir, "s.dat")));
        Assert.True(File.Exists(bad)); // laissé en place pour récupération manuelle
    }

    public sealed class Payload
    {
        public string Name { get; set; } = string.Empty;
        public int Count { get; set; }
    }

    private string WriteEnvelope(string json, string hmac)
    {
        var path = Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".dat");
        var envelope = JsonSerializer.Serialize(new { Json = json, Hmac = hmac });
        File.WriteAllBytes(path, ProtectedData.Protect(Encoding.UTF8.GetBytes(envelope), null, DataProtectionScope.CurrentUser));
        return path;
    }

    private static string Sign(string json, byte[] key)
    {
        using var h = new HMACSHA256(key);
        return Convert.ToBase64String(h.ComputeHash(Encoding.UTF8.GetBytes(json)));
    }

    private static byte[] LegacyKey() => SHA256.HashData(Encoding.UTF8.GetBytes(
        "optiCombat-securestore-hmac|" +
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "|" +
        Environment.UserDomainName + "|" +
        Environment.UserName));

    private const string Json = """{"Name":"prefs","Count":3}""";

    [Fact]
    public void Unsigned_legacy_envelope_is_loaded_then_resigned()
    {
        var path = WriteEnvelope(Json, "");
        var before = File.ReadAllBytes(path);

        var loaded = SecureStore.Load<Payload>(path);

        Assert.Equal("prefs", loaded!.Name);
        Assert.NotEqual(before, File.ReadAllBytes(path)); // ré-enregistré avec HMAC
        Assert.Equal(3, SecureStore.Load<Payload>(path)!.Count);
    }

    [Fact]
    public void Envelope_signed_with_the_legacy_key_is_migrated()
    {
        var path = WriteEnvelope(Json, Sign(Json, LegacyKey()));
        var loaded = SecureStore.Load<Payload>(path);
        Assert.Equal(3, loaded!.Count);
        Assert.Equal("prefs", SecureStore.Load<Payload>(path)!.Name);
    }

    [Fact]
    public void Forged_signature_empty_payload_and_garbage_are_refused()
    {
        Assert.Null(SecureStore.Load<Payload>(WriteEnvelope(Json, Sign(Json, RandomNumberGenerator.GetBytes(32)))));
        Assert.Null(SecureStore.Load<Payload>(WriteEnvelope(Json, "pas-du-base64")));
        Assert.Null(SecureStore.Load<Payload>(WriteEnvelope("", "x")));

        var garbage = Path.Combine(_dir, "garbage.dat");
        File.WriteAllBytes(garbage, new byte[] { 1, 2, 3, 4, 5 });
        Assert.Null(SecureStore.Load<Payload>(garbage));
        Assert.Null(SecureStore.Load<Payload>(Path.Combine(_dir, "absent.dat")));
    }

    [Fact]
    public void Plaintext_migration_handles_invalid_and_null_json()
    {
        var bad = Path.Combine(_dir, "bad.json");
        File.WriteAllText(bad, "{pas du json");
        Assert.Null(SecureStore.MigrateFromPlaintext<Payload>(bad, Path.Combine(_dir, "bad.dat")));

        var nul = Path.Combine(_dir, "null.json");
        File.WriteAllText(nul, "null");
        Assert.Null(SecureStore.MigrateFromPlaintext<Payload>(nul, Path.Combine(_dir, "null.dat")));

        var ok = Path.Combine(_dir, "ok.json");
        File.WriteAllText(ok, Json);
        var secure = Path.Combine(_dir, "ok.dat");
        Assert.Equal(3, SecureStore.MigrateFromPlaintext<Payload>(ok, secure)!.Count);
        Assert.True(File.Exists(ok + ".legacy"));
        Assert.Equal("prefs", SecureStore.Load<Payload>(secure)!.Name);
    }
}
