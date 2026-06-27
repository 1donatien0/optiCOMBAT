using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ClamAvDatabasePathsTests
{
    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Crée un répertoire temp isolé, exécute <paramref name="test"/>, puis
    /// nettoie quoi qu'il arrive.
    /// </summary>
    private static void WithTempDir(Action<string> test)
    {
        var root = Path.Combine(Path.GetTempPath(), "opticombat-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try { test(root); }
        finally { try { Directory.Delete(root, recursive: true); } catch { /* best effort */ } }
    }

    // ── ResolveClamAvBinDir ───────────────────────────────────────────────────

    [Fact]
    public void ResolveClamAvBinDir_finds_arch_specific_binary()
    {
        // Layout : <root>/clamav/<arch>/clamscan.exe
        // Attendu : le dossier arch-spécifique est retourné.
        WithTempDir(root =>
        {
            var arch = Environment.Is64BitProcess ? "x64" : "x86";
            var archDir = Path.Combine(root, "clamav", arch);
            Directory.CreateDirectory(archDir);
            File.WriteAllText(Path.Combine(archDir, "clamscan.exe"), "stub");

            var result = ClamAvDatabasePaths.ResolveClamAvBinDir("clamscan.exe", root);

            Assert.Equal(Path.GetFullPath(archDir), Path.GetFullPath(result), ignoreCase: true);
        });
    }

    [Fact]
    public void ResolveClamAvBinDir_falls_back_to_flat_layout()
    {
        // Layout : <root>/clamav/clamscan.exe seulement (pas de sous-dossier arch).
        // Attendu : le dossier flat est retourné.
        WithTempDir(root =>
        {
            var flatDir = Path.Combine(root, "clamav");
            Directory.CreateDirectory(flatDir);
            File.WriteAllText(Path.Combine(flatDir, "clamscan.exe"), "stub");

            var result = ClamAvDatabasePaths.ResolveClamAvBinDir("clamscan.exe", root);

            Assert.Equal(Path.GetFullPath(flatDir), Path.GetFullPath(result), ignoreCase: true);
        });
    }

    [Fact]
    public void ResolveClamAvBinDir_respects_custom_executable_name()
    {
        // Layout : <root>/clamav/freshclam.exe seulement.
        // Recherche "clamscan.exe" → repli ; recherche "freshclam.exe" → flat trouvé.
        WithTempDir(root =>
        {
            var flatDir = Path.Combine(root, "clamav");
            Directory.CreateDirectory(flatDir);
            File.WriteAllText(Path.Combine(flatDir, "freshclam.exe"), "stub");

            // clamscan.exe absent → repli
            var fallback = ClamAvDatabasePaths.ResolveClamAvBinDir("clamscan.exe", root);
            Assert.Equal(
                Path.GetFullPath(flatDir),
                Path.GetFullPath(fallback),
                ignoreCase: true);

            // freshclam.exe présent → flat trouvé
            var found = ClamAvDatabasePaths.ResolveClamAvBinDir("freshclam.exe", root);
            Assert.Equal(
                Path.GetFullPath(flatDir),
                Path.GetFullPath(found),
                ignoreCase: true);
        });
    }

    [Fact]
    public void ResolveClamAvBinDir_returns_flat_fallback_when_no_binary_found()
    {
        // Aucun binaire dans l'arborescence.
        // Attendu : <root>/clamav est retourné (repli documenté — l'erreur sera
        // levée à l'utilisation par le moteur, pas ici).
        WithTempDir(root =>
        {
            var expectedFallback = Path.Combine(root, "clamav");

            var result = ClamAvDatabasePaths.ResolveClamAvBinDir("clamscan.exe", root);

            Assert.Equal(
                Path.GetFullPath(expectedFallback),
                Path.GetFullPath(result),
                ignoreCase: true);
        });
    }

    // ── ResolvePreferredDatabaseDir ───────────────────────────────────────────

    [Fact]
    public void ResolvePreferredDatabaseDir_finds_database_next_to_binaries()
    {
        var root = Path.Combine(Path.GetTempPath(), "opticombat-db-" + Guid.NewGuid().ToString("N"));
        var binDir = Path.Combine(root, "clamav", "x64");
        var dbDir = Path.Combine(binDir, "database");
        Directory.CreateDirectory(dbDir);

        try
        {
            var resolved = ClamAvDatabasePaths.ResolvePreferredDatabaseDir(binDir);
            Assert.Equal(Path.GetFullPath(dbDir), resolved, ignoreCase: true);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void ResolveWritableDatabaseDir_uses_local_folder_when_writable()
    {
        var root = Path.Combine(Path.GetTempPath(), "opticombat-db-" + Guid.NewGuid().ToString("N"));
        var binDir = Path.Combine(root, "clamav");
        var dbDir = Path.Combine(binDir, "database");
        Directory.CreateDirectory(dbDir);
        File.WriteAllText(Path.Combine(dbDir, "main.cvd"), "x");

        try
        {
            var resolved = ClamAvDatabasePaths.ResolveWritableDatabaseDir(binDir);
            Assert.Equal(Path.GetFullPath(dbDir), resolved, ignoreCase: true);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }
}
