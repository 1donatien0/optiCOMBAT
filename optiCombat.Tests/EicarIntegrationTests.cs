using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

/// <summary>
/// EICAR via la règle YARA embarquée <c>rules/test_rules.yar</c> (<c>EICAR_Test</c>).
/// Ignore uniquement si <c>yara64.exe</c> est absent.
/// </summary>
public sealed class EicarIntegrationTests : IDisposable
{
    /// <summary>Chaîne attendue par <c>EICAR_Test</c> dans <c>test_rules.yar</c> (pas le fichier standard complet).</summary>
    private const string EicarYaraPayload = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-";

    private const string EicarRuleName = "EICAR_Test";

    private readonly string _sampleDir;
    private readonly string _rulesDir;

    public EicarIntegrationTests()
    {
        _sampleDir = CreateSampleDirectory();
        _rulesDir = Path.Combine(_sampleDir, "rules");
        Directory.CreateDirectory(_rulesDir);
        File.Copy(ResolveTestRulesYarPath(), Path.Combine(_rulesDir, "test_rules.yar"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_sampleDir, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public void test_rules_yar_defines_EICAR_Test_rule()
    {
        var content = File.ReadAllText(ResolveTestRulesYarPath());

        Assert.Contains("rule EICAR_Test", content, StringComparison.Ordinal);
        Assert.Contains(EicarYaraPayload, content, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task YaraEngine_detects_EICAR_via_test_rules_yar()
    {
        if (!TryCreateYaraEngine(out var yara))
            return;

        var file = PrepareEicarSample("eicar-yara.bin");
        var matches = await yara.ScanFileAsync(file);

        Assert.Contains(matches, m =>
            string.Equals(m.RuleName, EicarRuleName, StringComparison.OrdinalIgnoreCase)
            && string.Equals(m.FilePath, file, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task ScanOrchestrator_detects_EICAR_via_yara_test_rule()
    {
        if (!TryCreateYaraEngine(out var yara))
            return;

        var file = PrepareEicarSample("eicar-orchestrator.bin");
        var orch = new ScanOrchestrator(new SilentClamBackend(), yara);
        var result = await orch.ScanFileAsync(file);

        Assert.Equal(ScanStatus.Completed, result.Status);
        Assert.Contains(result.Threats, t =>
            string.Equals(t.VirusName, EicarRuleName, StringComparison.OrdinalIgnoreCase)
            && string.Equals(t.DetectedBy, "YARA", StringComparison.OrdinalIgnoreCase));
    }

    private string PrepareEicarSample(string fileName)
    {
        foreach (var dir in CandidateSampleDirectories())
        {
            try
            {
                Directory.CreateDirectory(dir);
                var file = Path.Combine(dir, fileName);
                File.WriteAllText(file, EicarYaraPayload);
                if (!CanReadSample(file))
                    continue;

                var yaraBin = ResolveYaraBinDir();
                if (yaraBin != null && !ProbeYaraMatch(yaraBin, _rulesDir, file))
                    continue;

                return file;
            }
            catch
            {
                /* essayer le répertoire suivant */
            }
        }

        throw new InvalidOperationException(
            "Impossible de préparer un échantillon EICAR scannable par YARA " +
            "(antivirus système ou droits d'accès). Ajoutez une exclusion pour le dossier de tests ou le dépôt.");
    }

    private IEnumerable<string> CandidateSampleDirectories()
    {
        yield return Path.Combine(_sampleDir, "samples");

        var repoRoot = ResolveRepoRoot();
        if (repoRoot != null)
            yield return Path.Combine(repoRoot, ".eicar-test", Guid.NewGuid().ToString("N"));

        yield return Path.Combine(Path.GetTempPath(), "opticombat_eicar_" + Guid.NewGuid().ToString("N"));
    }

    private static string CreateSampleDirectory()
    {
        var repoRoot = ResolveRepoRoot();
        if (repoRoot != null)
            return Path.Combine(repoRoot, ".eicar-test", "_run_" + Guid.NewGuid().ToString("N"));

        return Path.Combine(Path.GetTempPath(), "opticombat_eicar_" + Guid.NewGuid().ToString("N"));
    }

    private static bool CanReadSample(string filePath)
    {
        if (!File.Exists(filePath))
            return false;
        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            return stream.Length >= EicarYaraPayload.Length;
        }
        catch
        {
            return false;
        }
    }

    private static bool ProbeYaraMatch(string yaraBinDir, string rulesDir, string filePath)
    {
        var exe = Path.Combine(yaraBinDir, Environment.Is64BitProcess ? "yara64.exe" : "yara32.exe");
        if (!File.Exists(exe))
            return false;

        var ruleFile = Path.Combine(rulesDir, "test_rules.yar");
        if (!File.Exists(ruleFile))
            return false;

        try
        {
            using var proc = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = exe,
                    ArgumentList = { ruleFile, filePath },
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                }
            };
            proc.Start();
            var stdout = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10_000);
            return proc.ExitCode == 0 && stdout.Contains(EicarRuleName, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private bool TryCreateYaraEngine(out YaraEngine engine)
    {
        engine = null!;
        var yaraBin = ResolveYaraBinDir();
        if (yaraBin == null)
            return false;

        engine = new YaraEngine(yaraBin, _rulesDir);
        return engine.IsAvailable;
    }

    private static string ResolveTestRulesYarPath()
    {
        var fromRepo = TryFindRepoFile("optiCombat", "rules", "test_rules.yar");
        if (fromRepo != null)
            return fromRepo;

        throw new InvalidOperationException(
            "rules/test_rules.yar introuvable — exécuter les tests depuis la racine du dépôt.");
    }

    private static string? ResolveRepoRoot()
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 10 && dir != null; i++)
        {
            if (File.Exists(Path.Combine(dir, "optiCombat.sln")))
                return dir;
            dir = Directory.GetParent(dir)?.FullName;
        }

        return null;
    }

    private static string? ResolveYaraBinDir()
    {
        var exe = Environment.Is64BitProcess ? "yara64.exe" : "yara32.exe";

        var fromRepo = TryFindRepoFile("optiCombat", "yara", exe);
        if (fromRepo != null)
            return Path.GetDirectoryName(fromRepo);

        var nextToTests = Path.Combine(AppContext.BaseDirectory, "yara", exe);
        if (File.Exists(nextToTests))
            return Path.GetDirectoryName(nextToTests);

        var nextToAppBuild = TryFindRepoFile("optiCombat", "bin", "Release", "net8.0-windows10.0.17763.0", "yara", exe)
            ?? TryFindRepoFile("optiCombat", "bin", "Debug", "net8.0-windows10.0.17763.0", "yara", exe);
        if (nextToAppBuild != null)
            return Path.GetDirectoryName(nextToAppBuild);

        return null;
    }

    private static string? TryFindRepoFile(params string[] relativeParts)
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 10 && dir != null; i++)
        {
            var candidate = Path.Combine(new[] { dir }.Concat(relativeParts).ToArray());
            if (File.Exists(candidate))
                return candidate;
            dir = Directory.GetParent(dir)?.FullName;
        }

        return null;
    }

    private sealed class SilentClamBackend : IClamAvOrchestratorBackend
    {
        public bool IsClamAvInstalled() => true;

        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => Task.FromResult(CompletedFileResult(filePath));

        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => Task.FromResult(CompletedFileResult(folderPath));

        public Task<ScanResult> ScanFileListAsync(
            IReadOnlyList<string> files,
            string targetPath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
            => Task.FromResult(CompletedFileResult(targetPath));

        private static ScanResult CompletedFileResult(string targetPath) => new()
        {
            Status = ScanStatus.Completed,
            Type = ScanType.File,
            TargetPath = targetPath,
            FilesScanned = 1,
        };
    }
}
