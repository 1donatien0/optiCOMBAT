using optiCombat.Platform;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

/// <summary>
/// Surface IPC locale du service : chaque requête invalide doit produire une réponse d'erreur
/// (jamais une exception, jamais un scan), testée sans tube nommé via <c>Dispatch</c>.
/// </summary>
public sealed class ProtectionPipeDispatchTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "opticombat_ipcd_" + Guid.NewGuid().ToString("N"));
    private readonly ScriptedClamBackend _clam = new();

    public ProtectionPipeDispatchTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private ProtectionPipeServer Server(IpcScanRateLimiter? limiter = null) =>
        new(new ScanOrchestrator(_clam, new NoopYaraBackend(),
                new FixedPreferencesAccessor(new optiCombat.Services.UserPreferences()),
                new FixedExclusionsAccessor(new ExclusionSettings()), optiCombat: null),
            pipeName: "unused_" + Guid.NewGuid().ToString("N"),
            scanRateLimiter: limiter);

    private static ProtectionPipeRequest Buffer(string? b64, string? name = null) => new()
    {
        Operation = ProtectionPipeOperations.ScanBuffer,
        BufferBase64 = b64,
        ContentName = name,
    };

    [Fact]
    public void GetStatus_reports_available_engines()
    {
        var r = Server().Dispatch(new ProtectionPipeRequest { Operation = ProtectionPipeOperations.GetStatus });
        Assert.True(r.Ok);
        Assert.StartsWith("clam=", r.Message, StringComparison.Ordinal);
        Assert.Contains("yara=False", r.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Unknown_operation_is_an_error()
    {
        var r = Server().Dispatch(new ProtectionPipeRequest { Operation = "format_c" });
        Assert.False(r.Ok);
        Assert.Contains("format_c", r.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Shutdown_without_valid_token_is_refused()
    {
        var r = Server().Dispatch(new ProtectionPipeRequest
        {
            Operation = ProtectionPipeOperations.Shutdown,
            AuthToken = "devine",
        });
        Assert.False(r.Ok);
        Assert.Equal("Non autorisé", r.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("pas\u0001valide")]
    public void ScanPath_with_unusable_path_is_refused_without_scanning(string? path)
    {
        var r = Server().Dispatch(new ProtectionPipeRequest { Operation = ProtectionPipeOperations.ScanPath, Path = path });
        Assert.False(r.Ok);
        Assert.Equal("Chemin invalide", r.Message);
        Assert.Equal(0, _clam.Calls);
    }

    [Fact]
    public void ScanPath_on_missing_file_is_refused()
    {
        var r = Server().Dispatch(new ProtectionPipeRequest
        {
            Operation = ProtectionPipeOperations.ScanPath,
            Path = Path.Combine(_dir, "absent.exe"),
        });
        Assert.Equal("Chemin invalide", r.Message);
    }

    [Fact]
    public void ScanPath_reports_the_first_threat()
    {
        var file = Path.Combine(_dir, "mal.exe");
        File.WriteAllText(file, "x");
        _clam.ThreatsByPath[Path.GetFullPath(file)] = "Win.Test.Pipe";

        var r = Server().Dispatch(new ProtectionPipeRequest { Operation = ProtectionPipeOperations.ScanPath, Path = file });

        Assert.True(r.Ok);
        Assert.False(r.Clean);
        Assert.Equal("Win.Test.Pipe", r.ThreatName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void ScanBuffer_empty_is_refused(string? b64)
    {
        var r = Server().Dispatch(Buffer(b64));
        Assert.Equal("Buffer vide", r.Message);
        Assert.Equal(0, _clam.Calls);
    }

    [Fact]
    public void ScanBuffer_too_large_is_refused_before_decoding()
    {
        var r = Server().Dispatch(Buffer(new string('A', ProtectionPipeServer.MaxScanBufferBase64Length + 4)));
        Assert.Equal("Buffer trop volumineux", r.Message);
        Assert.Equal(0, _clam.Calls);
    }

    [Fact]
    public void ScanBuffer_with_invalid_base64_is_an_error_not_an_exception()
    {
        var r = Server().Dispatch(Buffer("ceci n'est pas du base64 !"));
        Assert.False(r.Ok);
        Assert.Equal("Buffer invalide", r.Message);
        Assert.Equal(0, _clam.Calls);
    }

    [Fact]
    public void ScanBuffer_writes_a_temporary_file_scans_it_and_cleans_up()
    {
        _clam.ThreatsByFileName["script.ps1"] = "PS.Test.Amsi";
        var before = Directory.GetDirectories(Path.GetTempPath(), "opticombat_ipc_*").Length;

        var r = Server().Dispatch(Buffer(Convert.ToBase64String("Invoke-Evil"u8.ToArray()), "../../script.ps1"));

        Assert.True(r.Ok);
        Assert.Equal("PS.Test.Amsi", r.ThreatName);
        Assert.Equal(1, _clam.Calls);
        Assert.True(Directory.GetDirectories(Path.GetTempPath(), "opticombat_ipc_*").Length <= before);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("dossier/")]
    [InlineData("nul\0char")]
    public void ScanBuffer_with_odd_content_name_falls_back_to_a_fixed_name(string? name)
    {
        _clam.ThreatsByFileName["amsi_buffer.bin"] = "Fallback.Name";
        var r = Server().Dispatch(Buffer(Convert.ToBase64String([1, 2, 3]), name ?? "amsi_buffer.bin"));
        Assert.True(r.Ok);
        Assert.Equal("Fallback.Name", r.ThreatName);
    }

    [Fact]
    public void ScanBuffer_clean_content_is_reported_clean()
    {
        var r = Server().Dispatch(Buffer(Convert.ToBase64String("bonjour"u8.ToArray()), "note.txt"));
        Assert.True(r.Ok);
        Assert.True(r.Clean);
    }
}
