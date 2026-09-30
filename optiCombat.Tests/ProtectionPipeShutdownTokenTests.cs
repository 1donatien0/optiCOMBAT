using optiCombat.Platform;

namespace optiCombat.Tests;

public sealed class ProtectionPipeShutdownTokenTests : IDisposable
{
    private readonly string _dir;
    private readonly string _previousPath;

    public ProtectionPipeShutdownTokenTests()
    {
        _previousPath = ProtectionPipeShutdownToken.TokenFilePath;
        _dir = Path.Combine(Path.GetTempPath(), "oc_shut_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        ProtectionPipeShutdownToken.TokenFilePath = Path.Combine(_dir, "ipc_shutdown.token");
    }

    public void Dispose()
    {
        ProtectionPipeShutdownToken.TokenFilePath = _previousPath;
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    [Fact]
    public void Validate_rejects_mismatch()
    {
        Assert.False(ProtectionPipeShutdownToken.Validate("abc", "xyz"));
        Assert.False(ProtectionPipeShutdownToken.Validate("abc", null));
    }

    [Fact]
    public void Validate_accepts_matching_token()
    {
        var token = ProtectionPipeShutdownToken.Generate();
        Assert.True(ProtectionPipeShutdownToken.Validate(token, token));
    }

    [Fact]
    public void Persist_exclusive_write_then_acl_does_not_throw()
    {
        var token = ProtectionPipeShutdownToken.Generate();
        var ex = Record.Exception(() => ProtectionPipeShutdownToken.Persist(token));
        Assert.Null(ex);

        // Après lockdown ACL admins, File.Exists / TryRead peuvent échouer pour un user standard
        // (comportement voulu). Si la lecture reste possible (ACL non appliquée), vérifier le contenu.
        if (ProtectionPipeShutdownToken.TryRead(out var read))
            Assert.Equal(token, read);
    }
}
