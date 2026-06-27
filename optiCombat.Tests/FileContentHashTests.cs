namespace optiCombat.Tests;

public sealed class FileContentHashTests
{
    [Fact]
    public async Task TryComputeSha256HexAsync_returns_stable_hash()
    {
        var dir = Path.Combine(Path.GetTempPath(), "opticombat_hash_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "sample.bin");
        await File.WriteAllBytesAsync(file, [1, 2, 3, 4]);

        try
        {
            var h1 = await optiCombat.Services.FileContentHash.TryComputeSha256HexAsync(file);
            var h2 = await optiCombat.Services.FileContentHash.TryComputeSha256HexAsync(file);

            Assert.NotNull(h1);
            Assert.Equal(h1, h2);
            Assert.Equal(64, h1!.Length);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }
}
