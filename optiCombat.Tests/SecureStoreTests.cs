using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class SecureStoreTests
{
    private sealed class TestDto
    {
        public string Value { get; set; } = "";
        public int N { get; set; }
    }

    [Fact]
    public void Save_Load_roundtrip_restores_payload()
    {
        var path = Path.Combine(Path.GetTempPath(), "opticombat_ut_secure_" + Guid.NewGuid().ToString("N") + ".dat");
        try
        {
            var original = new TestDto { Value = "roundtrip-payload", N = 42 };
            SecureStore.Save(path, original);

            var loaded = SecureStore.Load<TestDto>(path);
            Assert.NotNull(loaded);
            Assert.Equal("roundtrip-payload", loaded.Value);
            Assert.Equal(42, loaded.N);
        }
        finally
        {
            try { File.Delete(path); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void Load_corrupted_blob_returns_null()
    {
        var path = Path.Combine(Path.GetTempPath(), "opticombat_ut_corrupt_" + Guid.NewGuid().ToString("N") + ".dat");
        try
        {
            var original = new TestDto { Value = "x", N = 1 };
            SecureStore.Save(path, original);

            var bytes = File.ReadAllBytes(path);
            if (bytes.Length > 4)
                bytes[^1] ^= 0xFF;
            File.WriteAllBytes(path, bytes);

            Assert.Null(SecureStore.Load<TestDto>(path));
        }
        finally
        {
            try { File.Delete(path); } catch { /* best effort */ }
        }
    }
}
