using System.Security.Cryptography;
using System.Text.Json.Nodes;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class YaraForgePackageIntegrityTests
{
  private static readonly byte[] Zip = { 0x50, 0x4B, 0x03, 0x04, 0x2A, 0x2B };

  [Fact]
  public void Validate_rejects_non_zip_and_empty()
  {
    var hash = SHA256.HashData(Zip);
    Assert.False(YaraForgePackageIntegrity.Validate(Array.Empty<byte>(), null, hash));
    Assert.False(YaraForgePackageIntegrity.Validate(new byte[] { 0x3C, 0x68, 0x74, 0x6D }, null, hash));
  }

  [Fact]
  public void Validate_rejects_zip_without_sha256()
  {
    Assert.False(YaraForgePackageIntegrity.Validate(Zip, null, null));
    Assert.False(YaraForgePackageIntegrity.Validate(Zip, Zip.Length, Array.Empty<byte>()));
  }

  [Fact]
  public void Validate_checks_size_and_sha256()
  {
    var hash = SHA256.HashData(Zip);
    Assert.True(YaraForgePackageIntegrity.Validate(Zip, Zip.Length, hash));
    Assert.False(YaraForgePackageIntegrity.Validate(Zip, Zip.Length + 1, hash));
    Assert.False(YaraForgePackageIntegrity.Validate(Zip, Zip.Length, SHA256.HashData(new byte[] { 1, 2, 3 })));
    Assert.False(YaraForgePackageIntegrity.Validate(Zip, null, new byte[] { 1, 2 }));
  }

  [Fact]
  public void ReadExpected_parses_github_asset()
  {
    var hex = new string('a', 64);
    var node = JsonNode.Parse($$"""{"size":12345,"digest":"sha256:{{hex}}"}""");
    YaraForgePackageIntegrity.ReadExpected(node, out var size, out var sha);
    Assert.Equal(12345, size);
    Assert.NotNull(sha);
    Assert.Equal(32, sha!.Length);
  }

  [Theory]
  [InlineData(null)]
  [InlineData("")]
  [InlineData("md5:abcd")]
  [InlineData("sha256:1234")]
  [InlineData("sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")]
  public void TryParseDigest_rejects_invalid(string? digest)
  {
    Assert.False(YaraForgePackageIntegrity.TryParseDigest(digest, out _));
  }

  [Fact]
  public void ReadExpected_tolerates_missing_fields()
  {
    YaraForgePackageIntegrity.ReadExpected(JsonNode.Parse("{}"), out var size, out var sha);
    Assert.Null(size);
    Assert.Null(sha);
  }
}
