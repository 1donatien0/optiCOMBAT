using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ScanPathValidationTests
{
  [Theory]
  [InlineData(@"\\.\C:\")]
  [InlineData(@"\\?\C:\Windows")]
  [InlineData(@"\\.\PhysicalDrive0")]
  [InlineData("C:\\temp\\a\u0000b.exe")]
  [InlineData("C:\\temp\\a\nb.exe")]
  [InlineData("   ")]
  [InlineData(null)]
  public void Rejects_device_paths_control_chars_and_empty(string? path)
  {
    Assert.False(ScanPathValidation.IsSyntacticallyAcceptable(path));
    Assert.False(ScanPathValidation.TryNormalizeScanTarget(path, out var full));
    Assert.Equal(string.Empty, full);
  }

  [Fact]
  public void Accepts_existing_file_and_quoted_folder()
  {
    var dir = Path.Combine(Path.GetTempPath(), "oc_scanval_" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    var file = Path.Combine(dir, "a.txt");
    File.WriteAllText(file, "x");
    try
    {
      Assert.True(ScanPathValidation.TryNormalizeScanTarget(file, out var fullFile));
      Assert.Equal(Path.GetFullPath(file), fullFile);
      Assert.True(ScanPathValidation.TryNormalizeScanTarget("\"" + dir + "\"", out var fullDir));
      Assert.Equal(Path.GetFullPath(dir), fullDir);
    }
    finally
    {
      Directory.Delete(dir, recursive: true);
    }
  }

  [Fact]
  public void Rejects_missing_path()
  {
    var missing = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
    Assert.True(ScanPathValidation.IsSyntacticallyAcceptable(missing));
    Assert.False(ScanPathValidation.TryNormalizeScanTarget(missing, out _));
  }

  [Fact]
  public void Shell_argument_with_device_path_is_rejected()
  {
    Assert.False(ShellScanArguments.TryGetScanPath(new[] { "--scan", @"\\.\PhysicalDrive0" }, out var path));
    Assert.Equal(string.Empty, path);
  }

  [Fact]
  public void Rejects_sensitive_path_when_not_allowed()
  {
    var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
    if (string.IsNullOrEmpty(system32) || !Directory.Exists(system32))
      return;

    Assert.False(ScanPathValidation.TryNormalizeScanTarget(system32, out _, allowSensitive: false));
    Assert.True(ScanPathValidation.TryNormalizeScanTarget(system32, out var allowed, allowSensitive: true));
    Assert.Equal(Path.GetFullPath(system32), allowed);
  }

  [Fact]
  public void Rejects_junction_into_sensitive_path_when_not_allowed()
  {
    var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
    if (string.IsNullOrEmpty(system32) || !Directory.Exists(system32))
      return;

    var junctionRoot = Path.Combine(Path.GetTempPath(), "oc_junc_" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(junctionRoot);
    var junction = Path.Combine(junctionRoot, "to_system");
    try
    {
      try
      {
        Directory.CreateSymbolicLink(junction, system32);
      }
      catch (Exception)
      {
        // Création de lien souvent refusée sans privilège — le cas est alors non testable ici.
        return;
      }

      Assert.True(QuarantineManager.IsSensitivePath(junction));
      Assert.False(ScanPathValidation.TryNormalizeScanTarget(junction, out _, allowSensitive: false));
    }
    finally
    {
      try
      {
        if (Directory.Exists(junction))
          Directory.Delete(junction);
      }
      catch { /* best effort */ }
      try { Directory.Delete(junctionRoot, recursive: true); }
      catch { /* best effort */ }
    }
  }
}
