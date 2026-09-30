using System.Runtime.Versioning;
using optiCombat.Services;

namespace optiCombat.Tests;

[SupportedOSPlatform("windows")]
public sealed class DirectoryHardeningTests
{
  [Fact]
  public void Harden_keeps_owner_access_and_breaks_inheritance()
  {
    if (!OperatingSystem.IsWindows())
      return;

    var dir = Path.Combine(Path.GetTempPath(), "oc_acl_" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    try
    {
      Assert.True(DirectoryHardening.HardenDataDirectory(dir));

      var probe = Path.Combine(dir, "probe.txt");
      File.WriteAllText(probe, "ok");
      Assert.Equal("ok", File.ReadAllText(probe));

      var security = new DirectoryInfo(dir).GetAccessControl();
      Assert.True(security.AreAccessRulesProtected);
    }
    finally
    {
      try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
    }
  }

  [Fact]
  public void Harden_missing_directory_is_a_no_op()
  {
    var missing = Path.Combine(Path.GetTempPath(), "oc_missing_" + Guid.NewGuid().ToString("N"));
    Assert.False(DirectoryHardening.HardenDataDirectory(missing));
  }
}
