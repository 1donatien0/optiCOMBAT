using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ElevatedCommandRunnerTests
{
  [Theory]
  [InlineData("share")]
  [InlineData("Docs_2024")]
  [InlineData("a.b-c")]
  public void IsSafeArgument_accepts_simple_names(string value) =>
    Assert.True(ElevatedCommandRunner.IsSafeArgument(value));

  [Theory]
  [InlineData("a&b")]
  [InlineData("a|b")]
  [InlineData("a(b)")]
  [InlineData("(payload)")]
  [InlineData("a%PATH%")]
  [InlineData("a\"b")]
  [InlineData("")]
  [InlineData("   ")]
  public void IsSafeArgument_rejects_cmd_metacharacters(string value) =>
    Assert.False(ElevatedCommandRunner.IsSafeArgument(value));
}
