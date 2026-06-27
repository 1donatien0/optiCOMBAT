using System.Text;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class YaraRulesCacheSupportTests : IDisposable
{
    private readonly string _rulesDir;

    public YaraRulesCacheSupportTests()
    {
        _rulesDir = Path.Combine(Path.GetTempPath(), "opticombat_yara_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_rulesDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_rulesDir, recursive: true); } catch { }
    }

    [Fact]
    public void IsCompiledUpToDate_false_when_stamp_missing()
    {
        var yar = Path.Combine(_rulesDir, "a.yar");
        File.WriteAllText(yar, "rule test { condition: false }");
        var yarc = Path.Combine(_rulesDir, "_compiled.yarc");
        File.WriteAllBytes(yarc, [1, 2, 3]);
        var stamp = Path.Combine(_rulesDir, "_compiled.stamp");
        Assert.False(YaraRulesCacheSupport.IsCompiledUpToDate(_rulesDir, yarc, stamp));
    }

    [Fact]
    public void IsCompiledUpToDate_true_when_stamp_matches_rules()
    {
        var yar = Path.Combine(_rulesDir, "a.yar");
        File.WriteAllText(yar, "rule test { condition: false }");
        var files = Directory.GetFiles(_rulesDir, "*.yar");
        Array.Sort(files, StringComparer.OrdinalIgnoreCase);
        var stampPath = Path.Combine(_rulesDir, "_compiled.stamp");
        YaraRulesCacheSupport.WriteCompiledStamp(stampPath, files);
        var yarc = Path.Combine(_rulesDir, "_compiled.yarc");
        File.WriteAllBytes(yarc, [1]);

        Assert.True(YaraRulesCacheSupport.IsCompiledUpToDate(_rulesDir, yarc, stampPath));
    }

    [Fact]
    public void IsCompiledUpToDate_false_after_rule_file_changes()
    {
        var yar = Path.Combine(_rulesDir, "a.yar");
        File.WriteAllText(yar, "rule test { condition: false }");
        var files = Directory.GetFiles(_rulesDir, "*.yar");
        Array.Sort(files, StringComparer.OrdinalIgnoreCase);
        var stampPath = Path.Combine(_rulesDir, "_compiled.stamp");
        YaraRulesCacheSupport.WriteCompiledStamp(stampPath, files);
        var yarc = Path.Combine(_rulesDir, "_compiled.yarc");
        File.WriteAllBytes(yarc, [1]);

        File.AppendAllText(yar, "\n// modified");

        Assert.False(YaraRulesCacheSupport.IsCompiledUpToDate(_rulesDir, yarc, stampPath));
    }

    [Fact]
    public void ComputeRulesDirectoryFingerprint_is_stable_for_same_files()
    {
        var yar = Path.Combine(_rulesDir, "b.yar");
        File.WriteAllText(yar, "rule x { condition: false }");
        var files = Directory.GetFiles(_rulesDir, "*.yar");
        Array.Sort(files, StringComparer.OrdinalIgnoreCase);
        var a = YaraRulesCacheSupport.ComputeRulesDirectoryFingerprint(files);
        var b = YaraRulesCacheSupport.ComputeRulesDirectoryFingerprint(files);
        Assert.Equal(a, b);
        Assert.NotEqual("EMPTY", a);
    }
}
