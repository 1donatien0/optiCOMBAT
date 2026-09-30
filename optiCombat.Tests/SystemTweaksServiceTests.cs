using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class SystemTweaksServiceTests
{
    [Fact]
    public void BuildClearDefenderHistoryHelperBatch_is_optiCombat_one_shot_cmd()
    {
        var script = SystemTweaksService.BuildClearDefenderHistoryHelperBatch();

        Assert.StartsWith("@echo off", script, StringComparison.Ordinal);
        Assert.Contains("optiCombat", script, StringComparison.Ordinal);
        Assert.Contains(@"%ProgramData%\Microsoft\Windows Defender", script, StringComparison.Ordinal);
        Assert.Contains(@"Scans\History\Service", script, StringComparison.Ordinal);
        Assert.Contains("Quarantine", script, StringComparison.Ordinal);
        Assert.Contains("mpenginedb.db*", script, StringComparison.Ordinal);
        Assert.Contains($"schtasks /delete /f /tn \"{SystemTweaksService.ClearDefenderHistoryTaskName}\"", script, StringComparison.Ordinal);
        Assert.DoesNotContain("powershell", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Register-ScheduledTask", script, StringComparison.Ordinal);
        Assert.DoesNotContain("DWDH", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Restart-Computer", script, StringComparison.Ordinal);
    }

    [Fact]
    public void ElevatedClearDefenderHistoryCommands_uses_schtasks_not_powershell()
    {
        var commands = SystemTweaksService.ElevatedClearDefenderHistoryCommands().ToList();

        Assert.Equal(4, commands.Count);
        Assert.Contains(commands, c => c.StartsWith("if not exist ", StringComparison.Ordinal));
        Assert.Contains(commands, c => c.StartsWith("copy /y ", StringComparison.Ordinal));
        Assert.Contains(commands, c => c.StartsWith("del /f /q ", StringComparison.Ordinal));
        Assert.Contains(
            commands,
            c => c.StartsWith($"schtasks /Create /TN \"{SystemTweaksService.ClearDefenderHistoryTaskName}\"", StringComparison.Ordinal));
        Assert.DoesNotContain(commands, c => c.Contains("powershell", StringComparison.OrdinalIgnoreCase));

        var copy = commands.Single(c => c.StartsWith("copy /y ", StringComparison.Ordinal));
        var source = copy.Split('"')[1];
        if (File.Exists(source))
            File.Delete(source);
    }
}
