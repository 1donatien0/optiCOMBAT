using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class SystemTweaksServiceTests
{
    [Fact]
    public void BuildElevatedCommandLine_chains_commands_without_script_file()
    {
        var args = SystemTweaksService.BuildElevatedCommandLine(new[] { "net stop wuauserv", "", "net start wuauserv" });

        Assert.Equal("/d /s /c \"net stop wuauserv & net start wuauserv\"", args);
    }

    [Fact]
    public void BuildElevatedCommandLine_rejects_newlines()
    {
        Assert.Throws<ArgumentException>(() =>
            SystemTweaksService.BuildElevatedCommandLine(new[] { "echo a\r\ndel x" }));
    }

    [Fact]
    public void WindowsUpdateCacheCommands_are_valid_on_command_line()
    {
        var commands = SystemTweaksService.ElevatedWindowsUpdateCacheCommands().ToList();

        // %%d n'est valide que dans un fichier .cmd : interdit maintenant que le lot passe en ligne.
        Assert.DoesNotContain(commands, c => c.Contains("%%", StringComparison.Ordinal));
        Assert.Equal("net stop wuauserv", commands[0]);
        Assert.Equal("net start wuauserv", commands[^1]);
    }

    [Fact]
    public void Elevated_commands_never_touch_windows_defender()
    {
        var all = SystemTweaksService.ElevatedTelemetryCommands()
            .Concat(SystemTweaksService.ElevatedDismCleanupCommands())
            .Concat(SystemTweaksService.ElevatedWindowsUpdateCacheCommands());

        Assert.DoesNotContain(all, c => c.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase));
    }
}
