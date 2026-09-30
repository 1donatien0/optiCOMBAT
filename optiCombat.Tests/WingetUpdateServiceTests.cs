using optiCombat.Services;

namespace optiCombat.Tests;

/// <summary>
/// Construction des arguments winget et nettoyage des versions empilées
/// (même programme en v4, v5, v6… après une mise à jour).
/// </summary>
public sealed class WingetUpdateServiceTests
{
    [Fact]
    public void Upgrade_package_arguments_include_uninstall_previous()
    {
        var args = WingetUpdateService.BuildUpgradePackageArguments("Foo.Bar", uninstallPrevious: true);
        Assert.Contains("--uninstall-previous", args);
        Assert.Contains("--id", args);
        Assert.Contains("Foo.Bar", args);
        Assert.Contains("--exact", args);
    }

    [Fact]
    public void Upgrade_package_arguments_can_omit_uninstall_previous()
    {
        var args = WingetUpdateService.BuildUpgradePackageArguments(
            "Microsoft.VCRedist.2015+.x64", uninstallPrevious: false);
        Assert.DoesNotContain("--uninstall-previous", args);
    }

    [Fact]
    public void Upgrade_all_arguments_include_uninstall_previous()
    {
        Assert.Contains("--uninstall-previous", WingetUpdateService.BuildUpgradeAllArguments());
    }

    [Fact]
    public void Uninstall_version_arguments_target_exact_id_and_version()
    {
        var args = WingetUpdateService.BuildUninstallVersionArguments("Foo.Bar", "5.0.0");
        Assert.Equal("uninstall", args[0]);
        Assert.Contains("--id", args);
        Assert.Contains("Foo.Bar", args);
        Assert.Contains("--version", args);
        Assert.Contains("5.0.0", args);
        Assert.Contains("--exact", args);
    }

    [Theory]
    [InlineData("Microsoft.VCRedist.2015+.x64", false)]
    [InlineData("Microsoft.DotNet.Runtime.8", false)]
    [InlineData("Microsoft.NET.Runtime.8.0", false)]
    [InlineData("Microsoft.DirectX", false)]
    [InlineData("", false)]
    [InlineData("Google.Chrome", true)]
    [InlineData("Git.Git", true)]
    public void Side_by_side_runtimes_are_not_force_cleaned(string packageId, bool allowed)
    {
        Assert.Equal(allowed, WingetUpdateService.AllowsPreviousVersionRemoval(packageId));
    }

    [Fact]
    public void Leftovers_are_the_versions_other_than_the_one_just_installed()
    {
        var leftovers = WingetUpdateService.SelectLeftoverVersions(
            ["4.0.0", "5.1.0", "6.2.0", "7.0.0"],
            "7.0.0");
        Assert.Equal(["4.0.0", "5.1.0", "6.2.0"], leftovers);
    }

    [Fact]
    public void Leftovers_are_empty_until_the_target_version_is_listed()
    {
        // La nouvelle version n'apparaît pas encore : ne pas désinstaller
        // les anciennes, sinon plus aucun binaire ne resterait.
        var leftovers = WingetUpdateService.SelectLeftoverVersions(
            ["4.0.0", "5.1.0", "6.2.0"],
            "7.0.0");
        Assert.Empty(leftovers);
    }

    [Fact]
    public void Unknown_keep_version_skips_cleanup()
    {
        Assert.Empty(WingetUpdateService.SelectLeftoverVersions(
            ["4.0.0", "Unknown"], "Unknown"));
        Assert.Empty(WingetUpdateService.SelectLeftoverVersions(
            ["4.0.0"], "Inconnu"));
        Assert.Empty(WingetUpdateService.SelectLeftoverVersions(
            ["4.0.0"], ""));
    }

    [Fact]
    public void ParseListOutput_reads_stacked_english_versions()
    {
        const string header =
            "Name                          Id                            Version       Available     Source";
        var output = string.Join('\n',
            header,
            new string('-', header.Length),
            WingetRow(header, "Foo App", "Foo.App", "4.0.0", "7.0.0"),
            WingetRow(header, "Foo App", "Foo.App", "5.1.0"),
            WingetRow(header, "Foo App", "Foo.App", "6.2.0"),
            WingetRow(header, "Foo App", "Foo.App", "7.0.0"),
            "",
            "4 packages installed.");

        var parsed = WingetUpdateService.ParseListOutput(output);
        Assert.Equal(4, parsed.Count);
        Assert.All(parsed, p => Assert.Equal("Foo.App", p.Id));
        Assert.Equal(["4.0.0", "5.1.0", "6.2.0", "7.0.0"], parsed.Select(p => p.Version).ToList());
    }

    [Fact]
    public void ParseListOutput_reads_french_header()
    {
        const string header =
            "Nom                           Id                            Version       Disponible    Source";
        var output = string.Join('\n',
            header,
            new string('-', header.Length),
            WingetRow(header, "Foo App", "Foo.App", "4.0.0", "7.0.0"),
            WingetRow(header, "Foo App", "Foo.App", "7.0.0"));

        var parsed = WingetUpdateService.ParseListOutput(output);
        Assert.Equal(2, parsed.Count);
        Assert.Equal("4.0.0", parsed[0].Version);
        Assert.Equal("7.0.0", parsed[1].Version);
    }

    private static string WingetRow(
        string header, string name, string id, string version,
        string available = "", string source = "winget")
    {
        int idxId = header.IndexOf("Id", StringComparison.Ordinal);
        int idxVersion = header.IndexOf("Version", StringComparison.Ordinal);
        int idxAvailable = header.IndexOf("Disponible", StringComparison.Ordinal);
        if (idxAvailable < 0)
            idxAvailable = header.IndexOf("Available", StringComparison.Ordinal);
        int idxSource = header.IndexOf("Source", StringComparison.Ordinal);

        var line = new string(' ', Math.Max(header.Length, idxSource + source.Length));
        line = Overlay(line, 0, name);
        line = Overlay(line, idxId, id);
        line = Overlay(line, idxVersion, version);
        if (idxAvailable > 0 && available.Length > 0)
            line = Overlay(line, idxAvailable, available);
        if (idxSource > 0)
            line = Overlay(line, idxSource, source);
        return line.TrimEnd();
    }

    private static string Overlay(string line, int index, string value)
    {
        if (index < 0 || value.Length == 0)
            return line;
        int needed = index + value.Length;
        if (line.Length < needed)
            line = line.PadRight(needed);
        return string.Concat(line.AsSpan(0, index), value, line.AsSpan(index + value.Length));
    }
}
