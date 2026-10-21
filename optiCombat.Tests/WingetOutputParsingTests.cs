using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class WingetOutputParsingTests
{
    private const string EnglishUpgrade =
        "   - \\ | /\r\n" +
        "Name                 Id                       Version      Available    Source\r\n" +
        "--------------------------------------------------------------------------------\r\n" +
        "Mozilla Firefox      Mozilla.Firefox          130.0        131.0.2      winget\r\n" +
        "7-Zip                7zip.7zip                23.01        24.08        winget\r\n" +
        "Short\r\n" +
        "\r\n" +
        "                                        \r\n" +
        "2 upgrades available.\r\n";

    private const string FrenchUpgrade =
        "Nom                  Id                       Version      Disponible   Source\n" +
        "--------------------------------------------------------------------------------\n" +
        "Notepad++            Notepad++.Notepad++      8.6          8.7.1        winget\n" +
        "Outil                Vendor.Tool              < 2.0        2.1          winget\n" +
        "1 mises à niveau disponibles.\n";

    [Fact]
    public void ParseUpgradeOutput_reads_english_table_and_skips_noise()
    {
        var updates = WingetUpdateService.ParseUpgradeOutput(EnglishUpgrade);

        Assert.Equal(2, updates.Count);
        Assert.Equal("Mozilla Firefox", updates[0].Name);
        Assert.Equal("Mozilla.Firefox", updates[0].Id);
        Assert.Equal("130.0", updates[0].InstalledVersion);
        Assert.Equal("131.0.2", updates[0].AvailableVersion);
        Assert.Equal("7zip.7zip", updates[1].Id);
    }

    [Fact]
    public void ParseUpgradeOutput_reads_french_table()
    {
        var updates = WingetUpdateService.ParseUpgradeOutput(FrenchUpgrade);

        Assert.Equal(2, updates.Count);
        Assert.Equal("Notepad++.Notepad++", updates[0].Id);
        Assert.Equal("8.7.1", updates[0].AvailableVersion);
        Assert.Equal("< 2.0", updates[1].InstalledVersion);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("Aucun package installé ne correspond.\n")]
    [InlineData("Name   Version   Id\n-----\nx   1   y\n")]
    public void ParseUpgradeOutput_returns_empty_for_unrecognised_output(string output) =>
        Assert.Empty(WingetUpdateService.ParseUpgradeOutput(output));

    [Fact]
    public void ParseUpgradeOutput_without_source_column_reads_to_end_of_line()
    {
        const string output =
            "Name         Id             Version   Available\n" +
            "-----------------------------------------------\n" +
            "Git          Git.Git        2.44      2.46\n";

        var update = Assert.Single(WingetUpdateService.ParseUpgradeOutput(output));
        Assert.Equal("2.46", update.AvailableVersion);
    }

    [Fact]
    public void ParseListOutput_stops_at_footer_and_handles_source_only_header()
    {
        const string output =
            "Name         Id             Version   Source\n" +
            "------------------------------------------\n" +
            "Git          Git.Git        2.44      winget\n" +
            "x\n" +
            "             \n" +
            "3 packages installed\n";

        var parsed = WingetUpdateService.ParseListOutput(output);

        var (id, version) = Assert.Single(parsed);
        Assert.Equal("Git.Git", id);
        Assert.Equal("2.44", version);
    }

    [Theory]
    [InlineData("")]
    [InlineData("pas de tableau")]
    [InlineData("Name   Version   Id\n---\n")]
    public void ParseListOutput_returns_empty_without_valid_header(string output) =>
        Assert.Empty(WingetUpdateService.ParseListOutput(output));

    [Fact]
    public void ParseListOutput_stops_on_numbered_footer_line()
    {
        const string output =
            "Nom          Id             Version\n" +
            "-----------------------------------\n" +
            "Git          Git.Git        2.44\n" +
            "1 paquet installé\n" +
            "Autre        Other.App      1.0\n";

        Assert.Single(WingetUpdateService.ParseListOutput(output));
    }

    [Fact]
    public void Argument_builders_target_exact_package()
    {
        var list = WingetUpdateService.BuildListPackageArguments("Git.Git");
        Assert.Contains("Git.Git", list);
        Assert.Contains("--exact", list);

        var all = WingetUpdateService.BuildUpgradeAllArguments();
        Assert.Contains("--all", all);
    }
}
