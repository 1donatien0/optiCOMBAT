using optiCombat.Services;

namespace optiCombat.Tests;

/// <summary>
/// L'INF du minifiltre, l'installateur et <see cref="PlatformRegistration"/> doivent désigner
/// le même service (<c>optiCombatMinifilter</c>) et le même pilote (<c>optiCombat.Minifilter.sys</c>) :
/// sinon <c>fltmc load</c> et la copie du .sys ne portent pas sur le même objet.
///
/// La couche pilote est en phase 2 (pilote signé) : l'INF est un stub de classe ActivityMonitor,
/// sans altitude ni section de service — ces éléments ne sont donc pas vérifiés ici.
/// </summary>
public sealed class MinifilterRegistrationConsistencyTests
{
    private static string RepoFile(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "optiCombat.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return Path.Combine([dir!.FullName, .. parts]);
    }

    private static string Inf() =>
        File.ReadAllText(RepoFile("native", "optiCombat.Minifilter", "optiCombat.Minifilter.inf"));

    private static string Installer() => File.ReadAllText(RepoFile("installer", "setup.iss"));

    [Fact]
    public void Inf_declares_the_same_service_and_driver_file_as_the_code()
    {
        var inf = Inf();

        // [Standard.NTamd64] : %DeviceName%=<install-section>, <hardware id = nom du service>
        Assert.Matches(
            @"(?m)^\s*%DeviceName%\s*=\s*\S+\s*,\s*" + PlatformRegistration.MinifilterName + @"\s*$",
            inf);
        Assert.Contains(PlatformRegistration.MinifilterSysFileName, inf, StringComparison.Ordinal);
    }

    [Fact]
    public void Installer_unloads_the_same_service_and_installs_the_same_driver_file()
    {
        var iss = Installer();

        Assert.Contains("unload " + PlatformRegistration.MinifilterName, iss, StringComparison.Ordinal);
        Assert.Contains(PlatformRegistration.MinifilterSysFileName, iss, StringComparison.Ordinal);
    }

    [Fact]
    public void Inf_is_a_filesystem_activity_monitor_filter()
    {
        var inf = Inf();

        // Classe imposée pour un minifiltre de surveillance de système de fichiers.
        Assert.Matches(@"(?mi)^\s*Class\s*=\s*ActivityMonitor\s*$", inf);
        Assert.Matches(
            @"(?mi)^\s*ClassGuid\s*=\s*\{b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2\}\s*$",
            inf);
    }
}
