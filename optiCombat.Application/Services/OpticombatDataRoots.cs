namespace optiCombat.Services;

/// <summary>
/// Racines des données utilisateur (<c>%APPDATA%\optiCombat</c> et <c>%LOCALAPPDATA%\optiCombat</c>).
/// <see cref="TestRootOverride"/> redirige les deux vers un dossier temporaire : réservé aux tests
/// (<c>internal</c>), pour qu'aucun test n'écrase les préférences réelles du poste.
/// </summary>
internal static class OpticombatDataRoots
{
    private const string AppFolder = "optiCombat";

    /// <summary>Tests uniquement — <c>null</c> en production.</summary>
    internal static string? TestRootOverride { get; set; }

    /// <summary>Fichier sous <c>%APPDATA%\optiCombat</c> (préférences).</summary>
    internal static string RoamingFile(string fileName) => Path.Combine(
        TestRootOverride is { } root
            ? Path.Combine(root, "roaming")
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), AppFolder),
        fileName);

    /// <summary>Fichier sous <c>%LOCALAPPDATA%\optiCombat</c> (exclusions).</summary>
    internal static string LocalFile(string fileName) => Path.Combine(
        TestRootOverride is { } root
            ? Path.Combine(root, "local")
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), AppFolder),
        fileName);
}
