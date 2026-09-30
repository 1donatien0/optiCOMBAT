namespace optiCombat.Coordinators;

/// <summary>Identifiants des sections de la fenêtre principale et clés de libellé associées.</summary>
public static class ShellSections
{
    public const string Overview = "overview";
    public const string Clean = "clean";
    public const string Antivirus = "antivirus";
    public const string History = "history";
    public const string Options = "options";

    /// <summary>Clé <c>UiStrings</c> du libellé de navigation (Accueil par défaut).</summary>
    public static string NavLabelKey(string? tag) => tag switch
    {
        Clean => "Nav_Clean",
        Antivirus => "Nav_Antivirus",
        History => "Nav_History",
        Options => "Nav_Options",
        _ => "Nav_Home",
    };

    /// <summary>Normalise un tag inconnu vers l'accueil.</summary>
    public static string Normalize(string? tag) => tag switch
    {
        Clean or Antivirus or History or Options => tag,
        _ => Overview,
    };
}
