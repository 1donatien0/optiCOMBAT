namespace optiCombat.Views;

/// <summary>Onglet Signatures de <see cref="AntivirusView"/>.</summary>
public interface IAntivirusSignaturesPanel
{
    void UpdateSignaturesPanel(
        string yaraVersion,
        string yaraLastMaj,
        string clamVersion,
        string clamLastMaj);
}
