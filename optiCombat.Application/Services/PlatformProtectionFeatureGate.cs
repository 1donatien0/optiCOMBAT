namespace optiCombat.Services;

/// <summary>
/// Bascule produit pour la couche plateforme (service Windows + AMSI + minifilter noyau).
/// L'architecture reste dans le code ; l'activation utilisateur est reportée tant qu'un pilote
/// signé (EV + Microsoft Partner Center) n'est pas disponible — horizon 3 à 5 ans.
/// </summary>
public static class PlatformProtectionFeatureGate
{
    /// <summary>
    /// Quand <c>false</c>, l'utilisateur ne peut pas activer le mode plateforme (UI grisée).
    /// Mettre à <c>true</c> lorsque le pilote signé et l'installeur associé sont prêts.
    /// </summary>
    /// <remarks>
    /// <c>static readonly</c> (et non <c>const</c>) pour éviter CS0162 en Release :
    /// le compilateur ne doit pas éliminer le code de la phase 2 tant que le flag est à false.
    /// </remarks>
    public static readonly bool IsUserActivatable = false;

    /// <summary>Normalise les préférences si le mode plateforme n'est pas encore activable.</summary>
    public static void NormalizePreferences(UserPreferences prefs)
    {
        if (!IsUserActivatable && prefs.UsePlatformProtectionService)
        {
            prefs.UsePlatformProtectionService = false;
            prefs.Save();
        }
    }
}
