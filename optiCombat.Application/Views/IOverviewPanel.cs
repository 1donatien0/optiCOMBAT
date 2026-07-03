using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Views;

/// <summary>Méthodes de rafraîchissement bindées sur <see cref="OverviewControl"/>.</summary>
public interface IOverviewPanel
{
    void UpdateProtectionHeadline(bool isProtected, string? headline = null);

    void UpdateRecommendations(
        string hygieneLine,
        int hygieneSeverity,
        bool showSigUpdateLink = false);

    void UpdateSecurityPosture(SecurityPostureReport report);

    void UpdateSignaturesSummary(
        string yaraPackVer,
        string yaraLastMaj,
        string clamDbVer,
        string clamLastMaj);

    void UpdatePlatformProtectionStatus(PlatformProtectionStatusReport report);

    void UpdateAntivirusCardStatus(bool clamAvOk, int yaraRulesCount, string? clamEngineMode = null);

    void UpdateProtectionStatistics(IReadOnlyList<ScanSession> history);

    void UpdateLastScanSummary(ScanSession? lastSession);
}
