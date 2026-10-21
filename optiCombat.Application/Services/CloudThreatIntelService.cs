using optiCombat.Models;
using System.IO;

namespace optiCombat.Services;

/// <summary>Réputation cloud (VirusTotal) avec cache local pour enrichir la détection.</summary>
public sealed class CloudThreatIntelService
{
    private readonly IThreatReputationService _reputation;

    public CloudThreatIntelService(IThreatReputationService reputation) => _reputation = reputation;

    public async Task<string?> EnrichThreatAsync(ThreatInfo threat, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(threat.FilePath) || !File.Exists(threat.FilePath))
            return null;

        try
        {
            var report = await _reputation.LookupFileAsync(threat.FilePath, ct).ConfigureAwait(false);
            return report.Success ? report.Summary : null;
        }
        catch (Exception ex)
        {
            AppLogger.Warn("CloudThreatIntel", "EnrichThreatAsync", ex);
            return null;
        }
    }
}
