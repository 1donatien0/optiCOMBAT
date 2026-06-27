using optiCombat.Services;

namespace optiCombat.Tests;

/// <summary>
/// Tests unitaires pour <see cref="OverviewRecommendationsBuilder"/>.
/// Logique pure — aucune dépendance UI ou fichier.
/// UserPreferences est muté par test (defaults restaurés via IDisposable).
/// </summary>
[CollectionDefinition(nameof(OverviewRecommendationsBuilderTests), DisableParallelization = true)]
public sealed class OverviewRecommendationsBuilderTestsCollection;

[Collection(nameof(OverviewRecommendationsBuilderTests))]
public sealed class OverviewRecommendationsBuilderTests : IDisposable
{
    // Sauvegarde les seuils pour restauration après chaque test.
    private readonly int _origClean;
    private readonly int _origSig;
    private readonly bool _origAutoUpdate;

    public OverviewRecommendationsBuilderTests()
    {
        _origClean = UserPreferences.Current.CleanSuggestThresholdDays;
        _origSig = UserPreferences.Current.SignatureStaleThresholdDays;
        _origAutoUpdate = UserPreferences.Current.SignatureAutoUpdateEnabled;
    }

    public void Dispose()
    {
        UserPreferences.Current.CleanSuggestThresholdDays = _origClean;
        UserPreferences.Current.SignatureStaleThresholdDays = _origSig;
        UserPreferences.Current.SignatureAutoUpdateEnabled = _origAutoUpdate;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static OverviewRecommendationsBuilder.Context BaseContext(
        bool clam = true,
        DateTime? lastFreshclam = null,
        DateTime? lastClean = null) =>
        new()
        {
            ClamInstalled = clam,
            LastFreshclamUpdate = lastFreshclam,
            LastCleanAt = lastClean,
        };

    // ── Hygiène : ClamAV manquant ─────────────────────────────────────────────

    [Fact]
    public void Hygiene_ClamMissing_when_clam_not_installed()
    {
        var r = OverviewRecommendationsBuilder.Build(BaseContext(clam: false));

        Assert.Equal(1, r.HygieneSeverity);
        Assert.False(r.ShowSigUpdateLink);
        Assert.Contains("ClamAV", r.HygieneLine, StringComparison.OrdinalIgnoreCase);
    }

    // ── Hygiène : signatures jamais mises à jour ──────────────────────────────

    [Fact]
    public void Hygiene_SigNeverUpdated_when_no_local_signature_database()
    {
        var r = OverviewRecommendationsBuilder.Build(BaseContext(clam: true, lastFreshclam: null));

        Assert.Equal(1, r.HygieneSeverity);
        Assert.True(r.ShowSigUpdateLink);
    }

    [Fact]
    public void Hygiene_no_SigNeverUpdated_when_local_cvd_present_without_freshclam_session()
    {
        // Simule des bases livrées par l'installateur (date fichier récente, LastUpdateTime null).
        var r = OverviewRecommendationsBuilder.Build(BaseContext(
            clam: true,
            lastFreshclam: DateTime.Now.AddDays(-2),
            lastClean: DateTime.Now.AddDays(-1)));

        Assert.False(r.ShowSigUpdateLink);
        Assert.DoesNotContain("jamais", r.HygieneLine, StringComparison.OrdinalIgnoreCase);
    }

    // ── Hygiène : signatures obsolètes ───────────────────────────────────────

    [Fact]
    public void Hygiene_SigStale_when_freshclam_older_than_threshold()
    {
        UserPreferences.Current.SignatureStaleThresholdDays = 7;
        var staleDate = DateTime.Now.AddDays(-10);

        var r = OverviewRecommendationsBuilder.Build(BaseContext(clam: true, lastFreshclam: staleDate));

        Assert.Equal(1, r.HygieneSeverity);
        Assert.True(r.ShowSigUpdateLink);
        Assert.Contains("7", r.HygieneLine); // le seuil configuré apparaît dans le message
    }

    [Fact]
    public void Hygiene_no_SigStale_when_freshclam_recent()
    {
        UserPreferences.Current.SignatureStaleThresholdDays = 7;
        UserPreferences.Current.SignatureAutoUpdateEnabled = true;
        var recentDate = DateTime.Now.AddDays(-3);

        var r = OverviewRecommendationsBuilder.Build(BaseContext(
            clam: true,
            lastFreshclam: recentDate,
            lastClean: DateTime.Now.AddDays(-1)));

        // Signatures récentes + nettoyage récent → vert
        Assert.Equal(0, r.HygieneSeverity);
        Assert.False(r.ShowSigUpdateLink);
    }

    // ── Hygiène : MAJ auto désactivée ────────────────────────────────────────

    [Fact]
    public void Hygiene_SigAutoOff_when_auto_update_disabled_and_sigs_fresh()
    {
        UserPreferences.Current.SignatureStaleThresholdDays = 7;
        UserPreferences.Current.SignatureAutoUpdateEnabled = false;
        var recentDate = DateTime.Now.AddDays(-2);

        var r = OverviewRecommendationsBuilder.Build(BaseContext(
            clam: true,
            lastFreshclam: recentDate,
            lastClean: DateTime.Now.AddDays(-1)));

        Assert.Equal(3, r.HygieneSeverity); // conseil bleu
        Assert.False(r.ShowSigUpdateLink);
    }

    // ── Hygiène : priorité ClamAV > SigNeverUpdated ──────────────────────────

    [Fact]
    public void Hygiene_ClamMissing_takes_priority_over_SigNeverUpdated()
    {
        var r = OverviewRecommendationsBuilder.Build(BaseContext(clam: false, lastFreshclam: null));

        // ClamAV manquant doit primer sur "jamais mis à jour"
        Assert.False(r.ShowSigUpdateLink);
        Assert.Contains("ClamAV", r.HygieneLine, StringComparison.OrdinalIgnoreCase);
    }

    // ── Hygiène : suggestion nettoyage ───────────────────────────────────────

    [Fact]
    public void Hygiene_CleanSuggest_when_never_cleaned_and_sigs_ok()
    {
        UserPreferences.Current.CleanSuggestThresholdDays = 14;
        UserPreferences.Current.SignatureStaleThresholdDays = 7;
        UserPreferences.Current.SignatureAutoUpdateEnabled = true;
        var recentSig = DateTime.Now.AddDays(-2);

        var r = OverviewRecommendationsBuilder.Build(BaseContext(
            clam: true,
            lastFreshclam: recentSig,
            lastClean: null)); // jamais nettoyé

        Assert.Equal(1, r.HygieneSeverity);
        Assert.False(r.ShowSigUpdateLink);
    }

    [Fact]
    public void Hygiene_CleanRecent_when_cleaned_within_threshold()
    {
        UserPreferences.Current.CleanSuggestThresholdDays = 14;
        UserPreferences.Current.SignatureStaleThresholdDays = 7;
        UserPreferences.Current.SignatureAutoUpdateEnabled = true;
        var recentSig = DateTime.Now.AddDays(-2);
        var recentClean = DateTime.Now.AddDays(-5);

        var r = OverviewRecommendationsBuilder.Build(BaseContext(
            clam: true,
            lastFreshclam: recentSig,
            lastClean: recentClean));

        Assert.Equal(0, r.HygieneSeverity);
        Assert.False(r.ShowSigUpdateLink);
    }

    // ── Seuils personnalisés ─────────────────────────────────────────────────

    [Fact]
    public void Custom_sig_threshold_respected()
    {
        UserPreferences.Current.SignatureStaleThresholdDays = 3;
        var sigDate = DateTime.Now.AddDays(-4); // > 3 jours → obsolète

        var r = OverviewRecommendationsBuilder.Build(BaseContext(clam: true, lastFreshclam: sigDate));

        Assert.Equal(1, r.HygieneSeverity);
        Assert.True(r.ShowSigUpdateLink);
        Assert.Contains("3", r.HygieneLine);
    }

    [Fact]
    public void Custom_clean_threshold_respected()
    {
        UserPreferences.Current.CleanSuggestThresholdDays = 30;
        UserPreferences.Current.SignatureStaleThresholdDays = 7;
        UserPreferences.Current.SignatureAutoUpdateEnabled = true;
        var recentSig = DateTime.Now.AddDays(-1);
        var cleanDate = DateTime.Now.AddDays(-20); // < 30 jours → pas de suggestion

        var r = OverviewRecommendationsBuilder.Build(BaseContext(
            clam: true, lastFreshclam: recentSig, lastClean: cleanDate));

        Assert.Equal(0, r.HygieneSeverity);
    }
}
