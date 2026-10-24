using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

[Collection("Localization")]
public sealed class ActivityEntryDisplayTests
{
    public ActivityEntryDisplayTests() => LocalizationService.ApplyCulture("fr-FR");

    private static readonly IReadOnlyDictionary<Guid, ScanSession> NoScans = new Dictionary<Guid, ScanSession>();

    [Fact]
    public void Clean_event_without_snapshot_uses_event_summaries()
    {
        var ev = new ActivityEventRecord
        {
            Kind = ActivityEventKind.CleanCompleted,
            OccurredAt = new DateTime(2026, 10, 1, 9, 30, 0),
            TargetSummary = "Temp",
            DetailSummary = "12 Mo",
            ResultSummary = "OK",
        };

        var entry = ActivityEntry.FromEvent(ev, NoScans)!;

        Assert.Equal(ActivityKind.Clean, entry.Kind);
        Assert.Equal(LocalizationService.GetString("Hist_TabCleans"), entry.TypeDisplay);
        Assert.Equal("Temp", entry.TargetDisplay);
        Assert.Equal("12 Mo", entry.DurationDisplay);
        Assert.Equal("Broom", entry.IconKind);
        Assert.Equal("TextAccent", entry.IconBrushKey);
        Assert.False(entry.IsClean);
        Assert.Empty(entry.Threats);
        Assert.Equal(0, entry.ThreatsFound);
        Assert.Equal(Guid.Empty, entry.ScanSessionId);
        Assert.Equal("01/10/2026 09:30", entry.DateDisplay);
    }

    [Theory]
    [InlineData(ActivityEventKind.ThreatQuarantined, "ShieldLock", "WarningOrange")]
    [InlineData(ActivityEventKind.ThreatRestored, "BackupRestore", "SuccessGreen")]
    [InlineData(ActivityEventKind.QuarantineDeleted, "TrashCanOutline", "DangerRed")]
    public void Quarantine_events_pick_icon_and_brush(ActivityEventKind kind, string icon, string brush)
    {
        var ev = new ActivityEventRecord
        {
            Kind = kind,
            OccurredAt = DateTime.Now,
            FilePath = @"C:\x\bad.exe",
            VirusName = "Win.Bad",
            QuarantineId = "q1",
        };

        var entry = ActivityEntry.FromEvent(ev, NoScans)!;

        Assert.Equal(ActivityKind.Quarantine, entry.Kind);
        Assert.Equal(icon, entry.IconKind);
        Assert.Equal(brush, entry.IconBrushKey);
        Assert.Contains("bad.exe", entry.ResultSummary);
    }

    [Fact]
    public void Quarantine_event_keeps_explicit_result_summary()
    {
        var ev = new ActivityEventRecord
        {
            Kind = ActivityEventKind.ThreatRestored,
            FilePath = @"C:\x\a.exe",
            ResultSummary = "Restauré manuellement",
        };

        Assert.Equal("Restauré manuellement", ActivityEntry.FromEvent(ev, NoScans)!.ResultSummary);
    }

    [Fact]
    public void Unknown_event_kind_is_ignored() =>
        Assert.Null(ActivityEntry.FromEvent(new ActivityEventRecord { Kind = (ActivityEventKind)42 }, NoScans));

    [Fact]
    public void Scan_entries_expose_threats_and_clean_state()
    {
        var session = new ScanSession { SessionId = Guid.NewGuid(), ThreatsFound = 1, StartedAt = DateTime.Now };
        session.Threats.Add(ThreatInfo.FromClamAv(@"C:\x\t.exe", "Win.T"));
        var threatEntry = new ActivityEntry { Kind = ActivityKind.Scan, HasThreats = true, ScanSession = session };
        var cleanEntry = new ActivityEntry { Kind = ActivityKind.Scan };

        Assert.Single(threatEntry.Threats);
        Assert.Equal(1, threatEntry.ThreatsFound);
        Assert.Equal(session.SessionId, threatEntry.ScanSessionId);
        Assert.Equal("ShieldAlert", threatEntry.IconKind);
        Assert.Equal("DangerRed", threatEntry.IconBrushKey);
        Assert.False(threatEntry.IsClean);

        Assert.True(cleanEntry.IsClean);
        Assert.Equal("ShieldCheck", cleanEntry.IconKind);
        Assert.Equal("SuccessGreen", cleanEntry.IconBrushKey);
    }
}

[Collection("OpticombatPrefs")]
public sealed class ExclusionSettingsIsolatedTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "opticombat_excl_" + Guid.NewGuid().ToString("N"));

    public ExclusionSettingsIsolatedTests() => OpticombatDataRoots.TestRootOverride = _root;

    public void Dispose()
    {
        OpticombatDataRoots.TestRootOverride = TestDataRoot.Session;
        try { Directory.Delete(_root, recursive: true); }
        catch { /* best effort */ }
    }

    [Fact]
    public void Rules_can_be_added_once_and_removed()
    {
        var settings = new ExclusionSettings();

        Assert.False(settings.AddRule(" "));
        Assert.True(settings.AddRule(" Custom_Rule "));
        Assert.False(settings.AddRule("custom_rule"));
        Assert.True(settings.IsRuleExcluded("CUSTOM_RULE"));

        Assert.True(settings.RemoveRule("Custom_Rule"));
        Assert.False(settings.RemoveRule("Custom_Rule"));
        Assert.False(settings.IsRuleExcluded("Custom_Rule"));
        Assert.True(File.Exists(Path.Combine(_root, "local", "exclusions.dat")));
    }

    [Fact]
    public void Load_from_empty_root_creates_defaults_with_protected_folders()
    {
        var loaded = ExclusionSettings.Load();

        Assert.True(loaded.RealTimeEnabled);
        Assert.Contains("SuspiciousDownloads", loaded.ExcludedRuleNames);
    }

    [Fact]
    public void Saved_settings_round_trip_through_secure_store()
    {
        var settings = new ExclusionSettings { AutoQuarantineEnabled = true };
        settings.ExcludedFilePaths.Add(@"C:\jeux\launcher.exe");
        settings.Save();

        var loaded = ExclusionSettings.Load();

        Assert.True(loaded.AutoQuarantineEnabled);
        Assert.Contains(@"C:\jeux\launcher.exe", loaded.ExcludedFilePaths);
    }

    [Fact]
    public void Preferences_round_trip_through_redirected_roaming_folder()
    {
        var prefs = new UserPreferences { ThemePresetId = "midnight", VirusTotalApiKey = "k" };
        prefs.Save();

        Assert.True(File.Exists(Path.Combine(_root, "roaming", "preferences.dat")));
        var loaded = UserPreferences.LoadFromStorage(
            Path.Combine(_root, "roaming", "preferences.dat"),
            Path.Combine(_root, "roaming", "preferences.json"));
        Assert.Equal("midnight", loaded.ThemePresetId);
    }
}
