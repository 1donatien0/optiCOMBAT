using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.ViewModels;

namespace optiCombat.Tests;

[Collection(nameof(UserPreferencesStorageTests))]
public sealed class HistoryViewModelTests : IDisposable
{
    private readonly string _root;
    private readonly ScanLogManager _logger;
    private readonly ActivityLogService _activity;
    private readonly QuarantineManager _quarantine;
    private readonly HistoryViewModel _vm;
    private readonly Guid _threatSessionId = Guid.NewGuid();
    private readonly Guid _cleanSessionId = Guid.NewGuid();

    public HistoryViewModelTests()
    {
        LocalizationService.ApplyCulture("fr-FR");
        _root = Path.Combine(Path.GetTempPath(), "opticombat_hvm_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        _logger = new ScanLogManager(_root);
        _activity = new ActivityLogService(_logger, _root);
        _logger.BindActivityLog(_activity);
        _quarantine = new QuarantineManager(Path.Combine(_root, "q"));
        _vm = new HistoryViewModel(_activity, _quarantine, _logger);

        _logger.SaveScanResult(new ScanResult
        {
            SessionId = _threatSessionId,
            StartedAt = DateTime.Now.AddHours(-2),
            FinishedAt = DateTime.Now.AddHours(-2).AddMinutes(1),
            Type = ScanType.QuickScan,
            TargetPath = @"C:\Users\threats",
            Status = ScanStatus.Completed,
            FilesScanned = 8,
            Threats = { ThreatInfo.FromClamAv(@"C:\Users\threats\bad.exe", "Win.Test", 12) },
        });
        _logger.SaveScanResult(new ScanResult
        {
            SessionId = _cleanSessionId,
            StartedAt = DateTime.Now.AddHours(-1),
            FinishedAt = DateTime.Now.AddHours(-1).AddMinutes(1),
            Type = ScanType.FullScan,
            TargetPath = @"D:\clean",
            Status = ScanStatus.Completed,
            FilesScanned = 20,
        });
        _logger.SaveCleanSession(new CleanSession
        {
            StartedAt = DateTime.Now.AddMinutes(-20),
            FinishedAt = DateTime.Now.AddMinutes(-19),
            TargetsSummary = "Temp Windows",
            BytesFreed = 4096,
            OperationLog = "ok",
        });
        _vm.Refresh();
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
        LocalizationService.ApplyCulture("fr-FR");
    }

    [Fact]
    public void Refresh_counts_and_filters_all_activity_kinds()
    {
        Assert.Equal(3, _vm.CountAll);
        Assert.Equal(1, _vm.CountThreats);
        Assert.Equal(1, _vm.CountCleanScans);
        Assert.Equal(1, _vm.CountCleans);
        Assert.Contains("3", _vm.ChipAllLabel);
        Assert.False(string.IsNullOrWhiteSpace(_vm.ChipThreatsLabel));
        Assert.False(string.IsNullOrWhiteSpace(_vm.ChipCleanScansLabel));
        Assert.False(string.IsNullOrWhiteSpace(_vm.ChipCleansLabel));
        Assert.False(string.IsNullOrWhiteSpace(_vm.ChipQuarantineLabel));

        _vm.SelectedFilter = HistoryFilter.Threats;
        Assert.Single(_vm.FilteredEntries);
        Assert.True(_vm.ShowScanActions);
        Assert.True(_vm.CanExportPdf);
        Assert.False(string.IsNullOrWhiteSpace(_vm.DetailText));
        Assert.Contains("threats", _vm.SessionInfoText, StringComparison.OrdinalIgnoreCase);

        _vm.SelectedFilter = HistoryFilter.CleanScans;
        Assert.Single(_vm.FilteredEntries);
        Assert.False(_vm.ShowScanActions);
        Assert.Equal(LocalizationService.GetString("Hist_NoThreatsInSession"), _vm.DetailText);

        _vm.SelectedFilter = HistoryFilter.Cleans;
        Assert.Single(_vm.FilteredEntries);
        Assert.Equal("ok", _vm.CleanLogText);
        Assert.Contains("Temp", _vm.SessionInfoText);

        _vm.SelectedFilter = HistoryFilter.Quarantine;
        Assert.True(_vm.IsEmpty);
        Assert.False(string.IsNullOrWhiteSpace(_vm.EmptyTitle));
        Assert.False(string.IsNullOrWhiteSpace(_vm.EmptySubtitle));

        _vm.SelectedFilter = HistoryFilter.All;
        Assert.Equal(3, _vm.FilteredEntries.Count);
        _vm.SelectedFilter = HistoryFilter.All;
    }

    [Fact]
    public void Search_and_selection_cover_detail_properties()
    {
        _vm.SearchText = "Temp";
        Assert.Single(_vm.FilteredEntries);
        Assert.Equal(ActivityKind.Clean, _vm.SelectedEntry!.Kind);

        _vm.SearchText = "no-such-token-xyz";
        Assert.True(_vm.IsEmpty);
        Assert.Null(_vm.SelectedEntry);
        Assert.Equal(LocalizationService.GetString("Hist_SelectEntry"), _vm.DetailText);
        Assert.Equal(string.Empty, _vm.SessionInfoText);

        _vm.SearchText = default!;
        Assert.Equal(string.Empty, _vm.SearchText);
        _vm.SearchText = string.Empty;

        Assert.True(_vm.TrySelectScanSession(_threatSessionId));
        Assert.Equal(_threatSessionId, _vm.SelectedEntry!.ScanSessionId);
        Assert.False(_vm.TrySelectScanSession(Guid.Empty));
        Assert.False(_vm.TrySelectScanSession(Guid.NewGuid()));
        Assert.Null(_vm.FindScanSession(Guid.Empty));
        Assert.NotNull(_vm.FindScanSession(_cleanSessionId));
    }

    [Fact]
    public void Quarantine_selection_exposes_read_only_details()
    {
        var sample = Path.Combine(_root, "iso.bin");
        File.WriteAllBytes(sample, new byte[] { 1, 2 });
        var threat = new ThreatInfo { FilePath = sample, VirusName = "Iso.Virus", FileSize = 2 };
        Assert.True(_quarantine.Quarantine(threat));
        var entry = Assert.Single(_quarantine.GetEntries());
        _activity.RecordThreatQuarantined(entry, _threatSessionId);
        _vm.Refresh();

        _vm.SelectedFilter = HistoryFilter.Quarantine;
        Assert.Single(_vm.FilteredEntries);
        Assert.True(_vm.ShowQuarantineReadOnly);
        Assert.True(_vm.HasQuarantineSourceScan);
        Assert.Equal(_threatSessionId, _vm.SelectedQuarantineSourceScan!.SessionId);
        Assert.Equal("Iso.Virus", _vm.QuarantineDetailTitle);
        Assert.Equal(sample, _vm.QuarantineDetailPath);
        Assert.Contains("Iso.Virus", _vm.QuarantineDetailMeta);
        Assert.Contains("Quarantaine", _vm.SessionInfoText, StringComparison.OrdinalIgnoreCase);
        Assert.False(string.IsNullOrWhiteSpace(_vm.DetailText));
    }
}
