using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;

namespace optiCombat.ViewModels;

public enum HistoryFilter
{
    All,
    Threats,
    CleanScans,
    Cleans,
    Quarantine,
}

/// <summary>ViewModel partagé de la page Historique — filtres, compteurs, sélection.</summary>
public sealed class HistoryViewModel : INotifyPropertyChanged
{
    private readonly ActivityLogService _activityLog;
    private readonly QuarantineManager _quarantine;
    private readonly ScanLogManager _logger;

    private List<ActivityEntry> _allFeed = new();
    private HistoryFilter _selectedFilter = HistoryFilter.All;
    private string _searchText = string.Empty;
    private ActivityEntry? _selectedEntry;
    private object? _selectionKey;

    public HistoryViewModel(IHistoryServices services)
        : this(services.ActivityLog, services.Quarantine, services.Logger)
    {
    }

    public HistoryViewModel(ServiceContainer container)
        : this((IHistoryServices)container)
    {
    }

    internal HistoryViewModel(ActivityLogService activityLog, QuarantineManager quarantine, ScanLogManager logger)
    {
        _activityLog = activityLog;
        _quarantine = quarantine;
        _logger = logger;
        FilteredEntries = new ObservableCollection<ActivityEntry>();
    }

    public ObservableCollection<ActivityEntry> FilteredEntries { get; }

    public HistoryFilter SelectedFilter
    {
        get => _selectedFilter;
        set
        {
            if (_selectedFilter == value) return;
            _selectedFilter = value;
            OnPropertyChanged();
            ApplyFilters();
            UpdateEmptyState();
        }
    }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (_searchText == value) return;
            _searchText = value ?? string.Empty;
            OnPropertyChanged();
            ApplyFilters();
            UpdateEmptyState();
        }
    }

    public ActivityEntry? SelectedEntry
    {
        get => _selectedEntry;
        set
        {
            _selectedEntry = value;
            _selectionKey = value != null ? SelectionKey(value) : null;
            OnPropertyChanged();
            OnPropertyChanged(nameof(CanExportPdf));
            OnPropertyChanged(nameof(ShowScanActions));
            OnPropertyChanged(nameof(ShowQuarantineReadOnly));
            OnPropertyChanged(nameof(SelectedQuarantineSourceScan));
            OnPropertyChanged(nameof(HasQuarantineSourceScan));
            OnPropertyChanged(nameof(DetailText));
            OnPropertyChanged(nameof(SessionInfoText));
            OnPropertyChanged(nameof(CleanLogText));
            OnPropertyChanged(nameof(QuarantineDetailTitle));
            OnPropertyChanged(nameof(QuarantineDetailPath));
            OnPropertyChanged(nameof(QuarantineDetailMeta));
        }
    }

    public bool CanExportPdf =>
        SelectedEntry?.Kind == ActivityKind.Scan && SelectedEntry.ScanSession != null;

    public bool ShowScanActions =>
        SelectedEntry?.Kind == ActivityKind.Scan && SelectedEntry.HasPendingThreats;

    public bool ShowQuarantineReadOnly =>
        SelectedEntry?.Kind == ActivityKind.Quarantine;

    public ScanSession? SelectedQuarantineSourceScan
    {
        get
        {
            var sessionId = SelectedEntry?.QuarantineEntry?.SourceSessionId;
            return sessionId is { } id && id != Guid.Empty
                ? FindScanSession(id)
                : null;
        }
    }

    public bool HasQuarantineSourceScan => SelectedQuarantineSourceScan != null;

    public bool IsEmpty => FilteredEntries.Count == 0;

    public string EmptyTitle { get; private set; } = string.Empty;
    public string EmptySubtitle { get; private set; } = string.Empty;

    public string ChipAllLabel => FormatChip("Hist_ChipAll", CountAll);
    public string ChipThreatsLabel => FormatChip("Hist_ChipThreats", CountThreats);
    public string ChipCleanScansLabel => FormatChip("Hist_ChipClean", CountCleanScans);
    public string ChipCleansLabel => FormatChip("Hist_ChipSweep", CountCleans);
    public string ChipQuarantineLabel => FormatChip("Hist_ChipQuarantine", CountQuarantine);

    public int CountAll { get; private set; }
    public int CountThreats { get; private set; }
    public int CountCleanScans { get; private set; }
    public int CountCleans { get; private set; }
    public int CountQuarantine { get; private set; }

    public string DetailText
    {
        get
        {
            if (SelectedEntry == null)
                return LocalizationService.GetString("Hist_SelectEntry");

            return SelectedEntry.Kind switch
            {
                ActivityKind.Scan when !SelectedEntry.HasPendingThreats =>
                    LocalizationService.GetString("Hist_NoThreatsInSession"),
                ActivityKind.Scan => SelectedEntry.ResultSummary,
                ActivityKind.Clean => SelectedEntry.ResultSummary,
                ActivityKind.Quarantine => SelectedEntry.ResultSummary,
                _ => SelectedEntry.ResultSummary
            };
        }
    }

    public string SessionInfoText
    {
        get
        {
            var entry = SelectedEntry;
            if (entry == null) return string.Empty;
            return entry.Kind switch
            {
                ActivityKind.Scan => $"{entry.TypeDisplay} · {entry.TargetDisplay} · {entry.DetailDisplay}",
                ActivityKind.Clean => $"{entry.TargetDisplay} · {entry.DetailDisplay}",
                ActivityKind.Quarantine => $"{entry.TypeDisplay} · {entry.StartedAt:g}",
                _ => entry.TypeDisplay
            };
        }
    }

    public string CleanLogText => SelectedEntry?.CleanSession?.OperationLog ?? string.Empty;

    public string QuarantineDetailTitle =>
        SelectedEntry?.QuarantineEntry?.VirusName ?? SelectedEntry?.TargetDisplay ?? string.Empty;

    public string QuarantineDetailPath =>
        SelectedEntry?.QuarantineEntry?.OriginalPath ?? SelectedEntry?.TargetDisplay ?? string.Empty;

    public string QuarantineDetailMeta
    {
        get
        {
            var q = SelectedEntry?.QuarantineEntry;
            if (q == null) return string.Empty;
            return LocalizationService.Format("Hist_InfoQuarantined", q.VirusName, Path.GetFileName(q.OriginalPath));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public void Refresh()
    {
        var keepKey = _selectionKey;
        _logger.ReconcileQuarantinedThreats(_quarantine.GetEntries());
        _allFeed = _activityLog.GetActivityFeed(_quarantine).ToList();
        UpdateCounts();
        _selectionKey = keepKey;
        ApplyFilters();
        UpdateEmptyState();
        OnPropertyChanged(nameof(SelectedQuarantineSourceScan));
        OnPropertyChanged(nameof(HasQuarantineSourceScan));
    }

    public ScanSession? FindScanSession(Guid sessionId)
    {
        if (sessionId == Guid.Empty) return null;
        var fromFeed = _allFeed.FirstOrDefault(e => e.ScanSession?.SessionId == sessionId)?.ScanSession;
        if (fromFeed != null) return fromFeed;
        return _logger.GetHistory().FirstOrDefault(s => s.SessionId == sessionId);
    }

    public bool TrySelectScanSession(Guid sessionId)
    {
        if (sessionId == Guid.Empty || FindScanSession(sessionId) == null)
            return false;

        _selectionKey = sessionId;
        if (SelectedFilter != HistoryFilter.All)
            SelectedFilter = HistoryFilter.All;
        else
            ApplyFilters();
        return SelectedEntry?.ScanSession?.SessionId == sessionId;
    }

    public void ApplyFilters()
    {
        IEnumerable<ActivityEntry> query = _allFeed;

        query = SelectedFilter switch
        {
            HistoryFilter.Threats => query.Where(e => e.Kind == ActivityKind.Scan && e.HasPendingThreats),
            HistoryFilter.CleanScans => query.Where(e => e.Kind == ActivityKind.Scan && !e.HasThreats),
            HistoryFilter.Cleans => query.Where(e => e.Kind == ActivityKind.Clean),
            HistoryFilter.Quarantine => query.Where(e => e.Kind == ActivityKind.Quarantine),
            _ => query,
        };

        var search = SearchText.Trim();
        if (search.Length > 0)
        {
            query = query.Where(e =>
                (e.TypeDisplay?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false)
                || (e.ResultSummary?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false)
                || (e.TargetDisplay?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false)
                || (e.ScanSession?.TargetPath?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false)
                || (e.CleanSession?.TargetsSummary?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false)
                || (e.QuarantineEntry?.OriginalPath?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false)
                || (e.QuarantineEntry?.VirusName?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false));
        }

        var list = query.ToList();
        FilteredEntries.Clear();
        foreach (var item in list)
            FilteredEntries.Add(item);

        OnPropertyChanged(nameof(IsEmpty));

        if (list.Count == 0)
        {
            SelectedEntry = null;
            return;
        }

        var idx = FindSelectionIndex(list);
        SelectedEntry = list[idx >= 0 ? idx : 0];
    }

    public QuarantineEntry? FindLiveQuarantine(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return null;
        return _quarantine.GetEntries()
            .FirstOrDefault(e => string.Equals(e.OriginalPath, filePath, StringComparison.OrdinalIgnoreCase));
    }

    public bool IsFileStillQuarantined(string filePath) => FindLiveQuarantine(filePath) != null;

    public bool IsThreatFileAccessible(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return false;
        try
        {
            var root = Path.GetPathRoot(filePath);
            if (!string.IsNullOrEmpty(root) && root.Length >= 2 && !Directory.Exists(root))
                return false;
            return File.Exists(filePath);
        }
        catch
        {
            return false;
        }
    }

    public IReadOnlyList<HistoryThreatRow> BuildThreatRows(IEnumerable<ThreatInfo> threats) =>
        threats.Select(t => new HistoryThreatRow(t, this)).ToList();

    private void UpdateCounts()
    {
        CountAll = _allFeed.Count;
        CountThreats = _allFeed.Count(e => e.Kind == ActivityKind.Scan && e.HasPendingThreats);
        CountCleanScans = _allFeed.Count(e => e.Kind == ActivityKind.Scan && !e.HasThreats);
        CountCleans = _allFeed.Count(e => e.Kind == ActivityKind.Clean);
        CountQuarantine = _allFeed.Count(e => e.Kind == ActivityKind.Quarantine);

        OnPropertyChanged(nameof(ChipAllLabel));
        OnPropertyChanged(nameof(ChipThreatsLabel));
        OnPropertyChanged(nameof(ChipCleanScansLabel));
        OnPropertyChanged(nameof(ChipCleansLabel));
        OnPropertyChanged(nameof(ChipQuarantineLabel));
    }

    private void UpdateEmptyState()
    {
        var (titleKey, subKey) = SelectedFilter switch
        {
            HistoryFilter.Threats => ("Hist_EmptyThreats", "Hist_EmptyThreatsSub"),
            HistoryFilter.CleanScans => ("Hist_EmptyCleanScans", "Hist_EmptyCleanScansSub"),
            HistoryFilter.Cleans => ("Hist_EmptySweep", "Hist_EmptySweepSub"),
            HistoryFilter.Quarantine => ("Hist_EmptyQuarantine", "Hist_EmptyQuarantineSub"),
            _ => ("Hist_EmptyAll", "Hist_EmptyAllSub"),
        };
        EmptyTitle = LocalizationService.GetString(titleKey);
        EmptySubtitle = LocalizationService.GetString(subKey);
        OnPropertyChanged(nameof(EmptyTitle));
        OnPropertyChanged(nameof(EmptySubtitle));
        OnPropertyChanged(nameof(IsEmpty));
    }

    private int FindSelectionIndex(IReadOnlyList<ActivityEntry> list)
    {
        if (_selectionKey == null) return -1;
        for (int i = 0; i < list.Count; i++)
        {
            if (Equals(SelectionKey(list[i]), _selectionKey))
                return i;
        }
        return -1;
    }

    private static object SelectionKey(ActivityEntry entry) => entry.Kind switch
    {
        ActivityKind.Scan => (object)(entry.ScanSession?.SessionId ?? Guid.Empty),
        _ => entry.EventId,
    };

    private static string FormatChip(string key, int count) =>
        count > 0
            ? $"{LocalizationService.GetString(key)} ({count})"
            : LocalizationService.GetString(key);

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
