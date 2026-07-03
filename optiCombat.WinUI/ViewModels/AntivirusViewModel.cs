using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Strings;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace optiCombat.WinUI.ViewModels;

public sealed class AntivirusViewModel : INotifyPropertyChanged
{
    private readonly ServiceContainer _container;
    private readonly ScanOrchestrator _orchestrator;
    private readonly QuarantineManager _quarantine;
    private readonly RealTimeProtection _rtp;
    private readonly SignatureStatusService _signatureStatus;
    private readonly SignatureUpdateUiRunner _updateRunner = new();
    private CancellationTokenSource? _cts;
    private Guid _activeSessionId;

    private bool _isInitializing = true;
    private bool _isScanning;
    private bool _isUpdating;
    private string _statusMessage = LocalizationService.GetString("Scan_Ready");
    private string _currentScanItem = "";
    private int _filesScanned;
    private int _threatsFound;
    private int _quarantineCount;
    private string _protectionBadgeText = "";
    private ProtectionBadgeLevel _protectionBadgeLevel;
    private string _lastScanDisplay = LocalizationService.GetString("Av_NoScanYet");
    private string _yaraVersion = "—";
    private string _yaraLastUpdate = "—";
    private string _clamVersion = "—";
    private string _clamLastUpdate = "—";
    private string _signatureLog = "";

    public AntivirusViewModel(ServiceContainer container)
    {
        _container = container;
        _orchestrator = container.Orchestrator;
        _quarantine = container.Quarantine;
        _rtp = container.RealTimeProtection;
        _signatureStatus = container.SignatureStatus;
        Threats = new ObservableCollection<ThreatInfo>();
        QuarantineEntries = new ObservableCollection<QuarantineEntry>();
        _ = InitializeAsync();
    }

    public ObservableCollection<ThreatInfo> Threats { get; }
    public ObservableCollection<QuarantineEntry> QuarantineEntries { get; }

    public bool IsInitializing
    {
        get => _isInitializing;
        private set { _isInitializing = value; OnPropertyChanged(); }
    }

    public bool IsScanning
    {
        get => _isScanning;
        private set
        {
            _isScanning = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(CanScan));
            OnPropertyChanged(nameof(CanStop));
        }
    }

    public bool IsUpdating
    {
        get => _isUpdating;
        private set { _isUpdating = value; OnPropertyChanged(); }
    }

    public bool CanScan => !IsScanning;
    public bool CanStop => IsScanning;

    public string StatusMessage
    {
        get => _statusMessage;
        private set { _statusMessage = value; OnPropertyChanged(); }
    }

    public string CurrentScanItem
    {
        get => _currentScanItem;
        private set { _currentScanItem = value; OnPropertyChanged(); }
    }

    public int FilesScanned
    {
        get => _filesScanned;
        private set { _filesScanned = value; OnPropertyChanged(); }
    }

    public int ThreatsFound
    {
        get => _threatsFound;
        private set { _threatsFound = value; OnPropertyChanged(); }
    }

    public int QuarantineCount
    {
        get => _quarantineCount;
        private set { _quarantineCount = value; OnPropertyChanged(); }
    }

    public string ProtectionBadgeText
    {
        get => _protectionBadgeText;
        private set { _protectionBadgeText = value; OnPropertyChanged(); }
    }

    public ProtectionBadgeLevel ProtectionBadgeLevel
    {
        get => _protectionBadgeLevel;
        private set { _protectionBadgeLevel = value; OnPropertyChanged(); }
    }

    public string LastScanDisplay
    {
        get => _lastScanDisplay;
        private set { _lastScanDisplay = value; OnPropertyChanged(); }
    }

    public string YaraVersion
    {
        get => _yaraVersion;
        set { _yaraVersion = value; OnPropertyChanged(); }
    }

    public string YaraLastUpdate
    {
        get => _yaraLastUpdate;
        set { _yaraLastUpdate = value; OnPropertyChanged(); }
    }

    public string ClamVersion
    {
        get => _clamVersion;
        set { _clamVersion = value; OnPropertyChanged(); }
    }

    public string ClamLastUpdate
    {
        get => _clamLastUpdate;
        set { _clamLastUpdate = value; OnPropertyChanged(); }
    }

    public string SignatureLog
    {
        get => _signatureLog;
        private set { _signatureLog = value; OnPropertyChanged(); }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public async Task InitializeAsync()
    {
        IsInitializing = true;
        try
        {
            RefreshProtectionBadge();
            RefreshLastScan();
            LoadQuarantine();
            await RefreshSignaturesAsync().ConfigureAwait(false);
        }
        finally
        {
            IsInitializing = false;
        }
    }

    public async Task RefreshSignaturesAsync(bool force = false)
    {
        var snapshot = await _signatureStatus.GetSnapshotAsync(force).ConfigureAwait(true);
        YaraVersion = snapshot.YaraPackVersion;
        YaraLastUpdate = snapshot.YaraLastUpdateDisplay;
        ClamVersion = VersionDisplayHelper.NormalizeForDisplay(snapshot.ClamDatabaseVersion);
        ClamLastUpdate = snapshot.ClamLastUpdateDisplay;
    }

    public void RefreshProtectionBadge()
    {
        var level = ProtectionStatusEvaluator.Evaluate(
            _container.ClamAv.IsClamAvInstalled(),
            _container.Yara.IsAvailable,
            _container.Yara.RulesCount,
            _container.ExclusionSettingsAccessor.Current.RealTimeEnabled,
            _rtp.IsEnabled || PlatformProtectionBootstrap.IsRemoteProtectionActive());
        ProtectionBadgeLevel = level;
        ProtectionBadgeText = ProtectionStatusEvaluator.GetBadgeText(level);
    }

    public void RefreshLastScan()
    {
        var history = _container.Logger.GetHistory();
        var last = history.Count == 0
            ? null
            : history.OrderByDescending(s => s.StartedAt).First();
        LastScanDisplay = last == null
            ? LocalizationService.GetString("Av_NoScanYet")
            : ScanLastScanDisplay.FormatDetailed(last);
    }

    public void LoadQuarantine()
    {
        QuarantineEntries.Clear();
        foreach (var entry in _quarantine.GetEntries().Take(50))
            QuarantineEntries.Add(entry);
        QuarantineCount = _quarantine.Count;
    }

    public async Task QuickScanAsync() => await StartScanAsync(ScanType.QuickScan).ConfigureAwait(true);
    public async Task FullScanAsync() => await StartScanAsync(ScanType.FullScan).ConfigureAwait(true);
    public async Task ScanFolderAsync(string path) => await StartScanAsync(ScanType.Folder, path).ConfigureAwait(true);
    public async Task ScanFileAsync(string path) => await StartScanAsync(ScanType.File, path).ConfigureAwait(true);

    public async Task RequestContextMenuScanAsync(string path)
    {
        if (!ShellScanArguments.IsValidScanTarget(path))
        {
            StatusMessage = LocalizationService.Format("ShellScan_InvalidPath", path);
            return;
        }

        var type = ShellScanArguments.ResolveScanType(path);
        await StartScanAsync(type, path).ConfigureAwait(true);
    }

    public void StopScan() => _cts?.Cancel();

    public async Task UpdateSignaturesAsync()
    {
        if (IsUpdating || !_updateRunner.TryEnterUpdate())
        {
            StatusMessage = OpticombatStrings.StatusUpdates.SignaturesUpdateAlreadyRunning;
            return;
        }

        IsUpdating = true;
        AppendSignatureLog(OpticombatStrings.StatusUpdates.FullSignaturesUpdateStarting);

        var completedOk = true;
        try
        {
            completedOk = await _updateRunner.RunFullUpdateAsync(
                _container.FreshclamUpdater,
                _container.RulesUpdater,
                AppendSignatureLog).ConfigureAwait(true);

            _signatureStatus.InvalidateCache();
            await RefreshSignaturesAsync(force: true).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            completedOk = false;
            AppendSignatureLog(UiLogText.Error($"Erreur : {ex.Message}"));
            StatusMessage = LocalizationService.Format("Status_UpdateError", ex.Message);
        }
        finally
        {
            IsUpdating = false;
            StatusMessage = completedOk
                ? OpticombatStrings.StatusUpdates.FullSignaturesUpdateFinished
                : OpticombatStrings.StatusUpdates.FullSignaturesUpdateFinishedWithErrors;
            RefreshProtectionBadge();
            _updateRunner.ReleaseUpdate();
        }
    }

    public void QuarantineAllThreats()
    {
        if (Threats.Count == 0)
            return;
        var count = _quarantine.QuarantineAll(Threats.ToList(), _activeSessionId);
        StatusMessage = LocalizationService.Format("Vm_QuarantineBatch", count);
        Threats.Clear();
        ThreatsFound = 0;
        LoadQuarantine();
    }

    public void RestoreQuarantineEntry(string? id)
    {
        if (string.IsNullOrWhiteSpace(id))
            return;
        if (_quarantine.Restore(id))
        {
            LoadQuarantine();
            StatusMessage = LocalizationService.GetString("Ui_RestoreOk");
        }
    }

    public void DeleteQuarantineEntry(string? id)
    {
        if (string.IsNullOrWhiteSpace(id))
            return;
        if (_quarantine.DeletePermanently(id))
        {
            LoadQuarantine();
            StatusMessage = LocalizationService.GetString("Vm_DeleteOk");
        }
    }

    private async Task StartScanAsync(ScanType type, string? path = null)
    {
        if (IsScanning)
            return;

        IsScanning = true;
        Threats.Clear();
        FilesScanned = 0;
        ThreatsFound = 0;
        CurrentScanItem = ScanUserDisplay.Preparation;
        StatusMessage = type == ScanType.FullScan && !ElevationHelper.IsRunningElevated()
            ? LocalizationService.GetString("Scan_FullPartialWithoutAdmin")
            : ScanUserDisplay.ScanStarting(type, path);

        _activeSessionId = Guid.NewGuid();
        _cts = new CancellationTokenSource();
        var progress = new Progress<ScanProgress>(p =>
        {
            if (p.FilesScanned > 0)
                FilesScanned = Math.Max(FilesScanned, p.FilesScanned);
            if (p.ThreatsFound > 0)
                ThreatsFound = Math.Max(ThreatsFound, p.ThreatsFound);

            if (!string.IsNullOrWhiteSpace(p.CurrentFilePath))
                CurrentScanItem = p.CurrentFilePath;
            else if (p.ThreatInfo != null && !string.IsNullOrWhiteSpace(p.ThreatInfo.FilePath))
                CurrentScanItem = p.ThreatInfo.FilePath;

            StatusMessage = FilesScanned > 0
                ? LocalizationService.Format("Scan_FilesProgress", FilesScanned)
                : LocalizationService.GetString("Scan_InProgress");
        });

        _rtp.Suspend();
        try
        {
            ScanResult result = type switch
            {
                ScanType.QuickScan => await _orchestrator.QuickScanAsync(progress, _cts.Token).ConfigureAwait(true),
                ScanType.FullScan => await _orchestrator.FullScanAsync(progress, _cts.Token).ConfigureAwait(true),
                ScanType.Folder => await _orchestrator.ScanFolderAsync(path!, progress, _cts.Token).ConfigureAwait(true),
                ScanType.File => await _orchestrator.ScanFileAsync(path!, progress, _cts.Token).ConfigureAwait(true),
                _ => throw new InvalidOperationException()
            };

            result.SessionId = _activeSessionId;
            _container.Logger.SaveScanResult(result);

            var prefs = _container.UserPreferencesAccessor.Current;
            prefs.FavoriteScanType = type;
            if (type is ScanType.File or ScanType.Folder && !string.IsNullOrWhiteSpace(path))
                prefs.AddRecentTarget(path, type);
            else if (type is ScanType.QuickScan or ScanType.FullScan)
                prefs.AddRecentTarget(string.Empty, type);
            prefs.IncrementScanCount(type);
            prefs.Save();

            Threats.Clear();
            foreach (var threat in result.Threats)
                Threats.Add(threat);

            if (_container.ExclusionSettingsAccessor.Current.AutoQuarantineEnabled && result.Threats.Count > 0)
            {
                var q = _quarantine.QuarantineAll(result.Threats, result.SessionId);
                if (q > 0)
                    LoadQuarantine();
            }

            FilesScanned = result.FilesScanned;
            ThreatsFound = result.Threats.Count;
            StatusMessage = result.SummaryDisplay;
            RefreshLastScan();
            RefreshProtectionBadge();

            if (_container.UserPreferencesAccessor.Current.ActionNotificationsEnabled)
                _container.Notifications.ShowScanCompleted(result.Threats.Count, result.FilesScanned);
        }
        catch (OperationCanceledException)
        {
            StatusMessage = OpticombatStrings.UiMessages.AnalyseInterrompueSurDemande;
        }
        catch (Exception ex)
        {
            StatusMessage = LocalizationService.Format("Vm_ScanError", ex.Message);
        }
        finally
        {
            IsScanning = false;
            CurrentScanItem = "";
            _cts?.Dispose();
            _cts = null;
            _rtp.Resume();
        }
    }

    private void AppendSignatureLog(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return;
        SignatureLog = string.IsNullOrEmpty(SignatureLog) ? line : SignatureLog + Environment.NewLine + line;
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
