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
        RecentTargets = new ObservableCollection<RecentScanTarget>();
        _ = InitializeAsync();
    }

    public ObservableCollection<ThreatInfo> Threats { get; }
    public ObservableCollection<QuarantineEntry> QuarantineEntries { get; }

    /// <summary>Dernières cibles analysées (puces « Récents » de l'onglet Analyse).</summary>
    public ObservableCollection<RecentScanTarget> RecentTargets { get; }

    /// <summary>Identifiant de la session en cours (Guid.Empty hors analyse) — rattache les actions aux menaces de cette session.</summary>
    public Guid ActiveScanSessionId => IsScanning ? _activeSessionId : Guid.Empty;

    private const int QuarantinePageSize = 200;
    private int _quarantineTotalCount;

    /// <summary>Nombre total d'éléments en quarantaine (la liste affichée est paginée).</summary>
    public int QuarantineTotalCount
    {
        get => _quarantineTotalCount;
        private set { _quarantineTotalCount = value; OnPropertyChanged(); OnPropertyChanged(nameof(QuarantineCount)); }
    }

    public bool QuarantineHasMore => QuarantineTotalCount > 0 && QuarantineEntries.Count < QuarantineTotalCount;

    public string QuarantinePagingStatus
    {
        get
        {
            if (QuarantineTotalCount == 0)
                return string.Empty;
            return QuarantineHasMore
                ? LocalizationService.Format("Vm_QuarantinePartial", QuarantineEntries.Count, QuarantineTotalCount)
                : LocalizationService.Format("Vm_QuarantineAllShown", QuarantineTotalCount);
        }
    }

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
        private set { _isUpdating = value; OnPropertyChanged(); OnPropertyChanged(nameof(ShowUpdateProgress)); }
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

    /// <summary>Progression indéterminée de la mise à jour des signatures (barre + bouton Arrêter).</summary>
    public bool ShowUpdateProgress => IsUpdating;

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
            RefreshRecentTargets();
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

    /// <summary>Recharge la première page de la quarantaine (compatible avec les délégués <c>Action</c>).</summary>
    public void LoadQuarantine() => LoadQuarantine(reset: true);

    /// <summary>Charge une page de la quarantaine ; <paramref name="reset"/> repart de zéro, sinon ajoute la page suivante.</summary>
    public void LoadQuarantine(bool reset)
    {
        QuarantineTotalCount = _quarantine.Count;
        QuarantineCount = QuarantineTotalCount;
        if (reset)
            QuarantineEntries.Clear();

        var offset = QuarantineEntries.Count;
        foreach (var entry in _quarantine.GetEntriesPaged(offset, QuarantinePageSize))
            QuarantineEntries.Add(entry);

        OnPropertyChanged(nameof(QuarantineHasMore));
        OnPropertyChanged(nameof(QuarantinePagingStatus));
    }

    public void LoadMoreQuarantine()
    {
        if (QuarantineHasMore)
            LoadQuarantine(reset: false);
    }

    /// <summary>Vide toute la quarantaine après confirmation (irréversible).</summary>
    public void PurgeQuarantine()
    {
        var total = _quarantine.Count;
        if (total == 0)
            return;

        if (!Confirm.ConfirmYesNo(OpticombatStrings.Confirmations.PurgeQuarantine(total),
                OpticombatStrings.Confirmations.Title))
            return;

        var count = _quarantine.PurgeAll();
        LoadQuarantine();
        StatusMessage = LocalizationService.Format("Vm_PurgeCount", count);
    }

    /// <summary>Charge les menaces d'une session de l'historique dans l'onglet Analyse (« Traiter dans Analyse »).</summary>
    public void LoadThreatsFromHistorySession(ScanSession session)
    {
        if (session is null || IsScanning)
            return;

        Threats.Clear();
        foreach (var t in session.Threats)
            Threats.Add(t);
        ThreatsFound = Threats.Count;
        StatusMessage = ThreatsFound > 0
            ? LocalizationService.Format("Vm_HistReviewLoaded", session.StartedAt, ThreatsFound)
            : LocalizationService.GetString("Scan_Ready");
    }

    public void RefreshRecentTargets()
    {
        RecentTargets.Clear();
        foreach (var target in _container.UserPreferencesAccessor.Current.RecentTargets)
            RecentTargets.Add(target);
    }

    /// <summary>Relance une cible récente : dossier/fichier avec son chemin, sinon analyse rapide/complète.</summary>
    public async Task ScanRecentAsync(RecentScanTarget? target)
    {
        if (target is null)
            return;

        if (target.ScanType is ScanType.File or ScanType.Folder)
            await StartScanAsync(target.ScanType, target.Path).ConfigureAwait(true);
        else
            await StartScanAsync(target.ScanType).ConfigureAwait(true);
    }

    // ── Actions par menace (mêmes règles que optiSCAN : succès → la ligne disparaît) ──────────

    public void RemoveDetectedThreat(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return;

        var removed = Threats
            .Where(t => string.Equals(t.FilePath, filePath, StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (removed.Count == 0)
            return;

        foreach (var t in removed)
            Threats.Remove(t);
        ThreatsFound = Threats.Count;
    }

    private void RefreshAfterThreatAction()
    {
        RefreshProtectionBadge();
        LoadQuarantine();
        _container.RequestScanHistoryViewsRefresh();
    }

    public void QuarantineThreat(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return;

        var result = _container.Actions.QuarantineThreat(filePath, ActiveScanSessionId);
        if (result.Success)
            RemoveDetectedThreat(filePath);
        RefreshAfterThreatAction();
    }

    public void IgnoreThreat(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return;

        if (_container.Actions.IgnoreThreat(filePath).Success)
        {
            RemoveDetectedThreat(filePath);
            RefreshAfterThreatAction();
        }
    }

    public void DeleteThreat(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return;

        if (!Confirm.ConfirmYesNo(
                LocalizationService.GetString("Av_ConfirmDeleteFile"),
                OpticombatStrings.Confirmations.Title,
                warning: true))
            return;

        if (_container.Actions.DeleteThreatFile(filePath).Success)
        {
            RemoveDetectedThreat(filePath);
            RefreshAfterThreatAction();
        }
    }

    /// <summary>Interroge la réputation du fichier (VirusTotal) et affiche le résultat.</summary>
    public async Task ShowReputationAsync(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return;

        var title = LocalizationService.GetString("Av_ReputationTitle");
        try
        {
            var result = await _container.ThreatReputation.LookupFileAsync(filePath).ConfigureAwait(true);
            var message = result.Summary;
            if (!string.IsNullOrEmpty(result.Permalink))
                message += Environment.NewLine + result.Permalink;

            if (result.IsError)
                Confirm.Warn(message, title);
            else
                Confirm.Inform(message, title);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("AntivirusViewModel", "Reputation", ex);
            Confirm.Warn(ex.Message, title);
        }
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

    private CancellationTokenSource? _updateCts;

    /// <summary>Interrompt la mise à jour des signatures en cours (ClamAV + règles YARA), comme le bouton Arrêter d'optiSCAN.</summary>
    public void StopSignatureUpdate()
    {
        if (!IsUpdating)
            return;

        StatusMessage = OpticombatStrings.StatusUpdates.SignaturesUpdateStopping;

        try { _container.FreshclamUpdater.CancelUpdate(); }
        catch (Exception ex) { AppLogger.Warn("AntivirusViewModel", "CancelUpdate ClamAV", ex); }

        try { _container.RulesUpdater.CancelUpdate(); }
        catch (Exception ex) { AppLogger.Warn("AntivirusViewModel", "CancelUpdate règles", ex); }

        try { _updateCts?.Cancel(); }
        catch (ObjectDisposedException) { /* mise à jour déjà terminée */ }
    }

    public async Task UpdateSignaturesAsync()
    {
        if (IsUpdating || !_updateRunner.TryEnterUpdate())
        {
            StatusMessage = OpticombatStrings.StatusUpdates.SignaturesUpdateAlreadyRunning;
            return;
        }

        IsUpdating = true;
        _updateCts = new CancellationTokenSource();
        AppendSignatureLog(OpticombatStrings.StatusUpdates.FullSignaturesUpdateStarting);

        var completedOk = true;
        try
        {
            completedOk = await _updateRunner.RunFullUpdateAsync(
                _container.FreshclamUpdater,
                _container.RulesUpdater,
                AppendSignatureLog,
                _updateCts.Token).ConfigureAwait(true);

            _signatureStatus.InvalidateCache();
            await RefreshSignaturesAsync(force: true).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            completedOk = false;
            AppendSignatureLog(LocalizationService.GetString("Status_SigInterrupted"));
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
            _updateCts?.Dispose();
            _updateCts = null;
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

    /// <summary>Confirmations utilisateur (suppression définitive). Remplacé par la boîte native au démarrage du shell.</summary>
    public IUserConfirmService Confirm { get; set; } = DeclineUserConfirmService.Instance;

    public void DeleteQuarantineEntry(string? id)
    {
        if (string.IsNullOrWhiteSpace(id))
            return;
        if (!Confirm.ConfirmYesNo(
                LocalizationService.GetString("Av_ConfirmDeleteQuarantine"),
                LocalizationService.GetString("Common_Confirmation")))
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
            RefreshRecentTargets();

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
