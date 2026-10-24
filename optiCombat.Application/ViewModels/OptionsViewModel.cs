using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace optiCombat.WinUI.ViewModels;

public sealed class OptionsViewModel : INotifyPropertyChanged
{
    private readonly ServiceContainer _container;
    private readonly IShellThemeController _theme;

    public OptionsViewModel(ServiceContainer container, IShellThemeController theme)
    {
        _container = container;
        _theme = theme;
        Exclusions = new ObservableCollection<string>();
        Load();
    }

    public ObservableCollection<string> Exclusions { get; }

    public bool NotificationsEnabled { get; set; }
    public bool AutoStart { get; set; }
    public bool RealtimeProtection { get; set; }
    public bool AutoQuarantine { get; set; }
    public bool AutoUpdateSignatures { get; set; }
    public bool AggressiveSignatureUpdates { get; set; }
    public bool ProcessMonitor { get; set; }
    public bool TamperProtection { get; set; }
    public bool RemovableDriveScan { get; set; }
    public bool RemovableDriveDetailed { get; set; }
    public bool IncludeRemovableInFullScan { get; set; }
    public bool BackupBeforeQuarantine { get; set; }
    public bool UseClamd { get; set; }
    public bool UseNativeEngine { get; set; }
    public bool GameMode { get; set; }
    public bool DarkTheme { get; set; }
    public bool SyncWindowsTheme { get; set; }
    public bool DefenderComplementMode { get; set; }
    public bool DefenderActive { get; private set; }
    public bool HighContrast { get; set; }
    public string ThemePresetId { get; private set; } = "combat";
    public string ThemeAccentColor { get; private set; } = string.Empty;
    public int CleanThresholdDays { get; set; } = 14;
    public int SignatureStaleDays { get; set; } = 7;
    public int ScheduledHour { get; set; } = 2;
    public int ScheduledMinute { get; set; }
    public string UiCulture { get; set; } = "fr-FR";
    public int FavoriteScanIndex { get; set; }
    public string VirusTotalApiKey { get; set; } = string.Empty;
    public string AbuseChAuthKey { get; set; } = string.Empty;

    /// <summary>État de la threat intel hors-ligne (clé absente / invalide / dernière mise à jour).</summary>
    public string ThreatIntelStatus { get; private set; } = string.Empty;
    public string ScheduledStatus { get; private set; } = "";
    public string AppVersionLabel { get; private set; } = string.Empty;
    public string UpdateStatusMessage { get; private set; } = string.Empty;

    public event PropertyChangedEventHandler? PropertyChanged;

    public void Load()
    {
        var prefs = _container.UserPreferencesAccessor.Current;
        var excl = _container.ExclusionSettingsAccessor.Current;

        NotificationsEnabled = prefs.ActionNotificationsEnabled;
        AutoStart = IsAutoStartRegistered();
        RealtimeProtection = excl.RealTimeEnabled;
        AutoQuarantine = excl.AutoQuarantineEnabled;
        AutoUpdateSignatures = prefs.SignatureAutoUpdateEnabled;
        AggressiveSignatureUpdates = prefs.AggressiveSignatureUpdates;
        ProcessMonitor = prefs.ProcessMonitorEnabled;
        TamperProtection = prefs.TamperProtectionEnabled;
        RemovableDriveScan = prefs.RemovableDriveScanEnabled;
        RemovableDriveDetailed = prefs.RemovableDriveScanDetailed;
        IncludeRemovableInFullScan = prefs.IncludeRemovableInFullScan;
        BackupBeforeQuarantine = prefs.BackupBeforeQuarantine;
        UseClamd = prefs.UseClamdEngine;
        UseNativeEngine = prefs.UseNativeEngine;
        GameMode = prefs.GameModeAutoEnabled;
        CleanThresholdDays = prefs.CleanSuggestThresholdDays;
        SignatureStaleDays = prefs.SignatureStaleThresholdDays;
        UiCulture = string.IsNullOrWhiteSpace(prefs.UiCulture) ? "fr-FR" : prefs.UiCulture;
        VirusTotalApiKey = prefs.VirusTotalApiKey ?? string.Empty;
        AbuseChAuthKey = prefs.AbuseChAuthKey ?? string.Empty;
        ThreatIntelStatus = BuildThreatIntelStatus();
        FavoriteScanIndex = prefs.FavoriteScanType switch
        {
            ScanType.FullScan => 1,
            ScanType.Folder => 2,
            ScanType.File => 3,
            _ => 0
        };
        DarkTheme = prefs.DarkTheme;
        SyncWindowsTheme = prefs.SyncWindowsTheme;
        DefenderComplementMode = prefs.DefenderComplementModeEnabled;
        DefenderActive = DefenderCoexistenceService.IsDefenderActive();
        HighContrast = prefs.HighContrastEnabled;
        ThemePresetId = string.IsNullOrWhiteSpace(prefs.ThemePresetId) ? "combat" : prefs.ThemePresetId;
        ThemeAccentColor = prefs.ThemeAccentColor ?? string.Empty;
        AppVersionLabel = $"{ProductVersionInfo.ReleaseLabel} ({ProductVersionInfo.SemVer})";

        Exclusions.Clear();
        foreach (var path in excl.ExcludedFolders)
            Exclusions.Add(path);

        _ = RefreshScheduledStatusAsync();
        NotifyAll();
    }

    public void SaveNotifications(bool enabled)
    {
        var prefs = _container.UserPreferencesAccessor.Current;
        prefs.ActionNotificationsEnabled = enabled;
        prefs.Save();
        _container.Notifications.IsEnabled = enabled;
    }

    public void SaveAutoStart(bool enabled) => SetAutoStart(enabled);

    public void SaveRealtimeProtection(bool enabled) => _container.ApplyRealtimeProtection(enabled);

    public void SaveAutoQuarantine(bool enabled)
    {
        var excl = _container.ExclusionSettingsAccessor.Current;
        excl.AutoQuarantineEnabled = enabled;
        excl.Save();
    }

    public void SaveAutoUpdate(bool enabled) => _container.ApplySignatureAutoUpdate(enabled);

    public void SaveAggressiveSignatures(bool enabled)
    {
        var prefs = _container.UserPreferencesAccessor.Current;
        prefs.AggressiveSignatureUpdates = enabled;
        prefs.Save();
    }

    public void SaveProcessMonitor(bool enabled) => _container.ApplyProcessMonitor(enabled);

    public void SaveTamperProtection(bool enabled) => _container.ApplyTamperProtection(enabled);

    public void SaveRemovableDriveScan(bool enabled)
    {
        var prefs = _container.UserPreferencesAccessor.Current;
        prefs.RemovableDriveScanEnabled = enabled;
        prefs.Save();
        _container.ApplyRemovableDriveScan(enabled);
    }

    public void SaveRemovableDriveDetailed(bool enabled)
    {
        var prefs = _container.UserPreferencesAccessor.Current;
        prefs.RemovableDriveScanDetailed = enabled;
        prefs.Save();
    }

    public void SaveIncludeRemovableInFullScan(bool enabled)
    {
        var prefs = _container.UserPreferencesAccessor.Current;
        prefs.IncludeRemovableInFullScan = enabled;
        prefs.Save();
    }

    public void SaveBackupBeforeQuarantine(bool enabled)
    {
        var prefs = _container.UserPreferencesAccessor.Current;
        prefs.BackupBeforeQuarantine = enabled;
        prefs.Save();
    }

    public void SaveUseClamd(bool enabled)
    {
        var prefs = _container.UserPreferencesAccessor.Current;
        prefs.UseClamdEngine = enabled;
        prefs.Save();
        if (enabled)
            _ = Task.Run(async () => { try { await ClamdHost.Shared.EnsureRunningAsync(); } catch { } });
        else
            ClamdHost.Shared.Stop();
    }

    public void SaveUseNativeEngine(bool enabled)
    {
        var prefs = _container.UserPreferencesAccessor.Current;
        prefs.UseNativeEngine = enabled;
        prefs.Save();
        UseNativeEngine = enabled;
    }

    public void SaveGameMode(bool enabled)
    {
        var prefs = _container.UserPreferencesAccessor.Current;
        prefs.GameModeAutoEnabled = enabled;
        prefs.Save();
        if (enabled) DistractionFreeMonitor.Start();
        else DistractionFreeMonitor.Stop();
    }

    public void SaveFavoriteScan(int index)
    {
        var prefs = _container.UserPreferencesAccessor.Current;
        prefs.FavoriteScanType = index switch
        {
            1 => ScanType.FullScan,
            2 => ScanType.Folder,
            3 => ScanType.File,
            _ => ScanType.QuickScan
        };
        prefs.Save();
        FavoriteScanIndex = index;
        OnPropertyChanged(nameof(FavoriteScanIndex));
    }

    public void SaveUiCulture(string culture)
    {
        if (string.Equals(UiCulture, culture, StringComparison.OrdinalIgnoreCase))
            return;

        UiCulture = culture;
        LocalizationService.SetUserCulture(culture);
        LocalizationService.ApplyCulture(culture);
        OnPropertyChanged(nameof(UiCulture));
        LocalizationService.RestartApplication();
    }

    public void SaveVirusTotalKey(string key)
    {
        var prefs = _container.UserPreferencesAccessor.Current;
        prefs.VirusTotalApiKey = key?.Trim() ?? string.Empty;
        prefs.Save();
        VirusTotalApiKey = prefs.VirusTotalApiKey;
        OnPropertyChanged(nameof(VirusTotalApiKey));
    }

    /// <summary>
    /// Enregistre la clé abuse.ch. Une clé valide lance aussitôt un premier téléchargement des
    /// feeds en arrière-plan. Renvoie <c>false</c> si la clé saisie n'a pas le format attendu
    /// (elle est tout de même conservée, pour que l'utilisateur la corrige).
    /// </summary>
    public bool SaveAbuseChAuthKey(string key)
    {
        var prefs = _container.UserPreferencesAccessor.Current;
        var trimmed = key?.Trim() ?? string.Empty;
        var changed = !string.Equals(prefs.AbuseChAuthKey, trimmed, StringComparison.Ordinal);
        prefs.AbuseChAuthKey = trimmed;
        prefs.Save();
        AbuseChAuthKey = trimmed;
        var valid = ThreatIntelFeedUpdater.IsValidAuthKey(trimmed);
        ThreatIntelStatus = BuildThreatIntelStatus();
        OnPropertyChanged(nameof(AbuseChAuthKey));
        OnPropertyChanged(nameof(ThreatIntelStatus));
        if (valid && changed)
            LastThreatIntelUpdate = RefreshThreatIntelAsync(force: true);
        return valid || trimmed.Length == 0;
    }

    /// <summary>Dernière mise à jour lancée depuis Options (exposée pour les tests).</summary>
    internal Task? LastThreatIntelUpdate { get; private set; }

    /// <summary>Télécharge les feeds abuse.ch puis met à jour <see cref="ThreatIntelStatus"/>.</summary>
    public async Task RefreshThreatIntelAsync(bool force = false)
    {
        try
        {
            var result = await _container.ThreatIntelUpdater.UpdateAsync(force).ConfigureAwait(true);
            ThreatIntelStatus = result.Skipped || result.Success ? BuildThreatIntelStatus() : result.Message;
        }
        catch (Exception ex)
        {
            AppLogger.Warn("OptionsViewModel", "RefreshThreatIntelAsync", ex);
            ThreatIntelStatus = ex.Message;
        }
        OnPropertyChanged(nameof(ThreatIntelStatus));
    }

    private string BuildThreatIntelStatus()
    {
        var key = _container.UserPreferencesAccessor.Current.AbuseChAuthKey;
        if (string.IsNullOrWhiteSpace(key))
            return LocalizationService.GetString("ThreatIntel_NoAuthKey");
        if (!ThreatIntelFeedUpdater.IsValidAuthKey(key))
            return LocalizationService.GetString("ThreatIntel_InvalidKey");
        return _container.ThreatIntelUpdater.LastUpdateUtc is { } last
            ? LocalizationService.Format("ThreatIntel_LastUpdate", last.ToLocalTime().ToString("g", System.Globalization.CultureInfo.CurrentCulture))
            : LocalizationService.GetString("ThreatIntel_NeverUpdated");
    }

    public void SaveThresholds()
    {
        var prefs = _container.UserPreferencesAccessor.Current;
        prefs.CleanSuggestThresholdDays = Math.Max(1, CleanThresholdDays);
        prefs.SignatureStaleThresholdDays = Math.Max(1, SignatureStaleDays);
        prefs.Save();
    }

    public void ApplyTheme(bool dark)
    {
        DarkTheme = dark;
        SyncWindowsTheme = false;
        // Thème piloté sur la racine visuelle (jamais Application.RequestedTheme après le lancement).
        _theme.ApplyExplicit(dark);
        OnPropertyChanged(nameof(DarkTheme));
        OnPropertyChanged(nameof(SyncWindowsTheme));
    }

    public void SaveSyncWindowsTheme(bool sync)
    {
        SyncWindowsTheme = sync;
        _theme.SetSyncWithWindows(sync);
        DarkTheme = _theme.IsDarkTheme;
        OnPropertyChanged(nameof(SyncWindowsTheme));
        OnPropertyChanged(nameof(DarkTheme));
    }

    /// <summary>Mode complément Defender : coupe (ou rétablit) la RTP et la surveillance des processus d'optiCOMBAT.</summary>
    public void SaveDefenderComplementMode(bool enabled)
    {
        DefenderCoexistenceService.Apply(
            enabled,
            _container.UserPreferencesAccessor,
            _container.ApplyRealtimeProtection,
            _container.ApplyProcessMonitor);
        DefenderComplementMode = enabled;
        RealtimeProtection = !enabled;
        ProcessMonitor = !enabled;
        OnPropertyChanged(nameof(DefenderComplementMode));
        OnPropertyChanged(nameof(RealtimeProtection));
        OnPropertyChanged(nameof(ProcessMonitor));
    }

    public string DefenderComplementCaption => LocalizationService.GetString(
        DefenderActive ? "Opt_DefenderComplementCaptionActive" : "Opt_DefenderComplementCaptionInactive");

    public void SaveHighContrast(bool enabled)
    {
        HighContrast = enabled;
        _theme.SetHighContrast(enabled);
        OnPropertyChanged(nameof(HighContrast));
    }

    public void SetThemePreset(string presetId)
    {
        ThemePresetId = string.IsNullOrWhiteSpace(presetId) ? "combat" : presetId;
        _theme.SetThemePreset(ThemePresetId);
        OnPropertyChanged(nameof(ThemePresetId));
    }

    public void SetThemeAccentColor(string? hex)
    {
        ThemeAccentColor = hex ?? string.Empty;
        _theme.SetCustomAccentColor(ThemeAccentColor);
        OnPropertyChanged(nameof(ThemeAccentColor));
    }

    public async Task CheckAppUpdatesAsync()
    {
        try
        {
            var result = await _container.AppUpdates.CheckForUpdatesAsync().ConfigureAwait(true);
            UpdateStatusMessage = result.UserMessage;
        }
        catch (Exception ex)
        {
            UpdateStatusMessage = LocalizationService.Format("Status_Error", ex.Message);
        }
        OnPropertyChanged(nameof(UpdateStatusMessage));
    }

    /// <summary>Exclusions Defender : action explicite de l'utilisateur uniquement.</summary>
    public async Task<string> ApplyDefenderExclusionsAsync()
    {
        var outcome = await WindowsDefenderExclusionService.ApplyOnUserRequestAsync().ConfigureAwait(true);
        return WindowsDefenderExclusionService.DescribeOutcome(outcome);
    }

    public void AddExclusion(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return;
        var excl = _container.ExclusionSettingsAccessor.Current;
        if (excl.ExcludedFolders.Contains(path, StringComparer.OrdinalIgnoreCase))
            return;
        excl.ExcludedFolders.Add(path);
        excl.Save();
        Exclusions.Add(path);
    }

    public void RemoveExclusion(string path)
    {
        var excl = _container.ExclusionSettingsAccessor.Current;
        excl.ExcludedFolders.RemoveAll(p => string.Equals(p, path, StringComparison.OrdinalIgnoreCase));
        excl.Save();
        Exclusions.Remove(path);
    }

    public async Task RefreshScheduledStatusAsync()
    {
        var scheduled = _container.ScheduledScan;
        bool exists = await Task.Run(scheduled.IsTaskExists).ConfigureAwait(true);
        if (!exists)
        {
            ScheduledStatus = LocalizationService.GetString("Opt_SchedNone");
        }
        else
        {
            var next = await Task.Run(scheduled.GetNextRunTime).ConfigureAwait(true);
            ScheduledStatus = next.HasValue
                ? LocalizationService.Format("Opt_SchedNextRun", next.Value.ToString("f", LocalizationService.CurrentCulture))
                : LocalizationService.GetString("Opt_SchedActiveUnknown");
        }
        OnPropertyChanged(nameof(ScheduledStatus));
    }

    public async Task ToggleScheduledScanAsync(bool enable)
    {
        var scheduled = _container.ScheduledScan;
        var time = new TimeSpan(Math.Clamp(ScheduledHour, 0, 23), Math.Clamp(ScheduledMinute, 0, 59), 0);
        if (enable)
            await Task.Run(() => scheduled.CreateDailyScan(time)).ConfigureAwait(true);
        else
            await Task.Run(scheduled.DeleteTask).ConfigureAwait(true);
        await RefreshScheduledStatusAsync().ConfigureAwait(true);
    }

    /// <summary>Messages utilisateur (remplacé par la boîte native au démarrage du shell).</summary>
    public IUserConfirmService Confirm { get; set; } = DeclineUserConfirmService.Instance;

    /// <summary>Déclenche tout de suite la tâche planifiée (« Lancer maintenant »).</summary>
    public async Task RunScheduleNowAsync()
    {
        var scheduled = _container.ScheduledScan;
        var title = LocalizationService.GetString("Opt_SchedTaskTitle");

        if (!await Task.Run(scheduled.IsTaskExists).ConfigureAwait(true))
        {
            Confirm.Inform(LocalizationService.GetString("Opt_SchedEnableFirst"), title);
            return;
        }

        var ok = await Task.Run(scheduled.RunNow).ConfigureAwait(true);
        if (ok)
            Confirm.Inform(LocalizationService.GetString("Opt_SchedRunOk"), title);
        else
            Confirm.Warn(LocalizationService.GetString("Opt_SchedRunFailed"), title);

        await RefreshScheduledStatusAsync().ConfigureAwait(true);
    }

    public void OpenLogsFolder()
    {
        try
        {
            Directory.CreateDirectory(AppLogger.LogDirectory);
            var opened = SystemShell.Current.Run(new System.Diagnostics.ProcessStartInfo
            {
                FileName = AppLogger.LogDirectory,
                UseShellExecute = true
            }, timeoutMs: null);
            if (!opened.Started)
                throw new IOException(AppLogger.LogDirectory);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("OptionsViewModel", "OpenLogsFolder", ex);
            Confirm.Warn(
                LocalizationService.Format("Opt_LogsOpenError", ex.Message),
                LocalizationService.GetString("Opt_DiagnosticsTitle"));
        }
    }

    /// <summary>Ouvre un document livré avec l'application (chemin relatif au dossier d'installation).</summary>
    public void OpenBundledDocument(string relativePath)
    {
        var path = Path.Combine(AppContext.BaseDirectory, relativePath);
        var title = LocalizationService.GetString("Opt_Title");
        if (!File.Exists(path))
        {
            Confirm.Warn(LocalizationService.Format("Opt_OpenDocError", path), title);
            return;
        }

        try
        {
            SystemShell.Current.Run(new System.Diagnostics.ProcessStartInfo { FileName = path, UseShellExecute = true }, timeoutMs: null);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("OptionsViewModel", $"Open document {relativePath}", ex);
            Confirm.Warn(LocalizationService.Format("Opt_OpenDocError", ex.Message), title);
        }
    }

    private const string AutoStartRunKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string AutoStartValueName = "optiCombat";

    /// <summary>Tests uniquement : exécutable inscrit au démarrage.</summary>
    internal static string? AutoStartExecutableOverride { get; set; }

    internal static bool IsAutoStartRegistered()
    {
        try { return SystemShell.Current.GetCurrentUserValue(AutoStartRunKey, AutoStartValueName) != null; }
        catch { return false; }
    }

    internal static void SetAutoStart(bool enable)
    {
        try
        {
            if (enable)
            {
                var exe = AutoStartExecutableOverride ?? Environment.ProcessPath;
                if (!string.IsNullOrWhiteSpace(exe))
                    SystemShell.Current.SetCurrentUserValue(AutoStartRunKey, AutoStartValueName, $"\"{exe}\"", Microsoft.Win32.RegistryValueKind.String);
            }
            else
                SystemShell.Current.DeleteCurrentUserValue(AutoStartRunKey, AutoStartValueName);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("OptionsViewModel", "SetAutoStart", ex);
        }
    }

    private void NotifyAll()
    {
        OnPropertyChanged(nameof(NotificationsEnabled));
        OnPropertyChanged(nameof(AutoStart));
        OnPropertyChanged(nameof(RealtimeProtection));
        OnPropertyChanged(nameof(AutoQuarantine));
        OnPropertyChanged(nameof(AutoUpdateSignatures));
        OnPropertyChanged(nameof(AggressiveSignatureUpdates));
        OnPropertyChanged(nameof(ProcessMonitor));
        OnPropertyChanged(nameof(TamperProtection));
        OnPropertyChanged(nameof(RemovableDriveScan));
        OnPropertyChanged(nameof(RemovableDriveDetailed));
        OnPropertyChanged(nameof(IncludeRemovableInFullScan));
        OnPropertyChanged(nameof(BackupBeforeQuarantine));
        OnPropertyChanged(nameof(UseClamd));
        OnPropertyChanged(nameof(UseNativeEngine));
        OnPropertyChanged(nameof(GameMode));
        OnPropertyChanged(nameof(DarkTheme));
        OnPropertyChanged(nameof(CleanThresholdDays));
        OnPropertyChanged(nameof(SignatureStaleDays));
        OnPropertyChanged(nameof(UiCulture));
        OnPropertyChanged(nameof(FavoriteScanIndex));
        OnPropertyChanged(nameof(VirusTotalApiKey));
        OnPropertyChanged(nameof(AbuseChAuthKey));
        OnPropertyChanged(nameof(ThreatIntelStatus));
        OnPropertyChanged(nameof(AppVersionLabel));
        OnPropertyChanged(nameof(HighContrast));
        OnPropertyChanged(nameof(ThemePresetId));
        OnPropertyChanged(nameof(ThemeAccentColor));
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
