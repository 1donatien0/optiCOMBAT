using Microsoft.UI.Xaml;
using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using WinUiApp = Microsoft.UI.Xaml.Application;

namespace optiCombat.WinUI.ViewModels;

public sealed class OptionsViewModel : INotifyPropertyChanged
{
    private readonly ServiceContainer _container;

    public OptionsViewModel(ServiceContainer container)
    {
        _container = container;
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
    public bool GameMode { get; set; }
    public bool DarkTheme { get; set; }
    public int CleanThresholdDays { get; set; } = 14;
    public int SignatureStaleDays { get; set; } = 7;
    public int ScheduledHour { get; set; } = 2;
    public int ScheduledMinute { get; set; }
    public string UiCulture { get; set; } = "fr-FR";
    public int FavoriteScanIndex { get; set; }
    public string VirusTotalApiKey { get; set; } = string.Empty;
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
        GameMode = prefs.GameModeAutoEnabled;
        CleanThresholdDays = prefs.CleanSuggestThresholdDays;
        SignatureStaleDays = prefs.SignatureStaleThresholdDays;
        UiCulture = string.IsNullOrWhiteSpace(prefs.UiCulture) ? "fr-FR" : prefs.UiCulture;
        VirusTotalApiKey = prefs.VirusTotalApiKey ?? string.Empty;
        FavoriteScanIndex = prefs.FavoriteScanType switch
        {
            ScanType.FullScan => 1,
            ScanType.Folder => 2,
            ScanType.File => 3,
            _ => 0
        };
        DarkTheme = prefs.DarkTheme;
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

        // Ne jamais toucher à Application.RequestedTheme après le lancement :
        // WinUI 3 lève une exception. Le thème se pilote au niveau de la racine visuelle.
        if (App.MainWindowInstance?.Content is FrameworkElement root)
            root.RequestedTheme = dark ? ElementTheme.Dark : ElementTheme.Light;

        var prefs = _container.UserPreferencesAccessor.Current;
        prefs.DarkTheme = dark;
        prefs.SyncWindowsTheme = false;
        prefs.Save();

        OnPropertyChanged(nameof(DarkTheme));
    }

    public async Task CheckAppUpdatesAsync()
    {
        try
        {
            var result = await new UpdateService().CheckForUpdatesAsync().ConfigureAwait(true);
            UpdateStatusMessage = result.UserMessage;
        }
        catch (Exception ex)
        {
            UpdateStatusMessage = LocalizationService.Format("Status_Error", ex.Message);
        }
        OnPropertyChanged(nameof(UpdateStatusMessage));
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

    private static bool IsAutoStartRegistered()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", false);
            return key?.GetValue("optiCombat") != null;
        }
        catch { return false; }
    }

    private static void SetAutoStart(bool enable)
    {
        const string regKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        const string appName = "optiCombat";
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(regKey, true)
                ?? Microsoft.Win32.Registry.CurrentUser.CreateSubKey(regKey);
            if (key == null) return;
            if (enable)
            {
                var exe = Environment.ProcessPath;
                if (!string.IsNullOrWhiteSpace(exe))
                    key.SetValue(appName, $"\"{exe}\"");
            }
            else
                key.DeleteValue(appName, throwOnMissingValue: false);
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
        OnPropertyChanged(nameof(GameMode));
        OnPropertyChanged(nameof(DarkTheme));
        OnPropertyChanged(nameof(CleanThresholdDays));
        OnPropertyChanged(nameof(SignatureStaleDays));
        OnPropertyChanged(nameof(UiCulture));
        OnPropertyChanged(nameof(FavoriteScanIndex));
        OnPropertyChanged(nameof(VirusTotalApiKey));
        OnPropertyChanged(nameof(AppVersionLabel));
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
