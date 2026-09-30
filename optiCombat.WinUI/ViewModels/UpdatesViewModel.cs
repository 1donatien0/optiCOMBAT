using optiCombat.Localization;
using optiCombat.Services;
using optiCombat.Strings;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace optiCombat.WinUI.ViewModels;

/// <summary>Sévérité du marquage d'une ligne de mise à jour après tentative.</summary>
public enum UpdateRowSeverity
{
    None,
    Warning,
    Danger,
}

/// <summary>Ligne de la liste « Mises à jour » (une application winget).</summary>
public sealed class UpdateRowViewModel : INotifyPropertyChanged
{
    private bool _isSelected = true;
    private string _tag = string.Empty;
    private UpdateRowSeverity _severity;

    public UpdateRowViewModel(WingetPackageUpdate package) => Package = package;

    public WingetPackageUpdate Package { get; }

    public string Label => $"{Package.Name}   {Package.InstalledVersion} → {Package.AvailableVersion}";

    /// <summary>Recocher une ligne en échec efface son marquage : elle redevient une mise à jour ordinaire.</summary>
    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (!SetField(ref _isSelected, value))
                return;
            if (value)
                ClearMark();
        }
    }

    public string Tag { get => _tag; private set => SetField(ref _tag, value); }

    public UpdateRowSeverity Severity
    {
        get => _severity;
        private set
        {
            if (SetField(ref _severity, value))
            {
                OnPropertyChanged(nameof(IsWarning));
                OnPropertyChanged(nameof(IsDanger));
            }
        }
    }

    public bool IsWarning => _severity == UpdateRowSeverity.Warning;
    public bool IsDanger => _severity == UpdateRowSeverity.Danger;

    /// <summary>Décoche la ligne et l'annote : évite qu'un second clic relance un paquet déjà traité.</summary>
    public void Mark(string label, UpdateRowSeverity severity)
    {
        IsSelected = false;
        Tag = $"[{label}]";
        Severity = severity;
    }

    private void ClearMark()
    {
        Tag = string.Empty;
        Severity = UpdateRowSeverity.None;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
            return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }
}

/// <summary>
/// Panneau Optimiser — onglet « Mises à jour » : applications via winget + lien Windows Update.
/// </summary>
public sealed class UpdatesViewModel : INotifyPropertyChanged
{
    private readonly WingetUpdateService _winget = new();
    private IUiThreadScheduler _ui;
    private IUserConfirmService _confirm;

    private bool _running;
    private bool _scanPerformed;
    private bool _logIsHint = true;
    private bool? _wingetAvailable;
    private string _logText = string.Empty;

    public UpdatesViewModel(IUiThreadScheduler ui, IUserConfirmService confirm)
    {
        _ui = ui;
        _confirm = confirm;
        _logText = LocalizationService.GetString("Upd_LogHint");
    }

    /// <summary>Branche le thread UI et la boîte de confirmation natives dès que la fenêtre existe.</summary>
    public void Attach(IUiThreadScheduler ui, IUserConfirmService confirm)
    {
        _ui = ui;
        _confirm = confirm;
    }

    public ObservableCollection<UpdateRowViewModel> Rows { get; } = new();

    public string LogText { get => _logText; private set => SetField(ref _logText, value); }

    public bool IsBusy => _running;
    public bool CanScan => !_running;

    // Volontairement basé sur la présence de lignes, pas sur les cases cochées.
    public bool CanUpdateSelected => !_running && Rows.Count > 0;

    public bool CanUpdateAll => !_running && IsWingetAvailable;

    public bool ShowEmptyState => !_running && _scanPerformed && Rows.Count == 0;

    private bool IsWingetAvailable => _wingetAvailable ??= _winget.ResolveWingetPath() != null;

    // ── Rechercher ───────────────────────────────────────────────────────────
    public async Task ScanAsync()
    {
        if (_running)
            return;
        await RefreshListAsync(resetLog: true);
    }

    /// <summary>Relance « winget upgrade » et reconstruit la liste (réutilisable après une mise à jour globale).</summary>
    private async Task RefreshListAsync(bool resetLog)
    {
        SetRunning(true);
        Rows.Clear();

        if (resetLog)
            SetLog(LocalizationService.GetString("Upd_LogScanStart"));
        else
            AppendLog(LocalizationService.GetString("Upd_LogScanStart"));

        try
        {
            var wingetPath = _winget.ResolveWingetPath();
            _wingetAvailable = wingetPath != null;
            if (wingetPath == null)
            {
                AppendLog(LocalizationService.GetString("Upd_LogWingetMissing"));
                return;
            }
            AppendLog(LocalizationService.Format("Upd_LogWinget", wingetPath));

            var updates = await _winget.GetAvailableUpdatesAsync();
            _scanPerformed = true;

            foreach (var u in updates)
                Rows.Add(new UpdateRowViewModel(u));

            AppendLog(Rows.Count == 0
                ? LocalizationService.GetString("Upd_LogNone")
                : LocalizationService.Format("Upd_LogFound", Rows.Count));
        }
        catch (Exception ex)
        {
            AppLogger.Warn("UpdatesViewModel", "Recherche winget", ex);
            AppendLog(LocalizationService.Format("Upd_LogError", ex.Message));
        }
        finally
        {
            SetRunning(false);
        }
    }

    // ── Mettre à jour la sélection ───────────────────────────────────────────
    public async Task UpdateSelectedAsync()
    {
        if (_running)
            return;

        var selected = Rows.Where(r => r.IsSelected).Select(r => r.Package).ToList();
        if (selected.Count == 0)
        {
            AppendLog(LocalizationService.GetString("Upd_LogNoneChecked"));
            return;
        }

        // Verrou posé avant la confirmation : un second clic ne doit pas lancer un doublon.
        SetRunning(true);
        try
        {
            var summary = string.Join("\n",
                selected.Select(u => $" •  {u.Name}  ({u.InstalledVersion} → {u.AvailableVersion})"));
            if (!_confirm.ConfirmYesNo(
                    LocalizationService.Format("Upd_ConfirmBody", summary),
                    OpticombatStrings.Confirmations.Title,
                    warning: false))
                return;

            AppendLog(LocalizationService.Format("Upd_LogUpgradeStart", selected.Count));

            // Progress<T> est créé sur le thread UI : chaque rapport y revient.
            var progress = new Progress<WingetUpgradeResult>(ApplyUpgradeResult);
            var results = await _winget.UpgradePackagesAsync(selected, AppendWingetOutputLine, progress);

            int ok = results.Count(r => r.IsResolved);
            AppendLog(LocalizationService.Format("Upd_LogUpgradeSummary", ok, results.Count - ok));
        }
        catch (Exception ex)
        {
            AppLogger.Warn("UpdatesViewModel", "Mise à jour winget (sélection)", ex);
            AppendLog(LocalizationService.Format("Upd_LogError", ex.Message));
        }
        finally
        {
            SetRunning(false);
        }
    }

    // ── Tout mettre à jour ───────────────────────────────────────────────────
    public async Task UpdateAllAsync()
    {
        if (_running)
            return;

        SetRunning(true);
        bool completed = false;
        try
        {
            if (!_confirm.ConfirmYesNo(
                    LocalizationService.GetString("Upd_ConfirmAllBody"),
                    OpticombatStrings.Confirmations.Title,
                    warning: false))
                return;

            AppendLog(LocalizationService.GetString("Upd_LogUpgradeAllStart"));
            await _winget.UpgradeAllAsync(AppendWingetOutputLine, Rows.Select(r => r.Package).ToList());
            AppendLog(LocalizationService.GetString("Upd_LogUpgradeAllDone"));
            completed = true;
        }
        catch (Exception ex)
        {
            AppLogger.Warn("UpdatesViewModel", "Mise à jour winget (tout)", ex);
            AppendLog(LocalizationService.Format("Upd_LogError", ex.Message));
        }
        finally
        {
            SetRunning(false);
        }

        if (!completed)
            return;

        // « upgrade --all » est un processus unique : la seule façon fiable de
        // rafraîchir la liste est de relancer une recherche.
        AppendLog(LocalizationService.GetString("Upd_LogRescan"));
        await RefreshListAsync(resetLog: false);
    }

    // ── Windows Update ───────────────────────────────────────────────────────
    public void OpenWindowsUpdate()
    {
        if (SystemTweaksService.OpenWindowsUpdateSettings())
            AppendLog(LocalizationService.GetString("Upd_LogWindowsSettings"));
    }

    // ── Résultats par paquet ─────────────────────────────────────────────────
    /// <summary>La ligne disparaît si la mise à jour est acquise, sinon elle est décochée et marquée.</summary>
    private void ApplyUpgradeResult(WingetUpgradeResult result)
    {
        // Recherche par référence : robuste même si deux paquets partagent un identifiant.
        var row = Rows.FirstOrDefault(r => ReferenceEquals(r.Package, result.Package));
        var pkg = result.Package;

        switch (result.Status)
        {
            case WingetUpgradeStatus.Succeeded:
                Remove(row);
                AppendLog(LocalizationService.Format("Upd_LogPkgSuccess", pkg.Name, pkg.AvailableVersion));
                break;

            case WingetUpgradeStatus.AlreadyUpToDate:
                Remove(row);
                AppendLog(LocalizationService.Format("Upd_LogPkgAlready", pkg.Name));
                break;

            case WingetUpgradeStatus.RebootRequired:
                row?.Mark(LocalizationService.GetString("Upd_TagReboot"), UpdateRowSeverity.Warning);
                AppendLog(LocalizationService.Format("Upd_LogPkgReboot", pkg.Name));
                break;

            case WingetUpgradeStatus.CancelledByUser:
                row?.Mark(LocalizationService.GetString("Upd_TagCancelled"), UpdateRowSeverity.Warning);
                AppendLog(LocalizationService.Format("Upd_LogPkgCancelled", pkg.Name));
                break;

            default:
                row?.Mark(LocalizationService.GetString("Upd_TagFailed"), UpdateRowSeverity.Danger);
                AppendLog(LocalizationService.Format("Upd_LogPkgFailed", pkg.Name, $"0x{result.ExitCode:X8}"));
                break;
        }

        RaiseState();
    }

    private void Remove(UpdateRowViewModel? row)
    {
        if (row != null)
            Rows.Remove(row);
    }

    // ── Journal ──────────────────────────────────────────────────────────────
    /// <summary>Filtre les lignes de progression winget (spinners, barres) avant journalisation.</summary>
    private void AppendWingetOutputLine(string line)
    {
        if (line.Length < 3)
            return;
        if (line.Contains('█') || line.Contains('▒') || line.Contains('░'))
            return;
        if (line.All(c => c is '-' or '\\' or '|' or '/' or ' ' or '.'))
            return;
        AppendLog(line);
    }

    private void SetLog(string text) => _ui.Invoke(() =>
    {
        _logIsHint = false;
        LogText = $"[{DateTime.Now:HH:mm:ss}] {text}\n";
    });

    private void AppendLog(string line) => _ui.Invoke(() =>
    {
        if (_logIsHint)
        {
            _logIsHint = false;
            LogText = string.Empty;
        }
        LogText += $"[{DateTime.Now:HH:mm:ss}] {line}\n";
        if (LogText.Length > 20000) LogText = LogText[^15000..];
    });

    private void SetRunning(bool running)
    {
        _running = running;
        RaiseState();
    }

    private void RaiseState()
    {
        OnPropertyChanged(nameof(IsBusy));
        OnPropertyChanged(nameof(CanScan));
        OnPropertyChanged(nameof(CanUpdateSelected));
        OnPropertyChanged(nameof(CanUpdateAll));
        OnPropertyChanged(nameof(ShowEmptyState));
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
            return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }
}
