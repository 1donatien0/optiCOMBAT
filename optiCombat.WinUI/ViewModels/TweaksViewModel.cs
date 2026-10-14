using optiCombat.Localization;
using optiCombat.Services;
using optiCombat.Strings;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace optiCombat.WinUI.ViewModels;

/// <summary>
/// Panneau Optimiser — onglet « Tweaks » (performance, confidentialité, interface, maintenance).
/// Les actions HKCU sont appliquées directement ; les actions admin (télémétrie, DISM,
/// historique Defender) partagent une seule invite UAC.
/// </summary>
public sealed class TweaksViewModel : INotifyPropertyChanged
{
    private IUiThreadScheduler _ui;
    private IUserConfirmService _confirm;

    private bool _running;
    private bool _logIsHint = true;
    private string _logText;

    private bool _powerPlan, _visualFx, _telemetry, _ads, _suggestions, _tailored;
    private bool _showExt, _showHidden, _taskbarLeft, _hideWidgets, _searchIcon, _thisPc;
    private bool _dism, _defenderHistory;

    public TweaksViewModel(IUiThreadScheduler ui, IUserConfirmService confirm)
    {
        _ui = ui;
        _confirm = confirm;
        _logText = LocalizationService.GetString("Twk_LogHint");
    }

    /// <summary>Branche le thread UI et la boîte de confirmation natives dès que la fenêtre existe.</summary>
    public void Attach(IUiThreadScheduler ui, IUserConfirmService confirm)
    {
        _ui = ui;
        _confirm = confirm;
    }

    // ── Sélection ────────────────────────────────────────────────────────────
    public bool PowerPlan { get => _powerPlan; set => SetField(ref _powerPlan, value); }
    public bool VisualFx { get => _visualFx; set => SetField(ref _visualFx, value); }
    public bool Telemetry { get => _telemetry; set => SetField(ref _telemetry, value); }
    public bool Ads { get => _ads; set => SetField(ref _ads, value); }
    public bool Suggestions { get => _suggestions; set => SetField(ref _suggestions, value); }
    public bool Tailored { get => _tailored; set => SetField(ref _tailored, value); }
    public bool ShowExt { get => _showExt; set => SetField(ref _showExt, value); }
    public bool ShowHidden { get => _showHidden; set => SetField(ref _showHidden, value); }
    public bool TaskbarLeft { get => _taskbarLeft; set => SetField(ref _taskbarLeft, value); }
    public bool HideWidgets { get => _hideWidgets; set => SetField(ref _hideWidgets, value); }
    public bool SearchIcon { get => _searchIcon; set => SetField(ref _searchIcon, value); }
    public bool ThisPc { get => _thisPc; set => SetField(ref _thisPc, value); }
    public bool Dism { get => _dism; set => SetField(ref _dism, value); }
    public bool DefenderHistory { get => _defenderHistory; set => SetField(ref _defenderHistory, value); }

    public string LogText { get => _logText; private set => SetField(ref _logText, value); }

    public bool IsBusy => _running;
    public bool CanApply => !_running;

    private bool AnyUi => ShowExt || ShowHidden || TaskbarLeft || HideWidgets || SearchIcon || ThisPc;
    private bool AnyElevated => Telemetry || Dism || DefenderHistory;
    private bool Any => PowerPlan || VisualFx || Telemetry || Ads || Suggestions
                        || Tailored || AnyUi || Dism || DefenderHistory;

    // ── Appliquer ────────────────────────────────────────────────────────────
    public async Task ApplyAsync()
    {
        if (_running)
            return;

        if (!Any)
        {
            AppendLog(LocalizationService.GetString("Twk_LogNone"));
            return;
        }

        // Instantané de la sélection : le thread d'arrière-plan ne relit pas l'UI.
        bool powerPlan = PowerPlan, visualFx = VisualFx, telemetry = Telemetry, ads = Ads,
             suggestions = Suggestions, tailored = Tailored, showExt = ShowExt, showHidden = ShowHidden,
             taskbarLeft = TaskbarLeft, hideWidgets = HideWidgets, searchIcon = SearchIcon,
             thisPc = ThisPc, dism = Dism, defenderHistory = DefenderHistory;
        bool anyUi = AnyUi, anyElevated = AnyElevated;

        // Récapitulatif + confirmation.
        var summary = string.Join("\n", BuildLabels().Select(l => $" •  {l}"));
        var confirmBody = LocalizationService.Format("Twk_ConfirmBody", summary);
        if (defenderHistory)
            confirmBody += "\n\n" + LocalizationService.GetString("Twk_DefenderHistoryWarn");

        if (!_confirm.ConfirmYesNo(confirmBody, OpticombatStrings.Confirmations.Title, warning: defenderHistory))
        {
            AppendLog(LocalizationService.GetString("Twk_Cancelled"));
            return;
        }

        SetRunning(true);
        SetLog(LocalizationService.GetString("Twk_LogStart"));

        try
        {
            bool elevatedOk = true;
            await Task.Run(() =>
            {
                // ── Actions sans élévation (HKCU / powercfg) ─────────────────
                if (powerPlan)
                    LogResult("Twk_PowerPlan", SystemTweaksService.EnableHighPerformancePowerPlan());
                if (visualFx)
                    LogResult("Twk_VisualFx", SystemTweaksService.SetVisualEffectsBestPerformance());
                if (ads)
                    LogResult("Twk_Ads", SystemTweaksService.DisableAdvertisingId());
                if (suggestions)
                    LogResult("Twk_Suggestions", SystemTweaksService.DisableSuggestions());
                if (tailored)
                    LogResult("Twk_Tailored", SystemTweaksService.DisableTailoredExperiences());
                if (showExt)
                    LogResult("Twk_ShowExt", SystemTweaksService.ShowFileExtensions());
                if (showHidden)
                    LogResult("Twk_ShowHidden", SystemTweaksService.ShowHiddenFiles());
                if (taskbarLeft)
                    LogResult("Twk_TaskbarLeft", SystemTweaksService.AlignTaskbarLeft());
                if (hideWidgets)
                    LogResult("Twk_HideWidgets", SystemTweaksService.HideTaskbarWidgets());
                if (searchIcon)
                    LogResult("Twk_SearchIcon", SystemTweaksService.SearchBoxAsIcon());
                if (thisPc)
                    LogResult("Twk_ThisPC", SystemTweaksService.ExplorerOpensThisPc());

                // ── Actions admin regroupées : une seule invite UAC ──────────
                if (anyElevated)
                {
                    var commands = new List<string>();
                    if (telemetry)
                        commands.AddRange(SystemTweaksService.ElevatedTelemetryCommands());
                    if (dism)
                        commands.AddRange(SystemTweaksService.ElevatedDismCleanupCommands());
                    if (defenderHistory)
                        commands.AddRange(SystemTweaksService.ElevatedClearDefenderHistoryCommands());

                    AppendLog(LocalizationService.GetString("Twk_LogElevStart"));
                    elevatedOk = SystemTweaksService.RunElevatedBatch(commands, waitForExit: true);
                    if (elevatedOk)
                    {
                        if (telemetry) LogResult("Twk_Telemetry", true);
                        if (dism) LogResult("Twk_Dism", true);
                        if (defenderHistory) LogResult("Twk_DefenderHistory", true);
                    }
                    else
                    {
                        AppendLog(LocalizationService.GetString("Twk_LogElevDenied"));
                    }
                }

                // ── Redémarrage de l'Explorateur si tweaks d'interface ───────
                if (anyUi)
                {
                    SystemTweaksService.RestartExplorer();
                    AppendLog(LocalizationService.GetString("Twk_LogExplorerRestart"));
                }
            });

            AppendLog(LocalizationService.GetString("Twk_LogEnd"));

            if (defenderHistory && elevatedOk)
                PromptDefenderHistoryRestart();
        }
        catch (Exception ex)
        {
            AppLogger.Warn("TweaksViewModel", "Application des tweaks", ex);
            AppendLog(LocalizationService.Format("Twk_LogError", ex.Message));
        }
        finally
        {
            SetRunning(false);
        }
    }

    // ── Applications au démarrage ────────────────────────────────────────────
    public void OpenStartupApps()
    {
        if (SystemTweaksService.OpenStartupAppsManager())
            AppendLog(LocalizationService.GetString("Twk_LogStartupOpened"));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────
    private List<string> BuildLabels()
    {
        var labels = new List<string>(14);
        if (PowerPlan) labels.Add(LocalizationService.GetString("Twk_PowerPlan"));
        if (VisualFx) labels.Add(LocalizationService.GetString("Twk_VisualFx"));
        if (Telemetry) labels.Add(LocalizationService.GetString("Twk_Telemetry"));
        if (Ads) labels.Add(LocalizationService.GetString("Twk_Ads"));
        if (Suggestions) labels.Add(LocalizationService.GetString("Twk_Suggestions"));
        if (Tailored) labels.Add(LocalizationService.GetString("Twk_Tailored"));
        if (ShowExt) labels.Add(LocalizationService.GetString("Twk_ShowExt"));
        if (ShowHidden) labels.Add(LocalizationService.GetString("Twk_ShowHidden"));
        if (TaskbarLeft) labels.Add(LocalizationService.GetString("Twk_TaskbarLeft"));
        if (HideWidgets) labels.Add(LocalizationService.GetString("Twk_HideWidgets"));
        if (SearchIcon) labels.Add(LocalizationService.GetString("Twk_SearchIcon"));
        if (ThisPc) labels.Add(LocalizationService.GetString("Twk_ThisPC"));
        if (Dism) labels.Add(LocalizationService.GetString("Twk_Dism"));
        if (DefenderHistory) labels.Add(LocalizationService.GetString("Twk_DefenderHistory"));
        return labels;
    }

    private void PromptDefenderHistoryRestart()
    {
        AppendLog(LocalizationService.GetString("Twk_LogDefenderHistoryPending"));
        var restart = _confirm.ConfirmYesNo(
            LocalizationService.GetString("Twk_DefenderHistoryRestartBody"),
            OpticombatStrings.Confirmations.Title,
            warning: true);

        if (restart && SystemTweaksService.RequestSystemRestart(0))
            AppendLog(LocalizationService.GetString("Twk_LogRestarting"));
        else
            AppendLog(LocalizationService.GetString("Twk_LogRestartLater"));
    }

    private void LogResult(string labelKey, bool success)
    {
        var label = LocalizationService.GetString(labelKey);
        AppendLog(success
            ? LocalizationService.Format("Twk_LogOk", label)
            : LocalizationService.Format("Twk_LogFail", label));
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
        OnPropertyChanged(nameof(IsBusy));
        OnPropertyChanged(nameof(CanApply));
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
