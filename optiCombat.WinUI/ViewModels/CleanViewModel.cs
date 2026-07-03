using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace optiCombat.WinUI.ViewModels;

public sealed class CleanViewModel : INotifyPropertyChanged
{
    private readonly ServiceContainer _container;
    private readonly ScanLogManager _logger;

    private bool _isBusy;
    private bool _canClean;
    private bool _tempWin = true;
    private bool _tempUser = true;
    private bool _recycle = true;
    private bool _logs;
    private bool _edge = true;
    private bool _chrome = true;
    private bool _firefox = true;
    private bool _brave;
    private bool _opera;
    private bool _vivaldi;
    private bool _arc;
    private string _tempSize = "0 Mo";
    private string _browserSize = "0 Mo";
    private string _totalSize = "0 Mo";
    private string _logText = "";

    public CleanViewModel(ServiceContainer container)
    {
        _container = container;
        _logger = container.Logger;
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set { _isBusy = value; OnPropertyChanged(); OnPropertyChanged(nameof(CanAnalyze)); }
    }

    public bool CanAnalyze => !IsBusy;
    public bool CanClean => !IsBusy && _canClean;

    public bool TempWin { get => _tempWin; set { _tempWin = value; OnPropertyChanged(); } }
    public bool TempUser { get => _tempUser; set { _tempUser = value; OnPropertyChanged(); } }
    public bool Recycle { get => _recycle; set { _recycle = value; OnPropertyChanged(); } }
    public bool Logs { get => _logs; set { _logs = value; OnPropertyChanged(); } }
    public bool Edge { get => _edge; set { _edge = value; OnPropertyChanged(); } }
    public bool Chrome { get => _chrome; set { _chrome = value; OnPropertyChanged(); } }
    public bool Firefox { get => _firefox; set { _firefox = value; OnPropertyChanged(); } }
    public bool Brave { get => _brave; set { _brave = value; OnPropertyChanged(); } }
    public bool Opera { get => _opera; set { _opera = value; OnPropertyChanged(); } }
    public bool Vivaldi { get => _vivaldi; set { _vivaldi = value; OnPropertyChanged(); } }
    public bool Arc { get => _arc; set { _arc = value; OnPropertyChanged(); } }

    public string TempSize { get => _tempSize; private set { _tempSize = value; OnPropertyChanged(); } }
    public string BrowserSize { get => _browserSize; private set { _browserSize = value; OnPropertyChanged(); } }
    public string TotalSize { get => _totalSize; private set { _totalSize = value; OnPropertyChanged(); } }
    public string LogText { get => _logText; private set { _logText = value; OnPropertyChanged(); } }

    public event PropertyChangedEventHandler? PropertyChanged;

    public CleanSelection BuildSelection() => new()
    {
        TempWin = TempWin,
        TempUser = TempUser,
        Recycle = Recycle,
        Logs = Logs,
        Edge = Edge,
        Chrome = Chrome,
        Firefox = Firefox,
        Brave = Brave,
        Opera = Opera,
        Vivaldi = Vivaldi,
        Arc = Arc
    };

    public async Task AnalyzeAsync()
    {
        var sel = BuildSelection();
        if (!sel.AnySelected)
        {
            AppendLog(LocalizationService.GetString("Clean_LogHint"));
            return;
        }

        IsBusy = true;
        _canClean = false;
        OnPropertyChanged(nameof(CanClean));
        AppendLog(LocalizationService.GetString("Clean_LogAnalyzeStart"), clear: true);

        var result = await Task.Run(() => SystemCleanService.Analyze(sel)).ConfigureAwait(true);
        TempSize = ByteSizeFormat.Format(result.SystemTotal);
        BrowserSize = ByteSizeFormat.Format(result.BrowserTotal);
        TotalSize = ByteSizeFormat.Format(result.GrandTotal);
        AppendLog(LocalizationService.Format("Clean_LogTotal", ByteSizeFormat.Format(result.GrandTotal)));
        AppendLog(LocalizationService.GetString("Clean_LogAnalyzeEnd"));
        _canClean = result.GrandTotal > 0;
        OnPropertyChanged(nameof(CanClean));
        IsBusy = false;
    }

    public async Task CleanAsync()
    {
        if (!CanClean)
            return;

        var sel = BuildSelection();
        IsBusy = true;
        OnPropertyChanged(nameof(CanClean));
        AppendLog(LocalizationService.GetString("Clean_LogCleanStart"));
        var started = DateTime.Now;

        try
        {
            var exec = await Task.Run(() => SystemCleanService.Execute(sel, line => AppendLog(line))).ConfigureAwait(true);
            AppendLog(LocalizationService.GetString("Clean_LogCleanEnd"));
            TempSize = ByteSizeFormat.Format(0);
            BrowserSize = ByteSizeFormat.Format(0);
            TotalSize = ByteSizeFormat.Format(0);
            _canClean = false;
            OnPropertyChanged(nameof(CanClean));

            _logger.SaveCleanSession(new CleanSession
            {
                StartedAt = started,
                FinishedAt = DateTime.Now,
                TargetsSummary = SystemCleanService.BuildTargetsSummary(sel),
                BytesFreed = exec.BytesFreed,
                OperationLog = LogText
            });
            _container.RequestScanHistoryViewsRefresh();
        }
        catch (Exception ex)
        {
            AppendLog(LocalizationService.Format("Clean_ErrCleaning", ex.Message));
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void AppendLog(string line, bool clear = false)
    {
        var entry = $"[{DateTime.Now:HH:mm:ss}] {line}";
        LogText = clear ? entry + Environment.NewLine : LogText + entry + Environment.NewLine;
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
