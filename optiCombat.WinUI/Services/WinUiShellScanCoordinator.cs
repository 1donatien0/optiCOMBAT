using optiCombat.Services;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.WinUI.Services;

/// <summary>Scan menu contextuel Explorateur pour le shell WinUI.</summary>
public sealed class WinUiShellScanCoordinator
{
    private readonly AntivirusViewModel _antivirus;
    private readonly Action<string> _navigateToAntivirus;
    private readonly Action _showWindow;

    public WinUiShellScanCoordinator(
        AntivirusViewModel antivirus,
        Action<string> navigateToAntivirus,
        Action showWindow)
    {
        _antivirus = antivirus;
        _navigateToAntivirus = navigateToAntivirus;
        _showWindow = showWindow;
    }

    public async Task RunShellScanAsync(string path)
    {
        if (!ShellScanArguments.IsValidScanTarget(path))
            return;

        _navigateToAntivirus("antivirus");
        _showWindow();
        await _antivirus.RequestContextMenuScanAsync(path).ConfigureAwait(true);
    }

    public async Task OnShellScanRequestedAsync()
    {
        var path = ShellScanRequest.TryConsume();
        if (!string.IsNullOrWhiteSpace(path))
            await RunShellScanAsync(path).ConfigureAwait(true);
        _showWindow();
    }
}
