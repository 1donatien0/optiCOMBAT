using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using optiCombat.Localization;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.WinUI.Services;

/// <summary>Barre d'état — message épinglé, scan en cours, mise à jour des signatures.</summary>
public sealed class WinUiStatusFooterCoordinator
{
    private string? _lastStatusText;
    private bool _lastStatusIsError;
    private bool _lastStatusIsWarning;

    public void SetStatus(
        string text,
        bool isError,
        bool isWarning,
        TextBlock? label,
        ProgressRing? ring,
        FontIcon? icon,
        Func<bool> isLiveFooterActive)
    {
        _lastStatusText = text;
        _lastStatusIsError = isError;
        _lastStatusIsWarning = isWarning;

        if (!isLiveFooterActive())
            ApplyPinnedFooter(label, ring, icon);
    }

    public void RefreshLiveFooter(
        AntivirusViewModel? viewModel,
        TextBlock? label,
        ProgressRing? ring,
        FontIcon? icon)
    {
        if (viewModel == null)
            return;

        if (viewModel.IsScanning)
        {
            if (ring != null)
            {
                ring.Visibility = Visibility.Visible;
                ring.IsActive = true;
            }
            if (icon != null)
                icon.Visibility = Visibility.Collapsed;

            if (label != null)
            {
                var detail = viewModel.CurrentScanItem;
                label.Text = string.IsNullOrWhiteSpace(detail)
                    ? LocalizationService.GetString("Main_StatusScanning")
                    : detail;
                ThemeBrush.SetForegroundKey(label, "TextMutedBrush");
            }
            return;
        }

        if (ring != null)
        {
            ring.Visibility = Visibility.Collapsed;
            ring.IsActive = false;
        }
        if (icon != null)
            icon.Visibility = Visibility.Visible;

        if (viewModel.IsUpdating)
        {
            if (label != null)
            {
                label.Text = LocalizationService.GetString("Main_StatusUpdating");
                ThemeBrush.SetForegroundKey(label, "AccentBrush");
            }

            if (icon != null)
            {
                icon.Glyph = "\uE72C";
                ThemeBrush.SetForegroundKey(icon, "AccentBrush");
            }
            return;
        }

        ApplyPinnedFooter(label, ring, icon);
    }

    public void ApplyPinnedFooter(TextBlock? label, ProgressRing? ring, FontIcon? icon)
    {
        if (_lastStatusText == null)
            return;

        if (ring != null)
        {
            ring.Visibility = Visibility.Collapsed;
            ring.IsActive = false;
        }
        if (icon != null)
            icon.Visibility = Visibility.Visible;

        var toneKey = _lastStatusIsError ? "DangerBrush" : _lastStatusIsWarning ? "WarningBrush" : "SuccessGreen";
        if (label != null)
        {
            label.Text = _lastStatusText;
            ThemeBrush.SetForegroundKey(
                label,
                _lastStatusIsError || _lastStatusIsWarning ? toneKey : "TextMutedBrush");
        }

        if (icon != null)
        {
            icon.Glyph = _lastStatusIsError ? "\uE783" : _lastStatusIsWarning ? "\uE7BA" : "\uE735";
            ThemeBrush.SetForegroundKey(icon, toneKey);
        }
    }
}
