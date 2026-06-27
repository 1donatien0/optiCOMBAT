using MaterialDesignThemes.Wpf;
using optiCombat.Localization;
using optiCombat.Services;
using optiCombat.ViewModels;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace optiCombat.Coordinators;

/// <summary>Barre d'état basse : scan, mise à jour signatures, message épinglé.</summary>
public sealed class StatusFooterCoordinator
{
    private string? _lastStatusText;
    private bool _lastStatusIsError;
    private bool _lastStatusIsWarning;
    private string? _lastStatusIconKind;

    public void SetStatus(
        string text,
        bool isError,
        bool isWarning,
        string? iconKindName,
        TextBlock? label,
        PackIcon? icon,
        Func<bool> isLiveFooterActive,
        Action applyPinnedOrLive)
    {
        _lastStatusText = text;
        _lastStatusIsError = isError;
        _lastStatusIsWarning = isWarning;
        _lastStatusIconKind = iconKindName;

        if (!isLiveFooterActive())
            applyPinnedOrLive();
    }

    public void OnThemeChanged(Func<bool> isLiveFooterActive, Action applyPinnedOrLive)
    {
        if (_lastStatusText != null)
            applyPinnedOrLive();
    }

    public void RefreshLiveFooter(
        ScanViewModel? viewModel,
        TextBlock? label,
        PackIcon? icon,
        UIElement? spinner,
        Func<bool> isSignatureUpdateRunning)
    {
        if (viewModel == null)
            return;

        // Ces contrôles WPF n'appartiennent qu'au thread UI. Si l'appel vient d'un
        // thread d'arrière-plan (fin de mise à jour signatures, warmup YARA, timers),
        // on rebascule sur le Dispatcher — sinon WPF lève InvalidOperationException
        // (« calling thread cannot access this object ») qui fait tomber le process.
        var dispatcher = label?.Dispatcher ?? icon?.Dispatcher ?? spinner?.Dispatcher;
        if (dispatcher != null && !dispatcher.CheckAccess())
        {
            dispatcher.Invoke(() =>
                RefreshLiveFooter(viewModel, label, icon, spinner, isSignatureUpdateRunning));
            return;
        }

        if (viewModel.IsScanning)
        {
            if (spinner != null)
                spinner.Visibility = Visibility.Visible;
            if (icon != null)
                icon.Visibility = Visibility.Collapsed;
            StopRefreshSpin(icon);

            var detail = viewModel.ScanProgressDetail;
            if (label != null)
            {
                label.Text = string.IsNullOrWhiteSpace(detail)
                    ? LocalizationService.GetString("Main_StatusScanning")
                    : detail;
                var textBrush = ThemeUiBrushes.Get("TextMedium", label);
                if (textBrush != null)
                    label.Foreground = textBrush;
            }
            return;
        }

        if (spinner != null)
            spinner.Visibility = Visibility.Collapsed;
        if (icon != null)
            icon.Visibility = Visibility.Visible;

        if (isSignatureUpdateRunning() || viewModel.IsUpdating)
        {
            if (label != null)
            {
                label.Text = LocalizationService.GetString("Main_StatusUpdating");
                var textBrush = ThemeUiBrushes.Get("TextMedium", label);
                if (textBrush != null)
                    label.Foreground = textBrush;
            }

            if (icon != null)
            {
                if (Enum.TryParse<PackIconKind>(UiIconKinds.Refresh, ignoreCase: false, out var kind))
                    icon.Kind = kind;
                var accent = ThemeUiBrushes.Get("AccentBlue", icon);
                if (accent != null)
                    icon.Foreground = accent;
                StartRefreshSpin(icon);
            }
            return;
        }

        StopRefreshSpin(icon);
        ApplyPinnedFooter(label, icon);
    }

    public void ApplyPinnedFooter(TextBlock? label, PackIcon? icon)
    {
        if (_lastStatusText == null)
            return;

        var textKey = _lastStatusIsError ? "DangerRed" : _lastStatusIsWarning ? "AlertGold" : "TextMedium";
        var iconKey = _lastStatusIsError ? "DangerRed" : _lastStatusIsWarning ? "WarningOrange" : "SuccessGreen";
        var textBrush = ThemeUiBrushes.Get(textKey, label) ?? label?.Foreground;
        var iconBrush = ThemeUiBrushes.Get(iconKey, icon) ?? icon?.Foreground;

        if (label != null)
        {
            label.Text = _lastStatusText;
            if (textBrush != null)
                label.Foreground = textBrush;
        }

        if (icon != null)
        {
            var kindName = _lastStatusIconKind ?? UiIconKinds.ForStatusFooter(_lastStatusIsError, _lastStatusIsWarning);
            if (Enum.TryParse<PackIconKind>(kindName, ignoreCase: false, out var kind))
                icon.Kind = kind;
            if (iconBrush != null)
                icon.Foreground = iconBrush;
        }
    }

    private static void StartRefreshSpin(PackIcon? icon)
    {
        if (icon == null)
            return;

        icon.RenderTransformOrigin = new System.Windows.Point(0.5, 0.5);
        if (icon.RenderTransform is not RotateTransform rotate)
        {
            rotate = new RotateTransform();
            icon.RenderTransform = rotate;
        }

        rotate.BeginAnimation(RotateTransform.AngleProperty, new DoubleAnimation(0, 360, TimeSpan.FromSeconds(1.1))
        {
            RepeatBehavior = RepeatBehavior.Forever,
        });
    }

    private static void StopRefreshSpin(PackIcon? icon)
    {
        if (icon?.RenderTransform is RotateTransform rotate)
            rotate.BeginAnimation(RotateTransform.AngleProperty, null);
    }
}
