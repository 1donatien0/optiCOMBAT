using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using optiCombat.Localization;
using optiCombat.Services;

namespace optiCombat.WinUI.Services;

/// <summary>
/// Localisation des libellés XAML par propriétés attachées, à partir de <c>UiStrings.resx</c> /
/// <c>UiStrings.en.resx</c> :
/// <code>
/// xmlns:loc="using:optiCombat.WinUI.Services"
/// &lt;TextBlock loc:Loc.Text="Nav_Home" /&gt;
/// &lt;Button loc:Loc.Content="Av_Restore" loc:Loc.Tip="Av_Restore" /&gt;
/// &lt;TextBox loc:Loc.Placeholder="Hist_SearchPlaceholder" /&gt;
/// &lt;TabViewItem loc:Loc.Header="Av_TabScan" /&gt;
/// </code>
/// Les éléments sont suivis par référence faible : au changement de langue
/// (<see cref="LocalizationService.CultureChanged"/>), tous les libellés encore vivants sont
/// réappliqués sans recréer les pages. <c>Tip</c> pose aussi le nom d'accessibilité.
/// </summary>
public static class Loc
{
    public static readonly DependencyProperty TextProperty = Register("Text");
    public static readonly DependencyProperty ContentProperty = Register("Content");
    public static readonly DependencyProperty HeaderProperty = Register("Header");
    public static readonly DependencyProperty PlaceholderProperty = Register("Placeholder");
    public static readonly DependencyProperty TipProperty = Register("Tip");

    private static readonly List<WeakReference<DependencyObject>> Tracked = new();
    private static readonly object Gate = new();

    static Loc()
    {
        LocalizationService.CultureChanged += (_, _) => RefreshAll();
    }

    public static string GetText(DependencyObject d) => (string)d.GetValue(TextProperty);
    public static void SetText(DependencyObject d, string value) => d.SetValue(TextProperty, value);
    public static string GetContent(DependencyObject d) => (string)d.GetValue(ContentProperty);
    public static void SetContent(DependencyObject d, string value) => d.SetValue(ContentProperty, value);
    public static string GetHeader(DependencyObject d) => (string)d.GetValue(HeaderProperty);
    public static void SetHeader(DependencyObject d, string value) => d.SetValue(HeaderProperty, value);
    public static string GetPlaceholder(DependencyObject d) => (string)d.GetValue(PlaceholderProperty);
    public static void SetPlaceholder(DependencyObject d, string value) => d.SetValue(PlaceholderProperty, value);
    public static string GetTip(DependencyObject d) => (string)d.GetValue(TipProperty);
    public static void SetTip(DependencyObject d, string value) => d.SetValue(TipProperty, value);

    /// <summary>Réapplique tous les libellés suivis (appelé automatiquement au changement de langue).</summary>
    public static void RefreshAll()
    {
        List<DependencyObject> alive = new();
        lock (Gate)
        {
            Tracked.RemoveAll(w => !w.TryGetTarget(out _));
            foreach (var w in Tracked)
            {
                if (w.TryGetTarget(out var d))
                    alive.Add(d);
            }
        }

        foreach (var d in alive)
        {
            try
            {
                if (d.DispatcherQueue is { } queue && !queue.HasThreadAccess)
                    queue.TryEnqueue(() => ApplyAll(d));
                else
                    ApplyAll(d);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("Loc", "RefreshAll", ex);
            }
        }
    }

    private static DependencyProperty Register(string name) =>
        DependencyProperty.RegisterAttached(
            name,
            typeof(string),
            typeof(Loc),
            new PropertyMetadata(string.Empty, OnKeyChanged));

    private static void OnKeyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (e.NewValue is not string key || string.IsNullOrWhiteSpace(key))
            return;

        Track(d);
        ApplyAll(d);
    }

    private static void Track(DependencyObject d)
    {
        lock (Gate)
        {
            foreach (var w in Tracked)
            {
                if (w.TryGetTarget(out var existing) && ReferenceEquals(existing, d))
                    return;
            }

            Tracked.Add(new WeakReference<DependencyObject>(d));
        }
    }

    private static void ApplyAll(DependencyObject d)
    {
        var text = GetText(d);
        if (!string.IsNullOrWhiteSpace(text) && d is TextBlock tb)
            tb.Text = LocalizationService.GetString(text);

        var content = GetContent(d);
        if (!string.IsNullOrWhiteSpace(content) && d is ContentControl cc)
            cc.Content = LocalizationService.GetString(content);

        var header = GetHeader(d);
        if (!string.IsNullOrWhiteSpace(header))
            ApplyHeader(d, LocalizationService.GetString(header));

        var placeholder = GetPlaceholder(d);
        if (!string.IsNullOrWhiteSpace(placeholder))
            ApplyPlaceholder(d, LocalizationService.GetString(placeholder));

        var tip = GetTip(d);
        if (!string.IsNullOrWhiteSpace(tip))
        {
            var value = LocalizationService.GetString(tip);
            ToolTipService.SetToolTip(d, value);
            AutomationProperties.SetName(d, value);
        }
    }

    private static void ApplyHeader(DependencyObject d, string value)
    {
        switch (d)
        {
            case TabViewItem t: t.Header = value; break;
            case PivotItem p: p.Header = value; break;
            case ToggleSwitch s: s.Header = value; break;
            case NumberBox n: n.Header = value; break;
            case TextBox t: t.Header = value; break;
            case ComboBox c: c.Header = value; break;
            case Expander x: x.Header = value; break;
        }
    }

    private static void ApplyPlaceholder(DependencyObject d, string value)
    {
        switch (d)
        {
            case TextBox t: t.PlaceholderText = value; break;
            case PasswordBox p: p.PlaceholderText = value; break;
            case AutoSuggestBox a: a.PlaceholderText = value; break;
            case ComboBox c: c.PlaceholderText = value; break;
            case NumberBox n: n.PlaceholderText = value; break;
        }
    }
}
