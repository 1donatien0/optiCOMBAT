using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace optiCombat.WinUI.Services;

/// <summary>Convertit un booléen en <see cref="Visibility"/> (true = visible).</summary>
public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language) =>
        value is true ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        value is Visibility.Visible;
}
