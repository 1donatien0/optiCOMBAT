using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace optiCombat.Converters
{
    /// <summary>bool true → Collapsed, false → Visible (inverse de BooleanToVisibilityConverter).</summary>
    public sealed class InverseBooleanToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            var visible = value is bool b && b;
            return visible ? Visibility.Collapsed : Visibility.Visible;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}
