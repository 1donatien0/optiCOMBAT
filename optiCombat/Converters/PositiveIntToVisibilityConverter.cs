using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace optiCombat.Converters
{
    /// <summary>Visible si l'entier bindé est strictement positif.</summary>
    public sealed class PositiveIntToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            var n = value switch
            {
                int i => i,
                long l => (int)Math.Min(int.MaxValue, l),
                _ => 0
            };
            return n > 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}
