using System.Globalization;
using System.Windows.Data;
using MediaBrush = System.Windows.Media.Brush;
using MediaBrushes = System.Windows.Media.Brushes;
using optiCombat.Models;
using optiCombat.Services;
using WpfApplication = System.Windows.Application;

namespace optiCombat.Converters
{
    public sealed class ThreatRiskSeverityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
            => value is ThreatInfo t ? RiskScoringService.Assess(t).Severity : string.Empty;

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }

    public sealed class ThreatRiskLevelConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
            => value is ThreatInfo t ? RiskScoringService.Assess(t).Level : RiskLevel.Informational;

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }

    public sealed class ThreatRiskColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is not ThreatInfo t) return MediaBrushes.Gray;
            var key = RiskScoringService.Assess(t).BrushKey;
            if (string.IsNullOrEmpty(key)) return MediaBrushes.Gray;
            return WpfApplication.Current?.TryFindResource(key) as MediaBrush ?? MediaBrushes.Gray;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}
