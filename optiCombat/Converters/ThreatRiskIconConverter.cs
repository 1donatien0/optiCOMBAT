using System.Globalization;
using System.Windows.Data;
using MaterialDesignThemes.Wpf;
using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Converters
{
    /// <summary>Menace → icône Material Design pour la colonne Risque.</summary>
    public sealed class ThreatRiskIconConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is not ThreatInfo t)
                return PackIconKind.InformationOutline;

            var kindName = RiskScoringService.Assess(t).IconKind;
            return Enum.TryParse<PackIconKind>(kindName, ignoreCase: false, out var kind)
                ? kind
                : PackIconKind.Alert;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}
