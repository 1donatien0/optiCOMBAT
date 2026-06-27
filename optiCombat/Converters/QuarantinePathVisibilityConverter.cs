using optiCombat.Services;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace optiCombat.Converters
{
    /// <summary>
    /// Visible si le chemin bindé correspond à un fichier encore en quarantaine.
    /// Paramètre <c>NotQuarantined</c> : visible quand le fichier n'est pas en quarantaine.
    /// Assigner <see cref="Quarantine"/> depuis <c>Bind()</c> puis appeler <see cref="RefreshCache"/>
    /// quand la quarantaine change.
    /// </summary>
    public sealed class QuarantinePathVisibilityConverter : IValueConverter
    {
        private QuarantineManager? _quarantine;
        private HashSet<string>? _quarantinedPaths;

        public QuarantineManager? Quarantine
        {
            get => _quarantine;
            set
            {
                _quarantine = value;
                RefreshCache();
            }
        }

        /// <summary>Reconstruit le cache des chemins en quarantaine (O(n) une fois par refresh).</summary>
        public void RefreshCache()
        {
            if (_quarantine == null)
            {
                _quarantinedPaths = null;
                return;
            }

            _quarantinedPaths = new HashSet<string>(
                _quarantine.GetEntries().Select(e => e.OriginalPath),
                StringComparer.OrdinalIgnoreCase);
        }

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            var path = value as string;
            if (_quarantinedPaths == null)
                return Visibility.Collapsed;

            var isQuarantined = !string.IsNullOrWhiteSpace(path)
                && _quarantinedPaths.Contains(path);

            var showWhenNotQuarantined = string.Equals(
                parameter as string, "NotQuarantined", StringComparison.OrdinalIgnoreCase);
            var visible = showWhenNotQuarantined ? !isQuarantined : isQuarantined;
            return visible ? Visibility.Visible : Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}

