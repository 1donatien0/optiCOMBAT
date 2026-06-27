using System.Windows;
using WpfBrush = System.Windows.Media.Brush;

namespace optiCombat.Services
{
    /// <summary>Résolution des pinceaux du thème Donaby (clair / sombre).</summary>
    public static class ThemeUiBrushes
    {
        public static WpfBrush? Get(string resourceKey, FrameworkElement? relativeTo = null)
        {
            if (relativeTo != null)
                return relativeTo.TryFindResource(resourceKey) as WpfBrush;

            var app = System.Windows.Application.Current;
            return app?.TryFindResource(resourceKey) as WpfBrush;
        }
    }
}
