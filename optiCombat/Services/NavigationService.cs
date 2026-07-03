using System.Windows;
using System.Windows.Media.Animation;

namespace optiCombat.Services
{
    /// <summary>
    /// Implémentation WPF de <see cref="INavigationService"/>.
    /// Tous les panneaux sont gardés en mémoire ; seul le panneau actif est visible.
    /// </summary>
    public class NavigationService : INavigationService
    {
        private static readonly TimeSpan PanelFadeInDuration  = TimeSpan.FromMilliseconds(180);
        private static readonly TimeSpan PanelFadeOutDuration = TimeSpan.FromMilliseconds(100);

        private readonly Dictionary<string, UIElement> _panels = new(StringComparer.OrdinalIgnoreCase);

        public string CurrentView { get; private set; } = string.Empty;

        /// <inheritdoc/>
        public event EventHandler<string>? Navigated;

        /// <inheritdoc/>
        public void RegisterPanel(string name, UIElement panel)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Le nom du panneau ne peut pas être vide.", nameof(name));

            ArgumentNullException.ThrowIfNull(panel);

            if (!_panels.ContainsKey(name))
            {
                panel.Opacity = panel.Visibility == Visibility.Visible ? 1 : 0;
                _panels.Add(name, panel);
            }
        }

        /// <inheritdoc/>
        public void NavigateTo(string name)
        {
            if (!_panels.TryGetValue(name, out var target))
            {
                AppLogger.Warn("NavigationService", $"Panneau inconnu : '{name}'");
                return;
            }

            foreach (var panel in _panels.Values)
            {
                if (panel == target) continue;
                if (panel.Visibility != Visibility.Visible)
                {
                    panel.BeginAnimation(UIElement.OpacityProperty, null);
                    panel.Opacity = 0;
                    panel.Visibility = Visibility.Collapsed;
                    continue;
                }
                // Fade sortant 1→0 puis Collapsed
                var fadeOut = new DoubleAnimation(1, 0, PanelFadeOutDuration)
                {
                    EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseIn }
                };
                var capturedPanel = panel;
                fadeOut.Completed += (_, _) =>
                {
                    capturedPanel.BeginAnimation(UIElement.OpacityProperty, null);
                    capturedPanel.Opacity = 0;
                    capturedPanel.Visibility = Visibility.Collapsed;
                };
                panel.BeginAnimation(UIElement.OpacityProperty, fadeOut);
            }

            target.Visibility = Visibility.Visible;
            target.BeginAnimation(UIElement.OpacityProperty, null);
            target.Opacity = 0;

            var fadeIn = new DoubleAnimation(0, 1, PanelFadeInDuration)
            {
                EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
            };
            target.BeginAnimation(UIElement.OpacityProperty, fadeIn);

            CurrentView = name;
            Navigated?.Invoke(this, name);
        }

        /// <inheritdoc/>
        public bool HasPanel(string name)
            => !string.IsNullOrWhiteSpace(name) && _panels.ContainsKey(name);
    }
}
