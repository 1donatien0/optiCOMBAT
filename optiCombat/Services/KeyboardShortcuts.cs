using System.Windows;
using System.Windows.Input;

namespace optiCombat.Services
{
    /// <summary>
    /// Centralisation de l'enregistrement des raccourcis clavier de l'application.
    /// Une seule <see cref="RoutedCommand"/> paramétrée remplace cinq commandes distinctes pour Ctrl+1..Ctrl+5.
    /// </summary>
    public static class KeyboardShortcuts
    {
        /// <summary>
        /// Branche Ctrl+1..Ctrl+5 sur les noms de panneaux fournis dans l'ordre.
        /// </summary>
        public static void Register(Window window, IReadOnlyList<string> panelNames, Action<string> onActivate)
        {
            // Une seule RoutedCommand pour tout le set : on récupère le nom de
            // panneau via le CommandParameter associé au KeyBinding.
            var navCmd = new RoutedCommand();
            window.CommandBindings.Add(new CommandBinding(navCmd, (_, e) =>
            {
                if (e.Parameter is string panel)
                {
                    try { onActivate(panel); }
                    catch (Exception ex) { AppLogger.Warn("KeyboardShortcuts", $"onActivate {panel}", ex); }
                }
            }));

            for (int i = 0; i < panelNames.Count && i < 9; i++)
            {
                var key = (Key)((int)Key.D1 + i);
                window.InputBindings.Add(new KeyBinding(navCmd, key, ModifierKeys.Control)
                {
                    CommandParameter = panelNames[i],
                });
            }
        }
    }
}
