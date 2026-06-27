using optiCombat.Localization;
using System.IO;
using System.Windows.Forms;

namespace optiCombat.Services
{
    /// <summary>
    /// Icône et menu contextuel de la zone de notification Windows.
    /// Extrait de <c>MainWindow</c> pour réduire la taille de la fenêtre principale.
    /// </summary>
    public sealed class SystemTrayHost : IDisposable
    {
        private NotifyIcon? _icon;
        private ContextMenuStrip? _menu;
        private bool _disposed;

        /// <summary>Crée l'icône tray et le menu (idempotent si déjà initialisé).</summary>
        public void Initialize(Action showMainWindow, Action exitApplication)
        {
            ArgumentNullException.ThrowIfNull(showMainWindow);
            ArgumentNullException.ThrowIfNull(exitApplication);

            if (_icon != null)
                return;

            _menu = new ContextMenuStrip();
            _menu.Items.Add(LocalizationService.GetString("Tray_Open"), null, (_, _) => showMainWindow());
            _menu.Items.Add(new ToolStripSeparator());
            _menu.Items.Add(LocalizationService.GetString("Tray_Exit"), null, (_, _) => exitApplication());

            _icon = new NotifyIcon
            {
                Text = LocalizationService.GetString("Tray_Tooltip"),
                Icon = ResolveTrayIcon(),
                Visible = true,
                ContextMenuStrip = _menu
            };

            _icon.MouseClick += (_, e) =>
            {
                if (e.Button == MouseButtons.Left)
                    showMainWindow();
            };
            _icon.DoubleClick += (_, _) => showMainWindow();
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            if (_icon != null)
            {
                _icon.Visible = false;
                _icon.Dispose();
                _icon = null;
            }

            _menu?.Dispose();
            _menu = null;
        }

        /// <summary>Résout l'icône tray (exe embarqué, optiCombat.ico, icône système).</summary>
        public static Icon ResolveTrayIcon()
        {
            try
            {
                var processPath = Environment.ProcessPath;
                if (!string.IsNullOrWhiteSpace(processPath) && File.Exists(processPath))
                {
                    var embedded = Icon.ExtractAssociatedIcon(processPath);
                    if (embedded != null)
                        return embedded;
                }
            }
            catch
            {
                // Repli fichier.
            }

            try
            {
                var iconPath = Path.Combine(AppContext.BaseDirectory, "optiCombat.ico");
                if (File.Exists(iconPath))
                    return new Icon(iconPath);
            }
            catch
            {
                // Repli système.
            }

            return SystemIcons.Application;
        }
    }
}
