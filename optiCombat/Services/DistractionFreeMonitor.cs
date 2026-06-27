using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace optiCombat.Services
{
    /// <summary>
    /// Détecte plein écran / applications connues « jeu » pour suspendre toasts et scans headless.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class DistractionFreeMonitor
    {
        private static readonly HashSet<string> KnownGameProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "steam", "steamwebhelper", "EpicGamesLauncher", "FortniteClient-Win64-Shipping",
            "League of Legends", "RiotClientServices", "cs2", "valorant-win64-shipping",
            "GenshinImpact", "Overwatch", "cod", "eldenring",
        };

        private static System.Threading.Timer? _timer;
        private static volatile bool _active;
        private static long _lastCheckUtcTicks;
        private static IUserPreferencesAccessor _prefs = new DefaultUserPreferencesAccessor();

        public static bool IsActive => _active;

        public static void Initialize(IUserPreferencesAccessor? preferences = null)
        {
            if (preferences != null)
                _prefs = preferences;
        }

        public static void Start(TimeSpan? interval = null)
        {
            if (_timer != null) return;
            var period = interval ?? TimeSpan.FromSeconds(20);
            _timer = new System.Threading.Timer(_ => Refresh(), null, TimeSpan.Zero, period);
        }

        public static void Stop()
        {
            _timer?.Dispose();
            _timer = null;
            _active = false;
        }

        public static bool ShouldSuppressNotifications()
        {
            if (!_prefs.Current.GameModeAutoEnabled)
                return false;
            if ((DateTime.UtcNow - LastCheckUtc) > TimeSpan.FromSeconds(25))
                Refresh();
            return _active;
        }

        private static DateTime LastCheckUtc =>
            new(Volatile.Read(ref _lastCheckUtcTicks), DateTimeKind.Utc);

        /// <summary>Heuristique nom de processus « jeu » (tests unitaires).</summary>
        internal static bool IsKnownGameProcessName(string processName) =>
            KnownGameProcesses.Contains(processName);

        /// <summary>Réinitialise l'état pour les tests (InternalsVisibleTo).</summary>
        internal static void ResetForTests(bool active = false)
        {
            Stop();
            _active = active;
            Volatile.Write(ref _lastCheckUtcTicks, DateTime.UtcNow.Ticks);
        }

        private static void Refresh()
        {
            Volatile.Write(ref _lastCheckUtcTicks, DateTime.UtcNow.Ticks);
            try
            {
                _active = IsForegroundFullscreen() || IsKnownGameProcessRunning();
            }
            catch
            {
                _active = false;
            }
        }

        private static bool IsForegroundFullscreen()
        {
            var hwnd = GetForegroundWindow();
            if (hwnd == IntPtr.Zero) return false;

            if (!GetWindowRect(hwnd, out var rect))
                return false;

            int w = rect.Right - rect.Left;
            int h = rect.Bottom - rect.Top;
            if (w < 100 || h < 100) return false;

            var screen = System.Windows.Forms.Screen.FromHandle(hwnd);
            var bounds = screen.Bounds;
            return w >= bounds.Width - 8 && h >= bounds.Height - 8;
        }

        private static bool IsKnownGameProcessRunning()
        {
            foreach (var name in KnownGameProcesses)
            {
                Process[] procs;
                try
                {
                    procs = Process.GetProcessesByName(name);
                }
                catch
                {
                    continue;
                }

                try
                {
                    if (procs.Length > 0)
                        return true;
                }
                finally
                {
                    foreach (var proc in procs)
                        proc.Dispose();
                }
            }

            return false;
        }

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public int Left, Top, Right, Bottom;
        }
    }
}
