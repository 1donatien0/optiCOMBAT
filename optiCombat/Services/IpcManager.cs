using System.Windows;
using System.Windows.Interop;

namespace optiCombat.Services
{
    /// <summary>
    /// Communication inter-instance WPF : délègue à <see cref="SingleInstanceMessaging"/>.
    /// </summary>
    public static class IpcManager
    {
        public const int HWND_BROADCAST = SingleInstanceMessaging.HwndBroadcast;

        public static int WM_SHOWME => SingleInstanceMessaging.WmShowMe;

        public static int WM_SHELL_SCAN => SingleInstanceMessaging.WmShellScan;

        public static void NotifyShowExistingInstance() =>
            SingleInstanceMessaging.NotifyShowExistingInstance();

        public static void NotifyShellScanRequest() =>
            SingleInstanceMessaging.NotifyShellScanRequest();

        public static void HookShowMessage(Window window, Action onShow) =>
            HookMessage(window, WM_SHOWME, onShow);

        public static void HookShellScanRequest(Window window, Action onShellScan) =>
            HookMessage(window, WM_SHELL_SCAN, onShellScan);

        private static void HookMessage(Window window, int messageId, Action handler)
        {
            window.SourceInitialized += (_, _) =>
            {
                if (PresentationSource.FromVisual(window) is HwndSource src)
                {
                    src.AddHook((IntPtr h, int m, IntPtr w, IntPtr l, ref bool handled) =>
                    {
                        if (m == messageId)
                        {
                            try { handler(); } catch (Exception ex) { AppLogger.Warn("IpcManager", "HookMessage", ex); }
                            handled = true;
                        }
                        return IntPtr.Zero;
                    });
                }
            };
        }
    }
}
