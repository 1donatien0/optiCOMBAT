using Microsoft.UI.Xaml;
using System.Runtime.InteropServices;
using optiCombat.Services;
using WinRT.Interop;

namespace optiCombat.WinUI.Services;

/// <summary>Branche un hook WndProc Win32 sur une fenêtre WinUI 3.</summary>
internal static class WinUiWindowMessageHook
{
    private static readonly Dictionary<nuint, HookState> Hooks = new();
    private static readonly SubclassProc SubclassCallback = OnSubclassProc;
    private static nuint _nextId = 1;

    public static void Hook(Window window, int messageId, Action handler)
    {
        ArgumentNullException.ThrowIfNull(window);
        ArgumentNullException.ThrowIfNull(handler);

        void EnsureHook()
        {
            var hwnd = WindowNative.GetWindowHandle(window);
            if (hwnd == IntPtr.Zero)
                return;

            if (!Hooks.TryGetValue((nuint)hwnd, out var state))
            {
                var id = _nextId++;
                if (!SetWindowSubclass(hwnd, SubclassCallback, id, IntPtr.Zero))
                    return;

                state = new HookState(id);
                Hooks[(nuint)hwnd] = state;
            }

            state.Handlers[messageId] = handler;
        }

        window.Activated += (_, _) => EnsureHook();
        EnsureHook();
    }

    private static IntPtr OnSubclassProc(
        IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam, nuint idSubclass, IntPtr dwRefData)
    {
        if (Hooks.TryGetValue((nuint)hWnd, out var state) && state.Handlers.TryGetValue(msg, out var handler))
        {
            try { handler(); }
            catch (Exception ex) { AppLogger.Warn("WinUiWindowMessageHook", "Handler", ex); }
            return IntPtr.Zero;
        }

        return DefSubclassProc(hWnd, msg, wParam, lParam);
    }

    private sealed class HookState
    {
        public HookState(nuint id) => SubclassId = id;
        public nuint SubclassId { get; }
        public Dictionary<int, Action> Handlers { get; } = new();
    }

    private delegate IntPtr SubclassProc(
        IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam, nuint idSubclass, IntPtr dwRefData);

    [DllImport("comctl32.dll", SetLastError = true)]
    private static extern bool SetWindowSubclass(
        IntPtr hWnd, SubclassProc pfnSubclass, nuint uIdSubclass, IntPtr dwRefData);

    [DllImport("comctl32.dll")]
    private static extern IntPtr DefSubclassProc(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
}
