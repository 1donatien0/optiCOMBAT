using optiCombat.Localization;
using System.Drawing;
using System.Runtime.InteropServices;

namespace optiCombat.WinUI.Services;

/// <summary>Icône zone de notification Win32 pour le shell WinUI 3.</summary>
public sealed class WinUiTrayHost : IDisposable
{
    private const int WmUser = 0x0400;
    private const int WmTrayIcon = WmUser + 1;
    private const int NimAdd = 0x00000000;
    private const int NimModify = 0x00000001;
    private const int NimDelete = 0x00000002;
    private const int NifMessage = 0x00000001;
    private const int NifIcon = 0x00000002;
    private const int NifTip = 0x00000004;
    private const int NifShowTip = 0x00000080;
    private const int WmLButtonUp = 0x0202;
    private const int WmLButtonDblClk = 0x0203;
    private const int WmRButtonUp = 0x0205;
    private const int MfString = 0x00000000;
    private const int MfSeparator = 0x00000800;
    private const int TpmRightButton = 0x0002;
    private const int TpmReturnCmd = 0x0100;

    private readonly uint _id = 1;
    private IntPtr _hwnd = IntPtr.Zero;
    private IntPtr _iconHandle = IntPtr.Zero;
    private Action? _showMainWindow;
    private Action? _exitApplication;
    private bool _disposed;
    private WndProcDelegate? _wndProc;

    public void Initialize(IntPtr windowHandle, Action showMainWindow, Action exitApplication)
    {
        ArgumentNullException.ThrowIfNull(showMainWindow);
        ArgumentNullException.ThrowIfNull(exitApplication);

        if (_hwnd != IntPtr.Zero)
            return;

        _showMainWindow = showMainWindow;
        _exitApplication = exitApplication;
        _iconHandle = LoadTrayIconHandle();

        _wndProc = TrayWndProc;
        _hwnd = CreateMessageWindow();

        var data = CreateNotifyData(NimAdd);
        Shell_NotifyIcon(NimAdd, ref data);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        if (_hwnd != IntPtr.Zero)
        {
            var data = CreateNotifyData(NimDelete);
            Shell_NotifyIcon(NimDelete, ref data);
            DestroyWindow(_hwnd);
            _hwnd = IntPtr.Zero;
        }

        if (_iconHandle != IntPtr.Zero)
        {
            DestroyIcon(_iconHandle);
            _iconHandle = IntPtr.Zero;
        }
    }

    public bool TryHandleMessage(int msg, IntPtr wParam, IntPtr lParam)
    {
        if (msg != WmTrayIcon)
            return false;

        var mouseMsg = (uint)lParam.ToInt64();
        switch (mouseMsg)
        {
            case WmLButtonUp:
            case WmLButtonDblClk:
                _showMainWindow?.Invoke();
                return true;
            case WmRButtonUp:
                ShowContextMenu();
                return true;
        }

        return false;
    }

    private void ShowContextMenu()
    {
        var menu = CreatePopupMenu();
        if (menu == IntPtr.Zero)
            return;

        AppendMenu(menu, MfString, 1, LocalizationService.GetString("Tray_Open"));
        AppendMenu(menu, MfSeparator, 0, null);
        AppendMenu(menu, MfString, 2, LocalizationService.GetString("Tray_Exit"));

        GetCursorPos(out var pt);
        SetForegroundWindow(_hwnd);
        var cmd = TrackPopupMenuEx(menu, TpmRightButton | TpmReturnCmd, pt.X, pt.Y, _hwnd, IntPtr.Zero);
        DestroyMenu(menu);

        if (cmd == 1) _showMainWindow?.Invoke();
        else if (cmd == 2) _exitApplication?.Invoke();
    }

    private NOTIFYICONDATA CreateNotifyData(int operation)
    {
        return new NOTIFYICONDATA
        {
            cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATA>(),
            hWnd = _hwnd,
            uID = _id,
            uFlags = NifMessage | NifIcon | NifTip | NifShowTip,
            uCallbackMessage = WmTrayIcon,
            hIcon = _iconHandle,
            szTip = LocalizationService.GetString("Tray_Tooltip"),
        };
    }

    private IntPtr CreateMessageWindow()
    {
        var className = $"optiCombatWinUiTray_{Guid.NewGuid():N}";
        var wc = new WNDCLASS
        {
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(_wndProc!),
            lpszClassName = className,
        };
        RegisterClass(ref wc);
        return CreateWindowEx(0, className, className, 0, 0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
    }

    private IntPtr TrayWndProc(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam)
    {
        if (TryHandleMessage(msg, wParam, lParam))
            return IntPtr.Zero;
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }

    private static IntPtr LoadTrayIconHandle()
    {
        try
        {
            var processPath = Environment.ProcessPath;
            if (!string.IsNullOrWhiteSpace(processPath))
            {
                var extracted = Icon.ExtractAssociatedIcon(processPath);
                if (extracted != null)
                    return extracted.Handle;
            }
        }
        catch { }

        try
        {
            var iconPath = Path.Combine(AppContext.BaseDirectory, "optiCombat.ico");
            if (File.Exists(iconPath))
            {
                using var icon = new Icon(iconPath);
                return icon.Handle;
            }
        }
        catch { }

        return LoadIcon(IntPtr.Zero, new IntPtr(32512)); // IDI_APPLICATION
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATA
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WNDCLASS
    {
        public uint style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        public string lpszMenuName;
        public string lpszClassName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X;
        public int Y;
    }

    private delegate IntPtr WndProcDelegate(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Shell_NotifyIcon(int dwMessage, ref NOTIFYICONDATA lpData);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern ushort RegisterClass(ref WNDCLASS lpWndClass);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateWindowEx(
        int dwExStyle, string lpClassName, string lpWindowName, int dwStyle,
        int x, int y, int nWidth, int nHeight, IntPtr hWndParent, IntPtr hMenu,
        IntPtr hInstance, IntPtr lpParam);

    [DllImport("user32.dll")]
    private static extern bool DestroyWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern IntPtr DefWindowProc(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern IntPtr LoadIcon(IntPtr hInstance, IntPtr lpIconName);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("user32.dll")]
    private static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool AppendMenu(IntPtr hMenu, int uFlags, int uIdNewItem, string? lpNewItem);

    [DllImport("user32.dll")]
    private static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool DestroyMenu(IntPtr hMenu);

    [DllImport("user32.dll")]
    private static extern int TrackPopupMenuEx(IntPtr hmenu, int fuFlags, int x, int y, IntPtr hwnd, IntPtr lptpm);
}
