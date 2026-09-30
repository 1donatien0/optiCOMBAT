using System.Runtime.InteropServices;
using optiCombat.Services;

namespace optiCombat.WinUI.Services;

/// <summary>
/// Confirmations synchrones via la boîte de dialogue Win32 (<c>MessageBoxW</c>), parentée à la fenêtre
/// WinUI. Fonctionne aussi quand l'application tourne en administrateur, contrairement aux
/// <c>ContentDialog</c> asynchrones appelés depuis du code synchrone. « Non » est le bouton par défaut.
/// </summary>
public sealed class WinUiUserConfirmService : IUserConfirmService
{
    private const uint MB_OK = 0x00000000;
    private const uint MB_YESNO = 0x00000004;
    private const uint MB_ICONQUESTION = 0x00000020;
    private const uint MB_ICONWARNING = 0x00000030;
    private const uint MB_ICONINFORMATION = 0x00000040;
    private const uint MB_DEFBUTTON2 = 0x00000100;
    private const int IDYES = 6;

    private readonly Func<IntPtr> _getOwner;

    public WinUiUserConfirmService(Func<IntPtr> getOwner) => _getOwner = getOwner;

    public bool ConfirmYesNo(string message, string title, bool warning = true) =>
        MessageBoxW(_getOwner(), message, title, MB_YESNO | MB_DEFBUTTON2 | (warning ? MB_ICONWARNING : MB_ICONQUESTION)) == IDYES;

    public void Inform(string message, string title) =>
        _ = MessageBoxW(_getOwner(), message, title, MB_OK | MB_ICONINFORMATION);

    public void Warn(string message, string title) =>
        _ = MessageBoxW(_getOwner(), message, title, MB_OK | MB_ICONWARNING);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);
}
