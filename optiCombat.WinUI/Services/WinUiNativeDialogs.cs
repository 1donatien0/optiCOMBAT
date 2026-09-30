using System.Runtime.InteropServices;
using WinRT.Interop;

namespace optiCombat.WinUI.Services;

/// <summary>
/// Sélecteurs de fichiers / dossiers Win32 (IFileDialog) synchrones et modaux.
/// </summary>
/// <remarks>
/// Remplace les pickers WinRT (<c>FolderPicker</c>, <c>FileOpenPicker</c>, <c>FileSavePicker</c>) qui :
/// <list type="bullet">
/// <item>échouent quand optiCombat tourne en administrateur (relance élevée) ;</item>
/// <item>bloquaient l'application à l'export (appel asynchrone attendu en synchrone sur le thread UI → interblocage).</item>
/// </list>
/// Doit être appelé depuis le thread UI (STA).
/// </remarks>
public static class WinUiNativeDialogs
{
    private const uint FOS_OVERWRITEPROMPT = 0x00000002;
    private const uint FOS_PICKFOLDERS = 0x00000020;
    private const uint FOS_FORCEFILESYSTEM = 0x00000040;
    private const uint FOS_PATHMUSTEXIST = 0x00000800;
    private const uint FOS_FILEMUSTEXIST = 0x00001000;
    private const uint SIGDN_FILESYSPATH = 0x80058000;
    private const int ERROR_CANCELLED_HRESULT = unchecked((int)0x800704C7);
    private static readonly Guid FileOpenDialogClsid = new("DC1C5A9C-E88A-4DDE-A5A1-60F82A20AEF7");
    private static readonly Guid FileSaveDialogClsid = new("C0B4E2F3-BA21-4773-8DBA-335EC946EB8B");

    private static IntPtr OwnerHwnd
    {
        get
        {
            try
            {
                return App.MainWindowInstance is { } w ? WindowNative.GetWindowHandle(w) : IntPtr.Zero;
            }
            catch
            {
                return IntPtr.Zero;
            }
        }
    }

    /// <summary>Choix d'un dossier. Retourne <c>null</c> si l'utilisateur annule.</summary>
    public static string? PickFolder(string? title = null) =>
        Show(FileOpenDialogClsid, FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST, title, null, null, null);

    /// <summary>Choix d'un fichier existant. Retourne <c>null</c> si l'utilisateur annule.</summary>
    public static string? PickFile(string? title = null) =>
        Show(FileOpenDialogClsid, FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_FILEMUSTEXIST, title, null, null, null);

    /// <summary>« Enregistrer sous ». Retourne <c>null</c> si l'utilisateur annule.</summary>
    /// <param name="filterName">Libellé du filtre (ex. « Rapport HTML »).</param>
    /// <param name="extension">Extension avec ou sans point (ex. « .html »).</param>
    public static string? PickSaveFile(string suggestedFileName, string filterName, string extension)
    {
        var ext = extension.TrimStart('.');
        var filters = new[]
        {
            new COMDLG_FILTERSPEC
            {
                pszName = string.IsNullOrWhiteSpace(filterName) ? ext.ToUpperInvariant() : filterName,
                pszSpec = "*." + ext,
            },
        };
        return Show(FileSaveDialogClsid, FOS_OVERWRITEPROMPT | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST,
            null, suggestedFileName, ext, filters);
    }

    private static string? Show(
        Guid clsid,
        uint options,
        string? title,
        string? fileName,
        string? defaultExtension,
        COMDLG_FILTERSPEC[]? filters)
    {
        var type = Type.GetTypeFromCLSID(clsid, throwOnError: true)!;
        var dialog = (IFileDialog)Activator.CreateInstance(type)!;
        IShellItem? item = null;
        try
        {
            dialog.GetOptions(out var existing);
            dialog.SetOptions(existing | options);

            if (filters is { Length: > 0 })
            {
                dialog.SetFileTypes((uint)filters.Length, filters);
                dialog.SetFileTypeIndex(1);
            }

            if (!string.IsNullOrWhiteSpace(defaultExtension))
                dialog.SetDefaultExtension(defaultExtension);
            if (!string.IsNullOrWhiteSpace(fileName))
                dialog.SetFileName(fileName);
            if (!string.IsNullOrWhiteSpace(title))
                dialog.SetTitle(title);

            var hr = dialog.Show(OwnerHwnd);
            if (hr == ERROR_CANCELLED_HRESULT)
                return null;
            Marshal.ThrowExceptionForHR(hr);

            dialog.GetResult(out item);
            item.GetDisplayName(SIGDN_FILESYSPATH, out var pathPtr);
            try
            {
                return Marshal.PtrToStringUni(pathPtr);
            }
            finally
            {
                Marshal.FreeCoTaskMem(pathPtr);
            }
        }
        finally
        {
            if (item != null)
                Marshal.ReleaseComObject(item);
            Marshal.ReleaseComObject(dialog);
        }
    }

    // ── Interop COM ──────────────────────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct COMDLG_FILTERSPEC
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string pszName;
        [MarshalAs(UnmanagedType.LPWStr)] public string pszSpec;
    }

    /// <summary>IFileDialog (hérite d'IModalWindow) — l'ordre des méthodes suit la vtable native.</summary>
    [ComImport, Guid("42F85136-DB7E-439C-85F1-E4075D135FC8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IFileDialog
    {
        [PreserveSig] int Show(IntPtr hwndOwner);
        void SetFileTypes(uint cFileTypes, [MarshalAs(UnmanagedType.LPArray)] COMDLG_FILTERSPEC[] rgFilterSpec);
        void SetFileTypeIndex(uint iFileType);
        void GetFileTypeIndex(out uint piFileType);
        void Advise(IntPtr pfde, out uint pdwCookie);
        void Unadvise(uint dwCookie);
        void SetOptions(uint fos);
        void GetOptions(out uint pfos);
        void SetDefaultFolder(IShellItem psi);
        void SetFolder(IShellItem psi);
        void GetFolder(out IShellItem ppsi);
        void GetCurrentSelection(out IShellItem ppsi);
        void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string pszName);
        void GetFileName([MarshalAs(UnmanagedType.LPWStr)] out string pszName);
        void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string pszTitle);
        void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string pszText);
        void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string pszLabel);
        void GetResult(out IShellItem ppsi);
        void AddPlace(IShellItem psi, int fdap);
        void SetDefaultExtension([MarshalAs(UnmanagedType.LPWStr)] string pszDefaultExtension);
        void Close(int hr);
        void SetClientGuid(ref Guid guid);
        void ClearClientData();
        void SetFilter(IntPtr pFilter);
    }

    [ComImport, Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellItem
    {
        void BindToHandler(IntPtr pbc, ref Guid bhid, ref Guid riid, out IntPtr ppv);
        void GetParent(out IShellItem ppsi);
        void GetDisplayName(uint sigdnName, out IntPtr ppszName);
        void GetAttributes(uint sfgaoMask, out uint psfgaoAttribs);
        void Compare(IShellItem psi, uint hint, out int piOrder);
    }
}
