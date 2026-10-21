using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace optiCombat.Services
{
    /// <summary>
    /// Vérification Authenticode (WinVerifyTrust) d'un exécutable : signature valide et chaîne
    /// de confiance reconnue par Windows. Utilisée pour ne pas mettre en quarantaine, sur la seule
    /// foi d'heuristiques, un binaire signé par un éditeur de confiance (DLL Microsoft, ClamAV…).
    /// Révocation non vérifiée en ligne (pas d'accès réseau pendant une analyse).
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static class AuthenticodeVerifier
    {
        private static readonly Guid WintrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        private const uint WtdUiNone = 2;
        private const uint WtdRevokeNone = 0;
        private const uint WtdChoiceFile = 1;
        private const uint WtdStateActionVerify = 1;
        private const uint WtdStateActionClose = 2;
        private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;

        /// <summary>Vrai si le fichier porte une signature Authenticode valide et de confiance.</summary>
        public static bool IsTrustedSigned(string filePath)
        {
            if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                return false;

            var fileInfo = new WintrustFileInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WintrustFileInfo>(),
                pcwszFilePath = filePath,
            };
            var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WintrustFileInfo>());
            try
            {
                Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);
                var data = new WintrustData
                {
                    cbStruct = (uint)Marshal.SizeOf<WintrustData>(),
                    dwUIChoice = WtdUiNone,
                    fdwRevocationChecks = WtdRevokeNone,
                    dwUnionChoice = WtdChoiceFile,
                    pFile = fileInfoPtr,
                    dwStateAction = WtdStateActionVerify,
                    dwProvFlags = WtdCacheOnlyUrlRetrieval,
                };

                var action = WintrustActionGenericVerifyV2;
                int result;
                try
                {
                    result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                }
                finally
                {
                    data.dwStateAction = WtdStateActionClose;
                    _ = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                }

                return result == 0;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("AuthenticodeVerifier", $"Vérification impossible : {PathRedaction.RedactPath(filePath)}", ex);
                return false;
            }
            finally
            {
                Marshal.DestroyStructure<WintrustFileInfo>(fileInfoPtr);
                Marshal.FreeHGlobal(fileInfoPtr);
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WintrustFileInfo
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WintrustData
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WintrustData pWVTData);
    }
}
