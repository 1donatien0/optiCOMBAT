// OptiCombatNative.cs — pont P/Invoke pour optiCombat.Service vers le cœur Rust.
//
// EXEMPLE D'INTÉGRATION (Phase 3). À placer, le moment venu, dans
// optiCombat.Service (ex. Interop/). opticombat.dll doit être déployée à côté de
// l'exécutable. Aucune réécriture de l'UI WPF : le service appelle ce cœur.
using System;
using System.Runtime.InteropServices;

namespace OptiCombat.Service.Interop
{
    /// <summary>Verdict normalisé renvoyé par le cœur moteur Rust.</summary>
    public enum OptiCombatVerdict
    {
        Clean = 0,
        Suspicious = 1,
        Malicious = 2,
        Error = -1,
    }

    /// <summary>
    /// Liaison P/Invoke vers la bibliothèque native optiCombat (C ABI).
    /// Le marshaling des chaînes UTF-8 et la libération mémoire respectent
    /// le contrat de propriété défini dans opticombat.h.
    /// </summary>
    public static class OptiCombatNative
    {
        private const string Dll = "opticombat"; // opticombat.dll / libopticombat.so

        [DllImport(Dll, EntryPoint = "opticombat_scan_path", CallingConvention = CallingConvention.Cdecl)]
        private static extern int ScanPathNative([MarshalAs(UnmanagedType.LPUTF8Str)] string path);

        [DllImport(Dll, EntryPoint = "opticombat_scan_json", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ScanJsonNative([MarshalAs(UnmanagedType.LPUTF8Str)] string path);

        [DllImport(Dll, EntryPoint = "opticombat_string_free", CallingConvention = CallingConvention.Cdecl)]
        private static extern void StringFreeNative(IntPtr s);

        [DllImport(Dll, EntryPoint = "opticombat_version", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr VersionNative();

        /// <summary>Scanne un fichier et renvoie le verdict normalisé.</summary>
        public static OptiCombatVerdict ScanPath(string path)
            => (OptiCombatVerdict)ScanPathNative(path);

        /// <summary>Scanne un fichier et renvoie le résultat JSON explicable.</summary>
        public static string ScanJson(string path)
        {
            IntPtr ptr = ScanJsonNative(path);
            if (ptr == IntPtr.Zero) return null;
            try
            {
                return Marshal.PtrToStringUTF8(ptr);
            }
            finally
            {
                StringFreeNative(ptr); // libération côté natif (contrat de propriété)
            }
        }

        /// <summary>Version de la bibliothèque native (chaîne statique).</summary>
        public static string Version() => Marshal.PtrToStringUTF8(VersionNative());
    }
}
