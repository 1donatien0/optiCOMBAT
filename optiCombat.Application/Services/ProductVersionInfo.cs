using System;
using System.Reflection;

namespace optiCombat.Services
{
    /// <summary>
    /// Convention produit :
    /// <list type="bullet">
    /// <item><description><b>vM.m</b> — nom de release (ex. v1.0).</description></item>
    /// <item><description><b>M.m.p</b> — identifiant de build / assembly / installateur (ex. 1.0.0).</description></item>
    /// </list>
    /// </summary>
    internal static class ProductVersionInfo
    {
        private static readonly Assembly Asm = Assembly.GetExecutingAssembly();
        private static readonly Version? AsmNameVersion = Asm.GetName().Version;

        /// <summary>Triplet sémantique affiché (barre latérale, User-Agent HTTP, propriétés fichier).</summary>
        public static string SemVer
        {
            get
            {
                var info = Asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                    ?.InformationalVersion?.Split('+', 2)[0].Trim();
                if (!string.IsNullOrEmpty(info))
                    return info;
                return AsmNameVersion is null ? "0.0.0"
                    : $"{AsmNameVersion.Major}.{AsmNameVersion.Minor}.{Math.Max(0, AsmNameVersion.Build)}";
            }
        }

        /// <summary>Nom de release (ex. v1.0).</summary>
        public static string ReleaseLabel =>
            AsmNameVersion is null ? "v0.0" : $"v{AsmNameVersion.Major}.{AsmNameVersion.Minor}";

        public static string HttpUserAgent => $"optiCombat/{SemVer}";

        /// <summary>Marqueur freshclam.conf (historique : v2…v6 — numéro de version majeure seul).</summary>
        public static int ConfMarkerMajor => AsmNameVersion?.Major ?? 0;
    }
}
