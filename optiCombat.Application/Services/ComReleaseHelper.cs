using System.Runtime.InteropServices;

namespace optiCombat.Services
{
    /// <summary>Libère les RCW COM de façon explicite (évite d'attendre le GC).</summary>
    internal static class ComReleaseHelper
    {
        public static void Release(object? comObject)
        {
            if (comObject == null)
                return;

            try
            {
                if (Marshal.IsComObject(comObject))
                    Marshal.ReleaseComObject(comObject);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ComReleaseHelper", "ReleaseComObject", ex);
            }
        }
    }
}
