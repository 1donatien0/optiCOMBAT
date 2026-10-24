using System.Runtime.CompilerServices;
using optiCombat.Services;

namespace optiCombat.Tests.TestSupport;

/// <summary>
/// Racine de données de toute l'exécution des tests : posée avant le premier test, elle garantit
/// qu'aucun test — même sans redirection explicite — n'écrit dans le vrai <c>%APPDATA%</c> /
/// <c>%LOCALAPPDATA%</c> du poste (préférences, clé HMAC, copies de sécurité, configurations).
/// Les tests qui posent leur propre racine reviennent à celle-ci, jamais à <c>null</c>.
/// Pose aussi un <see cref="ISystemShell"/> inerte : aucun test ne lance de processus système
/// ni n'écrit dans le registre réel.
/// </summary>
internal static class TestDataRoot
{
    public static string Session { get; } =
        Path.Combine(Path.GetTempPath(), "opticombat_tests_" + Environment.ProcessId + "_" + Guid.NewGuid().ToString("N")[..8]);

    [ModuleInitializer]
    internal static void Initialize()
    {
        Directory.CreateDirectory(Session);
        OpticombatDataRoots.TestRootOverride = Session;
        // Aucun processus réel (sc.exe, powershell, cmd /runas, reg…) ni écriture de registre :
        // un test qui en a besoin installe son propre RecordingShell.
        SystemShell.Default = new RecordingShell();
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try { Directory.Delete(Session, recursive: true); } catch { /* best effort */ }
        };
    }
}
