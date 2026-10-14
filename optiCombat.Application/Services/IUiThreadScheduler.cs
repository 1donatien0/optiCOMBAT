namespace optiCombat.Services;

/// <summary>Planifie du travail sur le thread UI (WinUI <c>DispatcherQueue</c>), découplé pour les tests.</summary>
public interface IUiThreadScheduler
{
    /// <summary>Exécute immédiatement si l'appelant est déjà sur le thread UI, sinon met en file.</summary>
    void Invoke(Action action);

    /// <summary>Met toujours en file (ne bloque jamais l'appelant).</summary>
    void BeginInvoke(Action action);
}

/// <summary>Exécution synchrone sur le thread appelant (tests, mode headless).</summary>
public sealed class SyncUiThreadScheduler : IUiThreadScheduler
{
    public static SyncUiThreadScheduler Instance { get; } = new();

    public void Invoke(Action action) => action();

    public void BeginInvoke(Action action) => action();
}
