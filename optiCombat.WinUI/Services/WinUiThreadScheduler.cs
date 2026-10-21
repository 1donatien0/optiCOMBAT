using Microsoft.UI.Dispatching;
using optiCombat.Services;

namespace optiCombat.WinUI.Services;

/// <summary>Planifie du travail sur le <see cref="DispatcherQueue"/> WinUI.</summary>
public sealed class WinUiThreadScheduler : IUiThreadScheduler
{
    private readonly DispatcherQueue _queue;

    public WinUiThreadScheduler(DispatcherQueue queue) => _queue = queue;

    public void Invoke(Action action)
    {
        if (_queue.HasThreadAccess)
            action();
        else
            _queue.TryEnqueue(() => action());
    }

    public void BeginInvoke(Action action) => _queue.TryEnqueue(() => action());
}
