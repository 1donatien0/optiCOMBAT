namespace optiCombat.Services;

/// <summary>
/// Limite le débit des opérations <c>scan_path</c> / <c>scan_buffer</c> sur le pipe IPC.
/// Le pipe est ouvert aux utilisateurs authentifiés (nécessaire pour AMSI) : sans plafond,
/// n'importe quel processus local peut saturer le moteur (DoS local).
/// </summary>
public sealed class IpcScanRateLimiter
{
    public const int DefaultMaxScansPerMinute = 120;
    public const int DefaultMaxConcurrentScans = 4;

    /// <summary>
    /// Durée max de détention d'un slot concurrent (secondes). Un scan bloqué
    /// qui ignore l'annulation libère quand même le lease à l'échéance.
    /// Aligné sur <see cref="ProtectionPipeServer.DefaultIpcScanTimeout"/>.
    /// </summary>
    public const int DefaultMaxLeaseHoldSeconds = 90;

    private readonly int _maxPerMinute;
    private readonly int _maxConcurrent;
    private readonly TimeSpan _maxLeaseHold;
    private readonly Func<DateTime> _clock;
    private readonly Queue<DateTime> _recent = new();
    private readonly object _gate = new();
    private int _concurrent;

    public IpcScanRateLimiter(
        int maxPerMinute = DefaultMaxScansPerMinute,
        int maxConcurrent = DefaultMaxConcurrentScans,
        Func<DateTime>? clock = null,
        TimeSpan? maxLeaseHold = null)
    {
        _maxPerMinute = Math.Max(1, maxPerMinute);
        _maxConcurrent = Math.Max(1, maxConcurrent);
        _clock = clock ?? (() => DateTime.UtcNow);
        _maxLeaseHold = maxLeaseHold ?? TimeSpan.FromSeconds(DefaultMaxLeaseHoldSeconds);
        if (_maxLeaseHold < TimeSpan.Zero)
            _maxLeaseHold = TimeSpan.Zero;
    }

    /// <summary>Nombre total de requêtes refusées depuis le démarrage (diagnostic).</summary>
    public long RejectedCount => Interlocked.Read(ref _rejected);
    private long _rejected;

    /// <summary>Tente d'acquérir un slot ; disposer le lease à la fin du scan.</summary>
    public bool TryEnter(out IDisposable? lease)
    {
        lock (_gate)
        {
            var now = _clock();
            while (_recent.Count > 0 && now - _recent.Peek() >= TimeSpan.FromMinutes(1))
                _recent.Dequeue();

            if (_concurrent >= _maxConcurrent || _recent.Count >= _maxPerMinute)
            {
                lease = null;
                Interlocked.Increment(ref _rejected);
                return false;
            }

            _concurrent++;
            _recent.Enqueue(now);
            lease = new Lease(this, _maxLeaseHold);
            return true;
        }
    }

    private void Release()
    {
        lock (_gate)
            _concurrent = Math.Max(0, _concurrent - 1);
    }

    private sealed class Lease : IDisposable
    {
        private readonly IpcScanRateLimiter _owner;
        private readonly System.Threading.Timer? _timer;
        private int _disposed;

        public Lease(IpcScanRateLimiter owner, TimeSpan maxHold)
        {
            _owner = owner;
            if (maxHold > TimeSpan.Zero)
                _timer = new System.Threading.Timer(static state => ((Lease)state!).Dispose(), this, maxHold, Timeout.InfiniteTimeSpan);
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;

            try { _timer?.Dispose(); } catch { /* ignore */ }
            _owner.Release();
        }
    }
}
