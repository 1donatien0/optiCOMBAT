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
    private readonly List<Lease> _active = new();
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
            ExpireStale(now);
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
            var held = new Lease(this, now, _maxLeaseHold);
            _active.Add(held);
            lease = held;
            return true;
        }
    }

    /// <summary>Libère les slots dont l'échéance est passée selon <see cref="_clock"/>.</summary>
    private void ExpireStale(DateTime now)
    {
        if (_maxLeaseHold <= TimeSpan.Zero)
            return;

        for (var i = _active.Count - 1; i >= 0; i--)
        {
            var lease = _active[i];
            if (now - lease.Started < _maxLeaseHold)
                continue;
            if (!lease.TryMarkDisposed())
                continue;
            _active.RemoveAt(i);
            _concurrent = Math.Max(0, _concurrent - 1);
            lease.StopTimer();
        }
    }

    private sealed class Lease : IDisposable
    {
        private readonly IpcScanRateLimiter _owner;
        private readonly System.Threading.Timer? _timer;
        private int _disposed;

        public DateTime Started { get; }

        public Lease(IpcScanRateLimiter owner, DateTime started, TimeSpan maxHold)
        {
            _owner = owner;
            Started = started;
            if (maxHold > TimeSpan.Zero)
                _timer = new System.Threading.Timer(static state => ((Lease)state!).Dispose(), this, maxHold, Timeout.InfiniteTimeSpan);
        }

        public bool TryMarkDisposed() => Interlocked.Exchange(ref _disposed, 1) == 0;

        public void StopTimer()
        {
            try { _timer?.Dispose(); } catch { /* ignore */ }
        }

        public void Dispose()
        {
            lock (_owner._gate)
            {
                if (!TryMarkDisposed())
                    return;
                _owner._active.Remove(this);
                _owner._concurrent = Math.Max(0, _owner._concurrent - 1);
                StopTimer();
            }
        }
    }
}
