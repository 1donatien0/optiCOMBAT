namespace optiCombat.Platform;

/// <summary>Backoff et limites de relance pour le superviseur --service-host.</summary>
public sealed class ServiceHostRestartPolicy
{
    public const int MaxBackoffSeconds = 300;
    public const int MaxRestartsPerHour = 30;

    private int _consecutiveFailures;
    private int _restartsInWindow;
    private DateTime _windowStartUtc = DateTime.UtcNow;

    public int ConsecutiveFailures => _consecutiveFailures;
    public int RestartsInWindow => _restartsInWindow;

    public void OnHostHealthy()
    {
        _consecutiveFailures = 0;
    }

    public void OnHostExit()
    {
        RollWindowIfNeeded();
        _consecutiveFailures++;
        _restartsInWindow++;
    }

    public bool CanRestart()
    {
        RollWindowIfNeeded();
        return _restartsInWindow < MaxRestartsPerHour;
    }

    public TimeSpan GetBackoffDelay()
    {
        var seconds = Math.Pow(2, Math.Min(_consecutiveFailures, 8));
        return TimeSpan.FromSeconds(Math.Min(MaxBackoffSeconds, seconds));
    }

    private bool RollWindowIfNeeded()
    {
        if (DateTime.UtcNow - _windowStartUtc < TimeSpan.FromHours(1))
            return false;

        _windowStartUtc = DateTime.UtcNow;
        _restartsInWindow = 0;
        return true;
    }
}
