namespace optiCombat.Services;

/// <summary>Contexte menaces pour <see cref="ServiceHostThreatHandler"/> (mode --service-host).</summary>
public interface IServiceHostThreatContext
{
    QuarantineManager Quarantine { get; }

    ScanLogManager Logger { get; }

    CloudThreatIntelService CloudThreatIntel { get; }
}
