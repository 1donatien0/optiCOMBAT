namespace optiCombat.Services;

/// <summary>Accès testable aux exclusions / RTP (remplace <see cref="ExclusionSettings.Current"/> direct).</summary>
public interface IExclusionSettingsAccessor
{
    ExclusionSettings Current { get; }
}

/// <summary>Implémentation production — délègue au singleton <see cref="ExclusionSettings"/>.</summary>
public sealed class DefaultExclusionSettingsAccessor : IExclusionSettingsAccessor
{
    public ExclusionSettings Current => ExclusionSettings.Current;
}
