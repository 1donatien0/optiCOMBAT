namespace optiCombat.Services;

/// <summary>Accès testable aux préférences utilisateur (remplace <see cref="UserPreferences.Current"/> direct).</summary>
public interface IUserPreferencesAccessor
{
    UserPreferences Current { get; }
}

/// <summary>Implémentation production — délègue au singleton <see cref="UserPreferences"/>.</summary>
public sealed class DefaultUserPreferencesAccessor : IUserPreferencesAccessor
{
    public UserPreferences Current => UserPreferences.Current;
}
