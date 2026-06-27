namespace optiCombat.Tests;

/// <summary>Désactive le parallélisme xUnit pour les tests mutants UserPreferences / DistractionFreeMonitor.</summary>
[CollectionDefinition("OpticombatPrefs", DisableParallelization = true)]
public sealed class OpticombatPrefsCollection;
