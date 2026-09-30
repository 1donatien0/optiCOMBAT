namespace optiCombat.Tests;

/// <summary>Évite les courses sur UiCulture entre tests parallèles.</summary>
[CollectionDefinition("Localization", DisableParallelization = true)]
public sealed class LocalizationTestCollection;
