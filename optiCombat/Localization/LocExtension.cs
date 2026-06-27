using System.Windows.Markup;

namespace optiCombat.Localization
{
    /// <summary>Binding XAML vers <see cref="LocalizationService"/>.</summary>
    [MarkupExtensionReturnType(typeof(string))]
    public sealed class LocExtension : MarkupExtension
    {
        public string Key { get; set; } = string.Empty;

        public LocExtension() { }

        public LocExtension(string key) => Key = key;

        public override object ProvideValue(IServiceProvider serviceProvider) =>
            LocalizationService.GetString(Key);
    }
}
