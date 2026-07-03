using Microsoft.UI.Xaml.Controls;

namespace optiCombat.WinUI.Views;

public sealed partial class PlaceholderPage : UserControl
{
    public PlaceholderPage(string title, string body)
    {
        InitializeComponent();
        TitleText.Text = title;
        BodyText.Text = body;
    }
}
