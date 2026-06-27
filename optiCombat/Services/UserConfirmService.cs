namespace optiCombat.Services
{
    /// <summary>Confirmations utilisateur (découple le ViewModel de MessageBox).</summary>
    public interface IUserConfirmService
    {
        bool ConfirmYesNo(string message, string title, bool warning = true);
    }

    public sealed class WpfUserConfirmService : IUserConfirmService
    {
        public bool ConfirmYesNo(string message, string title, bool warning = true)
        {
            return System.Windows.MessageBox.Show(
                    message,
                    title,
                    System.Windows.MessageBoxButton.YesNo,
                    warning ? System.Windows.MessageBoxImage.Warning : System.Windows.MessageBoxImage.Question)
                == System.Windows.MessageBoxResult.Yes;
        }
    }
}
