using optiCombat.Strings;
using System.Windows.Threading;

namespace optiCombat.Services
{
    /// <summary>
    /// Coordonne les rafraîchissements de données déclenchés à chaque changement de vue.
    /// Extrait de MainWindow pour améliorer la testabilité et réduire la taille de la fenêtre principale.
    ///
    /// Pattern : <see cref="INavigationService.Navigated"/> → dispatch sur le Dispatcher WPF →
    /// await des callbacks injectés (<see cref="Func{Task}"/>).
    /// </summary>
    public sealed class NavigationRefreshCoordinator
    {
        private readonly INavigationService _navigation;
        private readonly Dispatcher _dispatcher;

        // Callbacks async injectés par MainWindow (un par bloc de données à recharger).
        private readonly Func<Task> _refreshHistory;
        private readonly Func<Task> _refreshAntivirusStatus;
        private readonly Func<Task> _refreshSignatures;
        private readonly Func<Task> _refreshAntivirusData;

        /// <summary>
        /// Initialise le coordinateur et s'abonne à l'événement <see cref="INavigationService.Navigated"/>.
        /// </summary>
        /// <param name="navigation">Service de navigation à observer.</param>
        /// <param name="dispatcher">Dispatcher WPF pour repasser sur le thread UI.</param>
        /// <param name="refreshHistory">Recharge l'historique des scans.</param>
        /// <param name="refreshAntivirusStatus">Recharge le statut ClamAV / YARA sidebar.</param>
        /// <param name="refreshSignatures">Recharge les versions de signatures (avec cache TTL).</param>
        /// <param name="refreshAntivirusData">Recharge l'ensemble des données Antivirus.</param>
        /// <remarks>
        /// Passer des méthodes <c>async Task</c> ou des lambdas retournant <see cref="Task"/>.
        /// Ne pas assigner de lambda <c>async</c> à un <see cref="Action"/> (async void implicite).
        /// </remarks>
        public NavigationRefreshCoordinator(
            INavigationService navigation,
            Dispatcher dispatcher,
            Func<Task> refreshHistory,
            Func<Task> refreshAntivirusStatus,
            Func<Task> refreshSignatures,
            Func<Task> refreshAntivirusData)
        {
            _navigation            = navigation;
            _dispatcher            = dispatcher;
            _refreshHistory        = refreshHistory;
            _refreshAntivirusStatus = refreshAntivirusStatus;
            _refreshSignatures     = refreshSignatures;
            _refreshAntivirusData  = refreshAntivirusData;

            _navigation.Navigated += OnNavigated;
        }

        /// <summary>Désinscrit le coordinateur du service de navigation.</summary>
        public void Detach() => _navigation.Navigated -= OnNavigated;

        private void OnNavigated(object? sender, string panelName)
        {
            _ = _dispatcher.InvokeAsync(() => ApplyRefreshesAsync(panelName), DispatcherPriority.Background);
        }

        /// <summary>Exposé aux tests unitaires (sans passer par le Dispatcher).</summary>
        internal Task ApplyRefreshesForPanelAsync(string panelName) => ApplyRefreshesAsync(panelName);

        private async Task ApplyRefreshesAsync(string panelName)
        {
            switch (panelName)
            {
                case OpticombatStrings.PanelIds.Overview:
                    await InvokeRefreshAsync(_refreshHistory, nameof(_refreshHistory)).ConfigureAwait(true);
                    await InvokeRefreshAsync(_refreshAntivirusStatus, nameof(_refreshAntivirusStatus)).ConfigureAwait(true);
                    await InvokeRefreshAsync(_refreshSignatures, nameof(_refreshSignatures)).ConfigureAwait(true);
                    break;

                case OpticombatStrings.PanelIds.Antivirus:
                    await InvokeRefreshAsync(_refreshAntivirusData, nameof(_refreshAntivirusData)).ConfigureAwait(true);
                    break;

                case OpticombatStrings.PanelIds.History:
                    await InvokeRefreshAsync(_refreshHistory, nameof(_refreshHistory)).ConfigureAwait(true);
                    break;
                // Clean et Options : aucun rafraîchissement nécessaire à la navigation.
            }
        }

        private static async Task InvokeRefreshAsync(Func<Task> refresh, string name)
        {
            try
            {
                await refresh().ConfigureAwait(true);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("NavigationRefreshCoordinator", name, ex);
            }
        }
    }
}
