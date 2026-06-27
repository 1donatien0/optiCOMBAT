namespace optiCombat.Services
{
    /// <summary>
    /// Mise à jour manuelle des signatures avec verrou anti double-clic — extrait de <see cref="optiCombat.MainWindow"/>.
    /// </summary>
    public sealed class SignatureUpdateUiRunner
    {
        private readonly SemaphoreSlim _lock = new(1, 1);

        public bool TryEnterUpdate() => _lock.Wait(0);

        public void ReleaseUpdate() => _lock.Release();

        public async Task<bool> RunFullUpdateAsync(
            FreshclamUpdater? freshclam,
            YaraForgeUpdater? rules,
            Action<string> appendLog,
            CancellationToken cancellationToken = default)
        {
            return await SignatureUpdateCoordinator.RunFullSignatureUpdateAsync(
                freshclam, rules, appendLog, cancellationToken).ConfigureAwait(false);
        }
    }
}
