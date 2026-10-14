namespace optiCombat.Services
{
    /// <summary>Intervalles de mise à jour des signatures et contrôle au démarrage.</summary>
    public static class SignatureUpdatePolicy
    {
        private static readonly TimeSpan StandardClamInterval = TimeSpan.FromHours(4);
        private static readonly TimeSpan StandardYaraInterval = TimeSpan.FromHours(24);
        private static readonly TimeSpan AggressiveClamInterval = TimeSpan.FromHours(2);
        private static readonly TimeSpan AggressiveYaraInterval = TimeSpan.FromHours(12);

        public static void ApplyAutoUpdateTimers(
            ISignatureAutoUpdateTarget freshclam,
            ISignatureAutoUpdateTarget rules,
            bool enabled,
            IUserPreferencesAccessor preferences)
        {
            if (!enabled)
            {
                freshclam.DisableAutoUpdate();
                rules.DisableAutoUpdate();
                return;
            }

            var aggressive = preferences.Current.AggressiveSignatureUpdates;
            freshclam.EnableAutoUpdate(aggressive ? AggressiveClamInterval : StandardClamInterval);
            rules.EnableAutoUpdate(aggressive ? AggressiveYaraInterval : StandardYaraInterval);
        }

        public static void ScheduleStartupRefreshIfStale(ServiceContainer container, IUserPreferencesAccessor preferences)
        {
            if (!preferences.Current.SignatureAutoUpdateEnabled)
                return;

            var threshold = TimeSpan.FromDays(Math.Max(1, preferences.Current.SignatureStaleThresholdDays));
            _ = Task.Run(async () =>
            {
                try
                {
                    var fresh = container.FreshclamUpdater;
                    var last = fresh.LastUpdateTime;
                    if (last.HasValue && DateTime.UtcNow - last.Value.ToUniversalTime() < threshold)
                        return;

                    AppLogger.Info("SignatureUpdatePolicy", "Signatures potentiellement obsolètes — MAJ au démarrage");
                    await fresh.UpdateAsync().ConfigureAwait(false);
                    await container.RulesUpdater.UpdateAsync().ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("SignatureUpdatePolicy", "ScheduleStartupRefreshIfStale", ex);
                }
            });
        }
    }
}
