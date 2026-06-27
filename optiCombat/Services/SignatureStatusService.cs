using optiCombat.Localization;
using optiCombat.ViewModels;

namespace optiCombat.Services
{
    /// <summary>
    /// Versions et dates des signatures ClamAV / YARA avec cache TTL — extrait de <see cref="optiCombat.MainWindow"/>.
    /// </summary>
    public sealed record SignatureStatusSnapshot(
        string ClamDatabaseVersion,
        string ClamLastUpdateDisplay,
        string YaraPackVersion,
        string YaraLastUpdateDisplay,
        int YaraRulesCount,
        bool YaraIsAvailable)
    {
        /// <summary>Met à jour les propriétés liées aux signatures du ViewModel.</summary>
        public void ApplyToScanViewModel(ScanViewModel vm)
        {
            vm.DbVersion = ClamDatabaseVersion;
            vm.RulesPackVersion = YaraPackVersion;
            vm.LastUpdateDisplay = ClamLastUpdateDisplay == "—"
                ? LocalizationService.GetString("Vm_Never")
                : ClamLastUpdateDisplay;
            vm.RulesLastUpdateDisplay = YaraLastUpdateDisplay == "—"
                ? LocalizationService.GetString("Vm_Never")
                : YaraLastUpdateDisplay;
            vm.YaraRulesCount = YaraRulesCount;
            vm.YaraStatus = YaraIsAvailable
                ? LocalizationService.Format("Vm_YaraOperational", YaraRulesCount)
                : LocalizationService.GetString("Vm_YaraUnavailable");
            vm.RefreshProtectionStatus();
        }
    }

    /// <summary>Lit et met en cache les libellés de versions de signatures (30 s par défaut).</summary>
    public sealed class SignatureStatusService
    {
        private readonly Func<Task<string>> _clamVerAsync;
        private readonly Func<string> _clamWhen;
        private readonly Func<string> _yaraVer;
        private readonly Func<string> _yaraWhen;
        private readonly Func<int> _rulesCount;
        private readonly Func<bool> _yaraAvailable;
        private readonly TimeSpan _cacheTtl;

        private DateTime _lastVersionRefreshAtUtc = DateTime.MinValue;
        private (string ClamVer, string ClamWhen, string YaraVer, string YaraWhen)? _versionCache;

        public SignatureStatusService(
            FreshclamUpdater? freshclam,
            YaraForgeUpdater? rulesUpdater,
            YaraEngine? yaraEngine,
            TimeSpan? cacheTtl = null)
            : this(
                () => freshclam != null
                    ? freshclam.GetLocalDatabaseVersionAsync()
                    : Task.FromResult("—"),
                () => freshclam?.GetLastSignatureChangeDisplay() ?? "—",
                () => rulesUpdater?.GetRulesPackVersionDisplay() ?? "—",
                () => rulesUpdater?.GetRulesLastUpdateDisplay() ?? "—",
                () => yaraEngine?.RulesCount ?? 0,
                () => yaraEngine?.IsAvailable ?? false,
                cacheTtl ?? TimeSpan.FromSeconds(30))
        {
        }

        internal SignatureStatusService(
            Func<Task<string>> clamVerAsync,
            Func<string> clamWhen,
            Func<string> yaraVer,
            Func<string> yaraWhen,
            Func<int> rulesCount,
            Func<bool> yaraAvailable,
            TimeSpan cacheTtl)
        {
            _clamVerAsync = clamVerAsync;
            _clamWhen = clamWhen;
            _yaraVer = yaraVer;
            _yaraWhen = yaraWhen;
            _rulesCount = rulesCount;
            _yaraAvailable = yaraAvailable;
            _cacheTtl = cacheTtl;
        }

        /// <summary>Invalide le cache TTL (après une MAJ effective des signatures).</summary>
        public void InvalidateCache()
        {
            _lastVersionRefreshAtUtc = DateTime.MinValue;
            _versionCache = null;
        }

        /// <summary>
        /// Retourne l'état des signatures. Les libellés version/date sont mis en cache ;
        /// le nombre de règles YARA et la disponibilité sont relus à chaque appel.
        /// </summary>
        public async Task<SignatureStatusSnapshot> GetSnapshotAsync(bool forceRefresh = false)
        {
            string clamVer, clamWhen, yaraVer, yaraWhen;
            if (!forceRefresh
                && _versionCache.HasValue
                && (DateTime.UtcNow - _lastVersionRefreshAtUtc) < _cacheTtl)
            {
                (clamVer, clamWhen, yaraVer, yaraWhen) = _versionCache.Value;
            }
            else
            {
                clamVer = await _clamVerAsync().ConfigureAwait(false);
                clamWhen = _clamWhen();
                yaraVer = _yaraVer();
                yaraWhen = _yaraWhen();
                _versionCache = (clamVer, clamWhen, yaraVer, yaraWhen);
                _lastVersionRefreshAtUtc = DateTime.UtcNow;
            }

            return new SignatureStatusSnapshot(
                clamVer,
                clamWhen,
                yaraVer,
                yaraWhen,
                _rulesCount(),
                _yaraAvailable());
        }
    }
}
