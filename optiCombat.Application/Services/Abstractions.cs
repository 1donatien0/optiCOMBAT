using optiCombat.Models;

namespace optiCombat.Services
{
    // Interfaces pour tests (mocks) et pour découpler les couches UI des implémentations.
    // Les services concrets sont des singletons exposés par ServiceContainer.

    /// <summary>Contrat ClamAV utilisé par <see cref="ScanOrchestrator"/> (tests via InternalsVisibleTo).</summary>
    internal interface IClamAvOrchestratorBackend
    {
        bool IsClamAvInstalled();
        Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default);
        Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default);
        Task<ScanResult> ScanFileListAsync(
            IReadOnlyList<string> files,
            string targetPath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default);
    }

    /// <summary>Contrat YARA utilisé par <see cref="ScanOrchestrator"/> (tests via InternalsVisibleTo).</summary>
    internal interface IYaraOrchestratorBackend
    {
        bool IsAvailable { get; }
        int RulesCount { get; }
        Task<List<YaraMatch>> ScanFileAsync(string filePath, CancellationToken ct = default);
        Task<List<YaraMatch>> ScanFolderAsync(string folderPath, IProgress<string>? progress = null, CancellationToken ct = default);
        Task<List<YaraMatch>> ScanFilesAsync(
            IReadOnlyList<string> files,
            IProgress<string>? progress = null,
            CancellationToken ct = default);
    }

    /// <summary>
    /// Moteur de scan antivirus (ClamAV, ou alternatif).
    /// </summary>
    public interface IScanEngine
    {
        bool IsAvailable { get; }
        Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default);
        Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default);
        Task<ScanResult> QuickScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default);
        Task<ScanResult> FullScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default);
        Task<string> GetVersionAsync();
    }

    /// <summary>
    /// Mise à jour d'un asset versionné (signatures ClamAV, règles YARA...).
    /// </summary>
    public interface IUpdater<TResult>
    {
        bool IsUpdating { get; }
        DateTime? LastUpdateTime { get; }
        event EventHandler<string>? UpdateOutput;
        event EventHandler<TResult>? UpdateCompleted;
        Task<TResult> UpdateAsync(CancellationToken ct = default);
        void EnableAutoUpdate(TimeSpan? interval = null);
        void DisableAutoUpdate();
        void CancelUpdate();
    }

    /// <summary>Annulation d'une mise à jour de signatures en cours (ClamAV, YARA).</summary>
    public interface ISignatureUpdateCanceller
    {
        void CancelUpdate();
    }

    /// <summary>Planification des mises à jour automatiques de signatures (ClamAV, YARA).</summary>
    public interface ISignatureAutoUpdateTarget
    {
        void EnableAutoUpdate(TimeSpan? interval = null);
        void DisableAutoUpdate();
    }

    /// <summary>
    /// Stockage des fichiers en quarantaine.
    /// </summary>
    public interface IThreatStore
    {
        bool Quarantine(ThreatInfo threat);
        int QuarantineAll(IEnumerable<ThreatInfo> threats);
        bool Restore(string quarantineId);
        bool RestoreTo(string quarantineId, string destinationFolder);
        bool DeletePermanently(string quarantineId);
        int PurgeAll();
        IReadOnlyList<QuarantineEntry> GetEntries();
        int Count { get; }
        long TotalSize { get; }
    }

    /// <summary>
    /// Adaptation de la classe concrète ClamAvEngine en IScanEngine.
    /// L'interface IScanEngine ne contient pas de propriété IsClamAvInstalled
    /// (spécifique ClamAV) — on expose IsAvailable comme proxy.
    /// </summary>
    public sealed class ClamAvScanEngineAdapter : IScanEngine
    {
        private readonly ClamAvEngine _engine;
        public ClamAvScanEngineAdapter(ClamAvEngine engine) => _engine = engine;

        public bool IsAvailable => _engine.IsClamAvInstalled();

        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => _engine.ScanFileAsync(filePath, progress, ct);

        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => _engine.ScanFolderAsync(folderPath, progress, ct);

        public Task<ScanResult> QuickScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => _engine.QuickScanAsync(progress, ct);

        public Task<ScanResult> FullScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => _engine.FullScanAsync(progress, ct);

        public Task<string> GetVersionAsync() => _engine.GetVersionAsync();
    }

    /// <summary>Gestion de la tâche planifiée Windows (schtasks).</summary>
    public interface IScheduledScanService
    {
        bool CreateDailyScan(TimeSpan? time = null);
        bool DeleteTask();
        bool IsTaskExists();
        DateTime? GetNextRunTime();
        bool RunNow();
    }

    /// <summary>Réputation cloud (VirusTotal) pour enrichissement des menaces.</summary>
    public interface IThreatReputationService
    {
        Task<ThreatReputationService.ReputationResult> LookupFileAsync(string filePath, CancellationToken ct = default);
    }
}
