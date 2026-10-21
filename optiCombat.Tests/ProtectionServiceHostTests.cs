using Moq;
using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ProtectionServiceHostTests
{
    [Fact]
    public async Task Start_is_idempotent_and_StopAsync_shuts_down_dependencies()
    {
        var deps = new FakeProtectionHostDependencies();
        var host = new ProtectionServiceHost(deps);

        host.Start();
        host.Start();

        Assert.Equal(1, deps.ApplyCount);

        await host.StopAsync();

        Assert.Equal(1, deps.ShutdownCount);
    }

    private sealed class FakeProtectionHostDependencies : IProtectionServiceHostDependencies
    {
        public int ApplyCount { get; private set; }
        public int ShutdownCount { get; private set; }

        private readonly ScanOrchestrator _orchestrator;
        private readonly QuarantineManager _quarantine;
        private readonly ScanLogManager _logger;
        private readonly NotificationService _notifications;
        private readonly CloudThreatIntelService _cloud;

        public FakeProtectionHostDependencies()
        {
            var root = Path.Combine(Path.GetTempPath(), "opticombat_host_" + Guid.NewGuid().ToString("N"));
            _orchestrator = new ScanOrchestrator(new FakeClam(), new FakeYara());
            _quarantine = new QuarantineManager(Path.Combine(root, "q"));
            _logger = new ScanLogManager(Path.Combine(root, "logs"));
            _notifications = new NotificationService();
            _cloud = new CloudThreatIntelService(new FakeReputation());
            var gateway = new ProtectionScanGateway(_orchestrator);
            RealTimeProtection = new RealTimeProtection(gateway, _quarantine, _notifications);
            ProcessStartMonitor = new ProcessStartMonitor(
                gateway, _quarantine, _notifications, () => RealTimeProtection.IsPaused);
            RemovableDriveScan = new RemovableDriveScanService(
                _orchestrator, _quarantine, _notifications, _logger, RealTimeProtection, new UiEventBus());
        }

        public RealTimeProtection RealTimeProtection { get; }
        public ProcessStartMonitor ProcessStartMonitor { get; }
        public RemovableDriveScanService RemovableDriveScan { get; }
        public IExclusionSettingsAccessor ExclusionSettingsAccessor { get; } = new DefaultExclusionSettingsAccessor();
        public IUserPreferencesAccessor UserPreferencesAccessor { get; } = new DefaultUserPreferencesAccessor();
        public ScanOrchestrator Orchestrator => _orchestrator;
        public QuarantineManager Quarantine => _quarantine;
        public ScanLogManager Logger => _logger;
        public CloudThreatIntelService CloudThreatIntel => _cloud;

        public void ApplyPreferencesOnStartup() => ApplyCount++;

        public void Shutdown() => ShutdownCount++;
    }

    private sealed class FakeClam : IClamAvOrchestratorBackend
    {
        public bool IsClamAvInstalled() => true;
        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new ScanResult { Status = ScanStatus.Completed, TargetPath = filePath });
        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new ScanResult { Status = ScanStatus.Completed, TargetPath = folderPath });
        public Task<ScanResult> ScanFileListAsync(IReadOnlyList<string> files, string targetPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new ScanResult { Status = ScanStatus.Completed, TargetPath = targetPath, FilesScanned = files.Count });
    }

    private sealed class FakeYara : IYaraOrchestratorBackend
    {
        public bool IsAvailable => true;
        public int RulesCount => 1;
        public Task<List<YaraMatch>> ScanFileAsync(string filePath, CancellationToken ct = default) =>
            Task.FromResult(new List<YaraMatch>());
        public Task<List<YaraMatch>> ScanFolderAsync(string folderPath, IProgress<string>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new List<YaraMatch>());
        public Task<List<YaraMatch>> ScanFilesAsync(IReadOnlyList<string> files, IProgress<string>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new List<YaraMatch>());
    }

    private sealed class FakeReputation : IThreatReputationService
    {
        public Task<ThreatReputationService.ReputationResult> LookupFileAsync(string filePath, CancellationToken ct = default) =>
            Task.FromResult(new ThreatReputationService.ReputationResult());
    }
}
