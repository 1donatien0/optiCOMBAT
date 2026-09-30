using Moq;
using optiCombat.Models;
using optiCombat.Services;
using System.Reflection;

namespace optiCombat.Tests;

public sealed class RemovableDriveScanServiceTests
{
    [Fact]
    public void Start_and_Stop_are_idempotent()
    {
        using var service = CreateService(out _);
        service.Start();
        service.Start();
        service.Stop();
        service.Stop();
    }

    [Fact]
    public async Task RunScanAsync_on_empty_folder_refreshes_history_and_emits_status()
    {
        var root = Path.Combine(Path.GetTempPath(), "opticombat_usb_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var ui = new Mock<IUiEventBus>(MockBehavior.Strict);
        ui.Setup(u => u.RequestScanHistoryViewsRefresh());

        var phases = new List<RemovableDriveScanPhase>();
        using var service = CreateService(out var logger, ui.Object);
        service.ScanStatusChanged += (_, e) => phases.Add(e.Phase);

        var detailed = UserPreferences.Current.RemovableDriveScanDetailed;
        var enabled = UserPreferences.Current.RemovableDriveScanEnabled;
        try
        {
            UserPreferences.Current.RemovableDriveScanDetailed = false;
            UserPreferences.Current.RemovableDriveScanEnabled = true;

            await InvokeRunScanAsync(service, root);

            ui.Verify(u => u.RequestScanHistoryViewsRefresh(), Times.Once);
            Assert.Contains(RemovableDriveScanPhase.Started, phases);
            Assert.Contains(RemovableDriveScanPhase.Completed, phases);
            Assert.NotEmpty(logger.GetHistory());
        }
        finally
        {
            UserPreferences.Current.RemovableDriveScanDetailed = detailed;
            UserPreferences.Current.RemovableDriveScanEnabled = enabled;
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public async Task RunScanAsync_raises_ThreatDetected_when_scan_finds_malware()
    {
        var root = Path.Combine(Path.GetTempPath(), "opticombat_usb_threat_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var sample = Path.Combine(root, "malware.exe");
        await File.WriteAllBytesAsync(sample, [0x4D, 0x5A]);

        ThreatInfo? detected = null;
        var ui = new Mock<IUiEventBus>(MockBehavior.Strict);
        ui.Setup(u => u.RequestScanHistoryViewsRefresh());

        using var service = CreateService(out _, ui.Object, new ThreatClamBackend());
        service.ThreatDetected += (_, t) => detected = t;

        var detailed = UserPreferences.Current.RemovableDriveScanDetailed;
        var enabled = UserPreferences.Current.RemovableDriveScanEnabled;
        try
        {
            UserPreferences.Current.RemovableDriveScanDetailed = false;
            UserPreferences.Current.RemovableDriveScanEnabled = true;
            await InvokeRunScanAsync(service, root);
            Assert.NotNull(detected);
            Assert.Equal("USB.Test", detected!.VirusName);
        }
        finally
        {
            UserPreferences.Current.RemovableDriveScanDetailed = detailed;
            UserPreferences.Current.RemovableDriveScanEnabled = enabled;
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    private static RemovableDriveScanService CreateService(
        out ScanLogManager logger,
        IUiEventBus? ui = null,
        IClamAvOrchestratorBackend? clam = null)
    {
        var orch = new ScanOrchestrator(clam ?? new FakeClamBackend(), new FakeYaraBackend());
        var qDir = Path.Combine(Path.GetTempPath(), "opticombat_usb_q_" + Guid.NewGuid().ToString("N"));
        var q = new QuarantineManager(qDir);
        logger = new ScanLogManager(Path.Combine(Path.GetTempPath(), "opticombat_usb_log_" + Guid.NewGuid().ToString("N")));
        var gateway = new ProtectionScanGateway(orch);
        var rtp = new RealTimeProtection(gateway, q, new NotificationService());
        ui ??= new UiEventBus();
        return new RemovableDriveScanService(orch, q, new NotificationService(), logger, rtp, ui);
    }

    private static async Task InvokeRunScanAsync(RemovableDriveScanService service, string root)
    {
        var method = typeof(RemovableDriveScanService).GetMethod(
            "RunScanAsync",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(method);
        await (Task)method!.Invoke(service, [root])!;
    }

    private sealed class FakeClamBackend : IClamAvOrchestratorBackend
    {
        public bool IsClamAvInstalled() => true;
        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(Completed(filePath, ScanType.File));
        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(Completed(folderPath, ScanType.Folder));
        public Task<ScanResult> ScanFileListAsync(IReadOnlyList<string> files, string targetPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(Completed(targetPath, ScanType.RemovableDrive, files.Count));

        private static ScanResult Completed(string target, ScanType type, int files = 0) => new()
        {
            Type = type,
            TargetPath = target,
            Status = ScanStatus.Completed,
            FilesScanned = files,
            StartedAt = DateTime.UtcNow,
            FinishedAt = DateTime.UtcNow,
        };
    }

    private sealed class FakeYaraBackend : IYaraOrchestratorBackend
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

    private sealed class ThreatClamBackend : IClamAvOrchestratorBackend
    {
        public bool IsClamAvInstalled() => true;
        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(ThreatResult(filePath, ScanType.File));
        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(ThreatResult(folderPath, ScanType.Folder));
        public Task<ScanResult> ScanFileListAsync(IReadOnlyList<string> files, string targetPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(ThreatResult(targetPath, ScanType.RemovableDrive, files.Count));

        private static ScanResult ThreatResult(string target, ScanType type, int files = 1) => new()
        {
            Type = type,
            TargetPath = target,
            Status = ScanStatus.Completed,
            FilesScanned = files,
            StartedAt = DateTime.UtcNow,
            FinishedAt = DateTime.UtcNow,
            Threats =
            [
                new ThreatInfo
                {
                    FilePath = Path.Combine(target.TrimEnd('\\'), "malware.exe"),
                    VirusName = "USB.Test",
                    FileSize = 2,
                },
            ],
        };
    }
}
