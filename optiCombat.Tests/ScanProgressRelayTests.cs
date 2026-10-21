using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ScanProgressRelayTests
{
    [Fact]
    public void Relay_keeps_monotonic_files_across_local_resets()
    {
        var reported = new List<int>();
        var relay = new ScanProgressRelay(12_000);
        var progress = relay.ToParent(new CollectProgress(reported));
        Assert.NotNull(progress);

        progress.Report(new ScanProgress { ClamFilesScanned = 120, Phase = ScanPhase.Scanning });
        progress.Report(new ScanProgress { ClamFilesScanned = 50, Phase = ScanPhase.Scanning });
        progress.Report(new ScanProgress { ClamFilesScanned = 0, Phase = ScanPhase.Scanning });

        Assert.Equal(3, reported.Count);
        Assert.All(reported, n => Assert.Equal(12_120, n));
    }

    [Fact]
    public void Relay_advances_display_when_both_engines_report_progress()
    {
        var reported = new List<int>();
        var relay = new ScanProgressRelay();
        var progress = relay.ToParent(new CollectProgress(reported));
        Assert.NotNull(progress);

        progress.Report(new ScanProgress { ClamFilesScanned = 120, Phase = ScanPhase.Scanning });
        progress.Report(new ScanProgress { YaraFilesScanned = 12, Phase = ScanPhase.Scanning });

        Assert.Equal(2, reported.Count);
        Assert.Equal(120, reported[0]);
        Assert.True(reported[1] > reported[0]);
    }

    [Fact]
    public void Relay_grows_when_second_engine_advances_after_first()
    {
        var reported = new List<int>();
        var relay = new ScanProgressRelay();
        var progress = relay.ToParent(new CollectProgress(reported));
        Assert.NotNull(progress);

        progress.Report(new ScanProgress { ClamFilesScanned = 8000, Phase = ScanPhase.Scanning });
        progress.Report(new ScanProgress { YaraFilesScanned = 200, Phase = ScanPhase.Scanning });
        progress.Report(new ScanProgress { YaraFilesScanned = 400, Phase = ScanPhase.Scanning });

        Assert.Equal(3, reported.Count);
        Assert.Equal(8000, reported[0]);
        Assert.True(reported[1] > 8000);
        Assert.True(reported[2] >= reported[1]);
    }

    [Fact]
    public void Relay_grows_total_when_scanned_exceeds_yara_estimate()
    {
        var reported = new List<ScanProgress>();
        var relay = new ScanProgressRelay();
        var progress = relay.ToParent(new CollectProgressFull(reported));
        Assert.NotNull(progress);

        progress.Report(new ScanProgress { TotalFiles = 100, FilesScanned = 0, Phase = ScanPhase.Starting });
        progress.Report(new ScanProgress { ClamFilesScanned = 50, Phase = ScanPhase.Scanning });
        progress.Report(new ScanProgress { ClamFilesScanned = 200, Phase = ScanPhase.Scanning });

        var last = reported[^1];
        Assert.Equal(200, last.FilesScanned);
        Assert.Equal(200, last.TotalFiles);
    }

    [Fact]
    public void Relay_completed_snaps_to_final_engine_max()
    {
        var reported = new List<int>();
        var relay = new ScanProgressRelay();
        var progress = relay.ToParent(new CollectProgress(reported));
        Assert.NotNull(progress);

        progress.Report(new ScanProgress { ClamFilesScanned = 5000, Phase = ScanPhase.Scanning });
        progress.Report(new ScanProgress { YaraFilesScanned = 3000, Phase = ScanPhase.Scanning });
        progress.Report(new ScanProgress { Phase = ScanPhase.Completed, FilesScanned = 5000 });

        Assert.Equal(5000, reported[^1]);
    }

    private sealed class CollectProgress(List<int> sink) : IProgress<ScanProgress>
    {
        public void Report(ScanProgress value) => sink.Add(value.FilesScanned);
    }

    private sealed class CollectProgressFull(List<ScanProgress> sink) : IProgress<ScanProgress>
    {
        public void Report(ScanProgress value) => sink.Add(value);
    }
}
