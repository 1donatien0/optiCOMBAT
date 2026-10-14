using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ScheduledScanServiceTests
{
    [Fact]
    public void TryParseNextRunFromTaskXml_parses_start_boundary_time()
    {
        const string xml = """
            <?xml version="1.0" encoding="UTF-16"?>
            <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Triggers>
                <CalendarTrigger>
                  <StartBoundary>2026-06-01T02:30:00</StartBoundary>
                </CalendarTrigger>
              </Triggers>
            </Task>
            """;

        Assert.True(ScheduledScanService.TryParseNextRunFromTaskXml(xml, out var next));
        Assert.Equal(2, next.Hour);
        Assert.Equal(30, next.Minute);
        Assert.True(next > DateTime.Now.AddMinutes(-1));
    }

    [Fact]
    public void TryParseNextRunFromTaskXml_invalid_xml_returns_false()
    {
        Assert.False(ScheduledScanService.TryParseNextRunFromTaskXml("not xml", out _));
    }

    [Fact]
    public void TryParseNextRunFromListOutput_parses_english_next_run_time()
    {
        const string text = """
            Folder: \
            HostName:                              DESKTOP
            TaskName:                              \optiCombat_DailyScan
            Next Run Time:                         6/15/2026 2:00:00 AM
            Status:                                Ready
            """;

        Assert.True(ScheduledScanService.TryParseNextRunFromListOutput(text, out var next));
        Assert.Equal(2, next.Hour);
    }

    [Fact]
    public void TryParseNextRunFromListOutput_parses_french_prochaine_execution()
    {
        const string text = """
            Dossier :                              \
            Nom de l'hôte :                       DESKTOP
            Nom de la tâche :                     \optiCombat_DailyScan
            Prochaine exécution :                  15/06/2026 02:00:00
            Statut :                               Prêt
            """;

        Assert.True(ScheduledScanService.TryParseNextRunFromListOutput(text, out var next));
        Assert.Equal(2, next.Hour);
    }

    [Fact]
    public void TryParseNextRunFromListOutput_na_value_returns_false()
    {
        const string text = "Next Run Time: N/A";
        Assert.False(ScheduledScanService.TryParseNextRunFromListOutput(text, out _));
    }
}
