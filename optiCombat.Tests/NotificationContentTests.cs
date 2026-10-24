using Microsoft.Toolkit.Uwp.Notifications;
using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

/// <summary>Contenu des toasts (capturés, jamais affichés) et décodage des clics.</summary>
[Collection("OpticombatPrefs")]
public sealed class NotificationContentTests : IDisposable
{
    private readonly List<string> _xml = new();
    private readonly NotificationService _svc;

    public NotificationContentTests()
    {
        LocalizationService.ApplyCulture("fr-FR");
        DistractionFreeMonitor.ResetForTests();
        NotificationService.ResetActivationHookForTests();
        _svc = new NotificationService(new FixedPreferencesAccessor(new UserPreferences()))
        {
            IsEnabled = true,
            PresentOverride = b => _xml.Add(b.GetToastContent().GetContent()),
        };
    }

    public void Dispose() => NotificationService.ResetActivationHookForTests();

    private string Single() => Assert.Single(_xml);

    private static ThreatInfo Threat() => new()
    {
        FilePath = Path.Combine(Path.GetTempPath(), "dossier", "facture.exe"),
        VirusName = "Win.Trojan.Test",
        DetectedBy = "ClamAV",
    };

    [Fact]
    public void Threat_toast_carries_quarantine_and_ignore_actions_for_the_file()
    {
        _svc.ShowThreatDetected(Threat());
        var xml = Single();

        Assert.Contains("Win.Trojan.Test", xml, StringComparison.Ordinal);
        Assert.Contains("facture.exe", xml, StringComparison.Ordinal);
        Assert.Contains("action=quarantine", xml, StringComparison.Ordinal);
        Assert.Contains("action=ignore", xml, StringComparison.Ordinal);
        Assert.Contains("duration=\"long\"", xml, StringComparison.Ordinal);
    }

    [Fact]
    public void Quarantined_and_rtp_toasts_are_built()
    {
        _svc.ShowQuarantined(Threat());
        _svc.ShowRealTimeProtectionStarted();
        _svc.ShowUpdateAvailable("9.9.9");

        Assert.Equal(3, _xml.Count);
        Assert.Contains("facture.exe", _xml[0], StringComparison.Ordinal);
        Assert.Contains("action=rtpstarted", _xml[1], StringComparison.Ordinal);
        Assert.Contains("9.9.9", _xml[2], StringComparison.Ordinal);
    }

    [Fact]
    public void Scan_completed_toast_differs_for_clean_and_infected_results()
    {
        _svc.ShowScanCompleted(0, 12);
        _svc.ShowScanCompleted(3, 50);

        Assert.Contains("action=scanok", _xml[0], StringComparison.Ordinal);
        Assert.Contains("12", _xml[0], StringComparison.Ordinal);
        Assert.Contains("action=scanthreats", _xml[1], StringComparison.Ordinal);
        Assert.Contains("action=history", _xml[1], StringComparison.Ordinal);
    }

    [Fact]
    public void Removable_drive_toasts_name_the_drive()
    {
        _svc.ShowRemovableDriveScanStarted("CLE_USB (E:)");
        _svc.ShowRemovableDriveScanCompleted("CLE_USB (E:)", 0, 10);
        _svc.ShowRemovableDriveScanCompleted("CLE_USB (E:)", 2, 10);

        Assert.Equal(3, _xml.Count);
        Assert.All(_xml, x => Assert.Contains("CLE_USB (E:)", x, StringComparison.Ordinal));
        Assert.NotEqual(_xml[1], _xml[2]);
    }

    [Fact]
    public void Disabled_toasts_are_not_built()
    {
        _svc.IsEnabled = false;
        _svc.ShowThreatDetected(Threat());
        _svc.ShowQuarantined(Threat());
        _svc.ShowScanCompleted(1, 1);
        _svc.ShowUpdateAvailable("1");
        _svc.ShowRealTimeProtectionStarted();
        _svc.ShowRemovableDriveScanStarted("E:");
        _svc.ShowRemovableDriveScanCompleted("E:", 1, 1);
        Assert.Empty(_xml);
    }

    [Fact]
    public void Failure_while_presenting_is_logged_not_thrown()
    {
        _svc.PresentOverride = _ => throw new InvalidOperationException("COM indisponible");
        _svc.ShowThreatDetected(Threat());
        _svc.ShowScanCompleted(0, 1);
        _svc.ShowRemovableDriveScanCompleted("E:", 1, 1);
    }

    [Fact]
    public void SyncFromUserPreferences_follows_the_setting()
    {
        var prefs = new UserPreferences { ActionNotificationsEnabled = false };
        var svc = new NotificationService(new FixedPreferencesAccessor(prefs)) { IsEnabled = true };
        svc.SyncFromUserPreferences();
        Assert.False(svc.IsEnabled);
    }

    [Fact]
    public void Clicked_threat_button_is_decoded_with_file_and_virus()
    {
        ToastActivationEventArgs? got = null;
        _svc.ToastActivated += (_, e) => got = e;
        var argument = new ToastArguments()
            .Add("action", "quarantine").Add("file", @"C:\x\y.exe").Add("virus", "Win.Test").ToString();

        NotificationService.HandleActivationArgument(argument);

        Assert.NotNull(got);
        Assert.Equal("quarantine", got.Action);
        Assert.Equal(@"C:\x\y.exe", got.FilePath);
        Assert.Equal("Win.Test", got.VirusName);
    }

    [Fact]
    public void Clicked_button_with_only_an_action_is_still_dispatched()
    {
        // Régression : « Get » levait KeyNotFoundException sur « file » → clic « Ouvrir l'antivirus » perdu.
        ToastActivationEventArgs? got = null;
        _svc.ToastActivated += (_, e) => got = e;

        NotificationService.HandleActivationArgument(new ToastArguments().Add("action", "openav").ToString());

        Assert.NotNull(got);
        Assert.Equal("openav", got.Action);
        Assert.Null(got.FilePath);
        Assert.Null(got.VirusName);
    }

    [Fact]
    public void Empty_or_malformed_argument_does_not_throw()
    {
        var count = 0;
        _svc.ToastActivated += (_, _) => count++;
        NotificationService.HandleActivationArgument(string.Empty);
        NotificationService.HandleActivationArgument("action");
        Assert.True(count <= 2);
    }
}
