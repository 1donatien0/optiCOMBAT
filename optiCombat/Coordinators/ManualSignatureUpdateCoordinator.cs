using optiCombat.Localization;
using optiCombat.Services;
using optiCombat.Strings;

namespace optiCombat.Coordinators;

/// <summary>Mise à jour manuelle des signatures (boutons Accueil / Antivirus) — extrait de <see cref="optiCombat.MainWindow"/>.</summary>
public static class ManualSignatureUpdateCoordinator
{
    public sealed class Host
    {
        public required SignatureUpdateUiRunner Runner { get; init; }
        public required FreshclamUpdater Freshclam { get; init; }
        public required YaraForgeUpdater Rules { get; init; }
        public required SignatureStatusService SignatureStatus { get; init; }
        public required Action<string, bool, bool, string?> SetStatus { get; init; }
        public required Action RefreshLiveFooter { get; init; }
        public required Func<bool, Task> RefreshSignaturesDisplayAsync { get; init; }
        public Action<bool>? SetSignatureUpdating { get; init; }
        public Action<string>? AppendSignatureLog { get; init; }
    }

    public static async Task RunAsync(Host host)
    {
        if (!host.Runner.TryEnterUpdate())
        {
            host.SetStatus(OpticombatStrings.StatusUpdates.SignaturesUpdateAlreadyRunning, false, true, null);
            return;
        }

        host.SetStatus(OpticombatStrings.StatusUpdates.FullSignaturesUpdateStarting, false, false, UiIconKinds.Refresh);
        host.RefreshLiveFooter();
        var completedOk = true;

        try
        {
            await Task.Yield();

            host.SetSignatureUpdating?.Invoke(true);

            completedOk = await host.Runner.RunFullUpdateAsync(
                host.Freshclam,
                host.Rules,
                line => host.AppendSignatureLog?.Invoke(line)).ConfigureAwait(true);

            host.SignatureStatus.InvalidateCache();
            await host.RefreshSignaturesDisplayAsync(true).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            completedOk = false;
            AppLogger.Error("ManualSignatureUpdate", "RunAsync", ex);
            host.AppendSignatureLog?.Invoke(UiLogText.Error($"Erreur : {ex.Message}"));
            host.SetStatus(LocalizationService.Format("Status_UpdateError", ex.Message), true, false, null);
        }
        finally
        {
            host.SetSignatureUpdating?.Invoke(false);
            await host.RefreshSignaturesDisplayAsync(false).ConfigureAwait(true);
            if (completedOk)
                host.SetStatus(OpticombatStrings.StatusUpdates.FullSignaturesUpdateFinished, false, false, null);
            else
                host.SetStatus(OpticombatStrings.StatusUpdates.FullSignaturesUpdateFinishedWithErrors, false, true, null);

            host.RefreshLiveFooter();
            host.Runner.ReleaseUpdate();
        }
    }

    public static void Stop(StopHost host)
    {
        host.SetStatus(OpticombatStrings.StatusUpdates.SignaturesUpdateStopping, false, false, UiIconKinds.Stop);

        try { host.Freshclam.CancelUpdate(); }
        catch (Exception ex) { AppLogger.Warn("ManualSignatureUpdate", "CancelUpdate ClamAV", ex); }

        try { host.Rules.CancelUpdate(); }
        catch (Exception ex) { AppLogger.Warn("ManualSignatureUpdate", "CancelUpdate règles", ex); }

        host.AppendSignatureLog?.Invoke(LocalizationService.GetString("Status_SigInterrupted"));
        host.SetSignatureUpdating?.Invoke(false);
    }

    public sealed class StopHost
    {
        public required FreshclamUpdater Freshclam { get; init; }
        public required YaraForgeUpdater Rules { get; init; }
        public required Action<string, bool, bool, string?> SetStatus { get; init; }
        public Action<string>? AppendSignatureLog { get; init; }
        public Action<bool>? SetSignatureUpdating { get; init; }
    }
}
