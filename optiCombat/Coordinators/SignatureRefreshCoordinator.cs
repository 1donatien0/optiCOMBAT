using optiCombat.Services;

namespace optiCombat.Coordinators;

/// <summary>
/// Branche les événements <see cref="FreshclamUpdater"/> / <see cref="YaraForgeUpdater"/>
/// pour rafraîchir signatures et pied de page (extrait du constructeur <see cref="optiCombat.MainWindow"/>).
/// </summary>
public sealed class SignatureRefreshCoordinator
{
    private readonly FreshclamUpdater _freshclam;
    private readonly YaraForgeUpdater _rules;
    private readonly SignatureStatusService _signatureStatus;
    private readonly EventHandler<string> _onFreshclamLog;
    private readonly EventHandler<string> _onRulesLog;
    private readonly Func<bool, Task> _refreshSignaturesAsync;
    private readonly Action _refreshFooter;
    private readonly Action<Func<Task>> _scheduleUiAsync;
    private readonly EventHandler<string> _footerOnOutput;

    public SignatureRefreshCoordinator(
        FreshclamUpdater freshclam,
        YaraForgeUpdater rules,
        SignatureStatusService signatureStatus,
        EventHandler<string> onFreshclamLog,
        EventHandler<string> onRulesLog,
        Func<bool, Task> refreshSignaturesAsync,
        Action refreshFooter,
        Action<Func<Task>> scheduleUiAsync)
    {
        _freshclam = freshclam;
        _rules = rules;
        _signatureStatus = signatureStatus;
        _onFreshclamLog = onFreshclamLog;
        _onRulesLog = onRulesLog;
        _refreshSignaturesAsync = refreshSignaturesAsync;
        _refreshFooter = refreshFooter;
        _scheduleUiAsync = scheduleUiAsync;
        _footerOnOutput = (_, _) => _refreshFooter();
    }

    public void Attach()
    {
        _freshclam.UpdateOutput += _onFreshclamLog;
        _rules.UpdateOutput += _onRulesLog;
        _freshclam.UpdateOutput += _footerOnOutput;
        _rules.UpdateOutput += _footerOnOutput;
        _freshclam.UpdateCompleted += OnFreshclamUpdateCompleted;
        _rules.UpdateCompleted += OnRulesUpdateCompleted;
    }

    public void Detach()
    {
        _freshclam.UpdateOutput -= _onFreshclamLog;
        _rules.UpdateOutput -= _onRulesLog;
        _freshclam.UpdateOutput -= _footerOnOutput;
        _rules.UpdateOutput -= _footerOnOutput;
        _freshclam.UpdateCompleted -= OnFreshclamUpdateCompleted;
        _rules.UpdateCompleted -= OnRulesUpdateCompleted;
    }

    private void OnFreshclamUpdateCompleted(object? sender, UpdateResult e) => ScheduleRefreshAfterUpdate();

    private void OnRulesUpdateCompleted(object? sender, RulesUpdateResult e) => ScheduleRefreshAfterUpdate();

    internal void ScheduleRefreshAfterUpdateForTests() => ScheduleRefreshAfterUpdate();

    private void ScheduleRefreshAfterUpdate() =>
        _scheduleUiAsync(async () =>
        {
            _signatureStatus.InvalidateCache();
            await _refreshSignaturesAsync(true).ConfigureAwait(true);
            _refreshFooter();
        });
}
