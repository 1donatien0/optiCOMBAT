using optiCombat.Localization;

namespace optiCombat.Services
{
    /// <summary>Journal utilisateur pour la mise à jour manuelle des signatures.</summary>
    public static class SignatureUpdateCoordinator
    {
        private static readonly TimeSpan FullUpdateTimeout = TimeSpan.FromMinutes(5);

        public static async Task<bool> RunFullSignatureUpdateAsync(
            FreshclamUpdater? freshclam,
            YaraForgeUpdater? rules,
            Action<string> appendLog,
            CancellationToken cancellationToken = default)
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(FullUpdateTimeout);
            var ct = timeoutCts.Token;

            appendLog(LocalizationService.GetString("SigUpd_HeaderStart"));
            appendLog(LocalizationService.GetString("SigUpd_StepClam"));

            var ok = true;

            if (freshclam != null)
            {
                var clam = await freshclam.UpdateAsync(ct).ConfigureAwait(false);
                appendLog(clam.Success
                    ? UiLogText.Ok($"{LocalizationService.GetString("SigUpd_LabelClam")} : {clam.Message}")
                    : UiLogText.Error($"{LocalizationService.GetString("SigUpd_LabelClam")} : {clam.Message}"));
                if (!clam.Success)
                    ok = false;
            }

            appendLog("");
            appendLog(LocalizationService.GetString("SigUpd_StepRules"));

            if (rules != null)
            {
                var progress = new Progress<string>(appendLog);
                var rulesResult = await rules.UpdateAsync(progress, ct).ConfigureAwait(false);
                appendLog(rulesResult.Success
                    ? UiLogText.Ok($"{LocalizationService.GetString("SigUpd_LabelRules")} : {rulesResult.Message}")
                    : UiLogText.Error($"{LocalizationService.GetString("SigUpd_LabelRules")} : {rulesResult.Message}"));
                if (!rulesResult.Success)
                    ok = false;
            }

            appendLog("");
            appendLog(LocalizationService.GetString("SigUpd_HeaderDone"));
            return ok;
        }
    }
}
