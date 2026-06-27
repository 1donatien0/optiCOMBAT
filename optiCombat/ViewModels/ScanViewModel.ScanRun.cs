using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Strings;
using System.Windows.Threading;
using WpfApp = System.Windows.Application;

namespace optiCombat.ViewModels
{
    public partial class ScanViewModel
    {
        private async Task StartScanAsync(ScanType type, string? path = null)
        {
            if (IsScanning) return;

            IsScanning = true;
            IsIndeterminate = true;
            ProgressValue = 0;
            FilesScanned = 0;
            ThreatsFound = 0;
            CurrentScanItem = ScanUserDisplay.Preparation;
            ScanProgressDetail = ScanUserDisplay.Preparation;

            WpfApp.Current?.Dispatcher.Invoke(() =>
            {
                Threats.Clear();
                _scanThreatPaths.Clear();
                _quarantinedDuringScanPaths.Clear();
            });

            _activeScanSessionId = Guid.NewGuid();

            if (type is ScanType.QuickScan or ScanType.FullScan or ScanType.File or ScanType.Folder)
            {
                _navigation?.NavigateTo(OpticombatStrings.PanelIds.Antivirus);
                DisplayScanProgressRequested?.Invoke(this, EventArgs.Empty);
            }

            if (type == ScanType.FullScan && !ElevationHelper.IsRunningElevated())
                StatusMessage = LocalizationService.GetString("Scan_FullPartialWithoutAdmin");
            else
                StatusMessage = ScanUserDisplay.ScanStarting(type, path);

            _cts = new CancellationTokenSource();
            var epoch = Interlocked.Increment(ref _scanEpoch);
            var progress = new Progress<ScanProgress>(p => SurChangementProgressionScan(p, epoch));

            _realTimeProtection.Suspend();
            try
            {
                ScanResult result = type switch
                {
                    ScanType.QuickScan => await _orchestrator.QuickScanAsync(progress, _cts.Token),
                    ScanType.FullScan => await _orchestrator.FullScanAsync(progress, _cts.Token),
                    ScanType.Folder => await _orchestrator.ScanFolderAsync(path!, progress, _cts.Token),
                    ScanType.File => await _orchestrator.ScanFileAsync(path!, progress, _cts.Token),
                    _ => throw new InvalidOperationException(),
                };

                FlushPendingProgressToUiImmediate(epoch);

                result.SessionId = _activeScanSessionId;
                RemoveAlreadyQuarantinedThreats(result);

                LastResult = result;
                _logger.SaveScanResult(result);
                var prefs = _prefs.Current;
                prefs.FavoriteScanType = type;
                if (type is ScanType.File or ScanType.Folder && !string.IsNullOrWhiteSpace(path))
                    prefs.AddRecentTarget(path, type);
                else if (type is ScanType.QuickScan or ScanType.FullScan)
                    prefs.AddRecentTarget(string.Empty, type);
                prefs.IncrementScanCount(type);
                RefreshRecentTargets();
                LoadHistory();
                _uiEvents.RequestScanHistoryViewsRefresh();

                WpfApp.Current?.Dispatcher.Invoke(() =>
                {
                    foreach (var t in result.Threats)
                    {
                        if (_scanThreatPaths.Add(t.FilePath))
                            Threats.Add(t);
                    }
                });

                int autoQuarantined = 0;
                if (_exclusions.Current.AutoQuarantineEnabled && result.Threats.Count > 0)
                {
                    autoQuarantined = _quarantine.QuarantineAll(result.Threats, result.SessionId);
                    WpfApp.Current?.Dispatcher.Invoke(LoadQuarantine);
                    _uiEvents.RequestScanHistoryViewsRefresh();
                }

                StatusMessage = autoQuarantined > 0
                    ? LocalizationService.Format("Vm_AutoQuarantineMsg", result.SummaryDisplay, autoQuarantined)
                    : result.SummaryDisplay;
                FilesScanned = result.FilesScanned;
                ThreatsFound = result.Threats.Count;

                if (_prefs.Current.ActionNotificationsEnabled)
                {
                    _notifications.ShowScanCompleted(
                        result.Threats.Count,
                        result.FilesScanned);
                }
            }
            catch (OperationCanceledException)
            {
                StatusMessage = OpticombatStrings.UiMessages.AnalyseInterrompueSurDemande;
            }
            catch (Exception ex)
            {
                StatusMessage = LocalizationService.Format("Vm_ScanError", ex.Message);
            }
            finally
            {
                FlushPendingProgressToUiImmediate(_scanEpoch);
                Interlocked.Increment(ref _scanEpoch);
                IsScanning = false;
                IsIndeterminate = false;
                ProgressValue = 0;
                CurrentScanItem = string.Empty;
                ScanProgressDetail = string.Empty;
                _cts?.Dispose();
                _cts = null;
                _realTimeProtection.Resume();
            }
        }

        private void SurChangementProgressionScan(ScanProgress p, long epoch)
        {
            lock (_progressCoalesceLock)
            {
                _pendingProgress = p;
                _pendingProgressEpoch = epoch;
            }
            ArmProgressCoalesceTimer();
        }

        private void ArmProgressCoalesceTimer()
        {
            var disp = WpfApp.Current?.Dispatcher;
            if (disp == null) return;

            if (Interlocked.CompareExchange(ref _progressCoalesceArmPosted, 1, 0) != 0)
                return;

            disp.BeginInvoke(() =>
            {
                EnsureProgressCoalesceTimer();
                _progressCoalesceTimer!.Stop();
                _progressCoalesceTimer.Start();
            }, DispatcherPriority.Background);
        }

        private void EnsureProgressCoalesceTimer()
        {
            if (_progressCoalesceTimer != null) return;

            var disp = WpfApp.Current?.Dispatcher;
            if (disp == null) return;

            _progressCoalesceTimer = new DispatcherTimer(
                ProgressCoalesceInterval,
                DispatcherPriority.Background,
                FlushPendingProgressToUi,
                disp);
        }

        private void FlushPendingProgressToUi(object? sender, EventArgs e)
        {
            _progressCoalesceTimer?.Stop();
            Interlocked.Exchange(ref _progressCoalesceArmPosted, 0);

            ScanProgress? p;
            long epoch;
            lock (_progressCoalesceLock)
            {
                p = _pendingProgress;
                epoch = _pendingProgressEpoch;
            }

            if (p == null || epoch != _scanEpoch) return;
            ApplyProgressSnapshot(p);

            lock (_progressCoalesceLock)
            {
                if (_pendingProgress != null && _pendingProgressEpoch == epoch)
                    ArmProgressCoalesceTimer();
            }
        }

        private void FlushPendingProgressToUiImmediate(long epoch)
        {
            var disp = WpfApp.Current?.Dispatcher;
            if (disp == null) return;

            disp.Invoke(() =>
            {
                _progressCoalesceTimer?.Stop();
                Interlocked.Exchange(ref _progressCoalesceArmPosted, 0);

                ScanProgress? p;
                long pendingEpoch;
                lock (_progressCoalesceLock)
                {
                    p = _pendingProgress;
                    pendingEpoch = _pendingProgressEpoch;
                }

                if (p == null || pendingEpoch != epoch) return;
                ApplyProgressSnapshot(p);
            });
        }

        private void ApplyProgressSnapshot(ScanProgress p)
        {
            if (p.FilesScanned > 0)
                FilesScanned = Math.Max(FilesScanned, p.FilesScanned);
            if (p.ThreatsFound > 0)
                ThreatsFound = Math.Max(ThreatsFound, p.ThreatsFound);

            if (!string.IsNullOrWhiteSpace(p.CurrentFilePath))
                CurrentScanItem = p.CurrentFilePath;
            else if (p.Phase == ScanPhase.ThreatFound && p.ThreatInfo != null
                     && !string.IsNullOrWhiteSpace(p.ThreatInfo.FilePath))
                CurrentScanItem = p.ThreatInfo.FilePath;

            int displayedFiles = FilesScanned;

            if (p.Phase != ScanPhase.ThreatFound)
            {
                StatusMessage = ScanUserDisplay.SyncFileCountInMessage(
                    ScanUserDisplay.ForProgressMessage(p.Message),
                    displayedFiles);
            }

            if (p.TotalFiles > 0 && displayedFiles > 0)
            {
                var pctVal = Math.Min(100.0, displayedFiles * 100.0 / p.TotalFiles);
                ScanProgressDetail = LocalizationService.Format(
                    "Vm_ScanProgressCountPct", displayedFiles, p.TotalFiles, (int)pctVal);
            }
            else if (displayedFiles > 0)
            {
                ScanProgressDetail = LocalizationService.Format("Vm_ScanProgressScanned", displayedFiles);
            }
            else if (p.TotalFiles > 0)
            {
                ScanProgressDetail = LocalizationService.Format("Vm_ScanProgressEstimated", p.TotalFiles);
            }
            else
            {
                ScanProgressDetail = LocalizationService.GetString("Vm_ScanInProgress");
            }

            if (p.TotalFiles > 0 && displayedFiles > 0)
            {
                IsIndeterminate = false;
                ProgressValue = Math.Min(100.0, displayedFiles * 100.0 / p.TotalFiles);
            }
            else if (displayedFiles > 0)
            {
                IsIndeterminate = true;
            }

            if (p.Phase == ScanPhase.ThreatFound && p.ThreatInfo != null)
            {
                CurrentScanItem = p.ThreatInfo.FilePath;
                StatusMessage = p.ThreatInfo.VirusName;
                if (_scanThreatPaths.Add(p.ThreatInfo.FilePath))
                    Threats.Add(p.ThreatInfo);
            }
        }

        private void RemoveAlreadyQuarantinedThreats(ScanResult result)
        {
            for (int i = result.Threats.Count - 1; i >= 0; i--)
            {
                var path = result.Threats[i].FilePath;
                if (_quarantinedDuringScanPaths.Contains(path)
                    || _quarantine.GetEntries().Any(e =>
                        string.Equals(e.OriginalPath, path, StringComparison.OrdinalIgnoreCase)))
                {
                    result.Threats.RemoveAt(i);
                }
            }
        }

        private void SurAjoutSortieMiseAJour(object? sender, string line)
            => AppendUpdateLog(line);

        private void SurTermineeMiseAJourSignatures(object? sender, UpdateResult result)
        {
            var d = WpfApp.Current?.Dispatcher;
            if (d == null) return;
            _ = d.InvokeAsync(async () =>
            {
                StatusMessage = result.Message;
                DbVersion = await _updater.GetLocalDatabaseVersionAsync().ConfigureAwait(false);
                LastUpdateDisplay = _updater.LastUpdateTime?.ToString("dd/MM/yyyy HH:mm") ?? LocalizationService.GetString("Vm_Never");
                RulesPackVersion = _rulesUpdater.GetRulesPackVersionDisplay();
                RulesLastUpdateDisplay = _rulesUpdater.GetRulesLastUpdateDisplay();
            });
        }

        private void SurTermineeMiseAJourRegles(object? sender, RulesUpdateResult result)
        {
            var d = WpfApp.Current?.Dispatcher;
            if (d == null) return;
            _ = d.InvokeAsync(() =>
            {
                RulesPackVersion = _rulesUpdater.GetRulesPackVersionDisplay();
                RulesLastUpdateDisplay = _rulesUpdater.GetRulesLastUpdateDisplay();
                YaraRulesCount = _yara.RulesCount;
                YaraStatus = _yara.IsAvailable
                    ? LocalizationService.Format("Vm_YaraEngineActive", _yara.RulesCount)
                    : result.Success
                        ? LocalizationService.GetString("Vm_SigEngineReloaded")
                        : LocalizationService.GetString("Vm_SigEngineUnavailable");
                RefreshProtectionStatus();
            });
        }

        /// <summary>Scan déclenché depuis le menu contextuel Explorateur (fichier ou dossier).</summary>
        public async Task RequestContextMenuScanAsync(string path)
        {
            if (!ShellScanArguments.IsValidScanTarget(path))
            {
                StatusMessage = LocalizationService.Format("ShellScan_InvalidPath", path);
                return;
            }

            var type = ShellScanArguments.ResolveScanType(path);
            await StartScanAsync(type, path).ConfigureAwait(true);
        }
    }
}
