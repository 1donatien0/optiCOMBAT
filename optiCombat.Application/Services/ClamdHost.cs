using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;

namespace optiCombat.Services
{
    /// <summary>Démarre et arrête clamd.exe avec une configuration gérée par optiCombat.</summary>
    [SupportedOSPlatform("windows")]
    internal sealed class ClamdHost : IDisposable
    {
        private static readonly object Gate = new();
        private static readonly SemaphoreSlim StartGate = new(1, 1);
        private static ClamdHost? _shared;

        private readonly string _clamdExe;
        private readonly string _databaseDir;
        private readonly Func<CancellationToken, Task<bool>> _ping;
        private readonly TimeSpan _startTimeout;
        private Process? _process;
        private bool _disposed;

        public static ClamdHost Shared
        {
            get
            {
                lock (Gate)
                {
                    var binDir = ClamAvDatabasePaths.ResolveClamAvBinDir("clamd.exe");
                    var dbDir = ClamAvDatabasePaths.ResolveWritableDatabaseDir(binDir);
                    return _shared ??= new ClamdHost(binDir, dbDir);
                }
            }
        }

        private ClamdHost(string clamavBinDir, string databaseDir)
            : this(clamavBinDir, databaseDir, DefaultPingAsync, TimeSpan.FromSeconds(20))
        {
        }

        /// <summary>Constructeur de test : sonde PING et délai de démarrage injectés.</summary>
        internal ClamdHost(
            string clamavBinDir, string databaseDir, Func<CancellationToken, Task<bool>> ping, TimeSpan startTimeout)
        {
            _clamdExe = Path.Combine(clamavBinDir, "clamd.exe");
            _databaseDir = databaseDir;
            _ping = ping;
            _startTimeout = startTimeout;
        }

        /// <summary>Processus clamd lancé par cet hôte et toujours actif.</summary>
        internal bool IsProcessRunning => _process is { HasExited: false };

        public bool IsBinaryPresent => File.Exists(_clamdExe);

        public async Task<bool> EnsureRunningAsync(CancellationToken ct = default)
        {
            if (!IsBinaryPresent)
                return false;

            if (await _ping(ct).ConfigureAwait(false))
                return true;

            await StartGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (await _ping(ct).ConfigureAwait(false))
                    return true;

                lock (Gate)
                {
                    try
                    {
                        StopProcessLocked();
                        var excludePatterns = AppInstallPaths.GetClamScanExcludePatterns().ToList();
                        ClamdConfSupport.EnsureConf(_databaseDir, excludePatterns);

                        var psi = new ProcessStartInfo
                        {
                            FileName = _clamdExe,
                            Arguments = $"--config-file={ClamdConfSupport.GetConfPath()}",
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            WorkingDirectory = Path.GetDirectoryName(_clamdExe) ?? Environment.CurrentDirectory,
                        };

                        _process = Process.Start(psi);
                        if (_process == null)
                            return false;
                    }
                    catch (Exception ex)
                    {
                        AppLogger.Warn("ClamdHost", "Démarrage clamd", ex);
                        return false;
                    }
                }
            }
            finally
            {
                StartGate.Release();
            }

            var deadline = DateTime.UtcNow + _startTimeout;
            while (DateTime.UtcNow < deadline && !ct.IsCancellationRequested)
            {
                await Task.Delay(400, ct).ConfigureAwait(false);
                if (await _ping(ct).ConfigureAwait(false))
                {
                    AppLogger.Info("ClamdHost", "clamd opérationnel (TCP 3310)");
                    return true;
                }
            }

            AppLogger.Warn("ClamdHost", "clamd n'a pas répondu à PING à temps");
            return false;
        }

        private static async Task<bool> DefaultPingAsync(CancellationToken ct)
        {
            try
            {
                using var client = new ClamdClient();
                return await client.PingAsync(ct).ConfigureAwait(false);
            }
            catch
            {
                return false;
            }
        }

        public void Stop()
        {
            lock (Gate)
                StopProcessLocked();
        }

        private void StopProcessLocked()
        {
            try
            {
                if (_process is { HasExited: false })
                {
                    _process.Kill(entireProcessTree: true);
                    _process.WaitForExit(3000);
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ClamdHost", "Arrêt clamd", ex);
            }
            finally
            {
                _process?.Dispose();
                _process = null;
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
        }

        internal static void ResetSharedForTests()
        {
            lock (Gate)
            {
                _shared?.Dispose();
                _shared = null;
            }
        }
    }
}
