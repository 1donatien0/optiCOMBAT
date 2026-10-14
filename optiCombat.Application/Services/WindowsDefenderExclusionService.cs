using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using optiCombat.Localization;

namespace optiCombat.Services
{
    /// <summary>
    /// Enregistre les chemins et processus optiCombat dans les exclusions Windows Defender
    /// pour éviter les blocages sur ClamAV, YARA, freshclam et les binaires de l'app.
    /// <para>
    /// <b>Opt-in uniquement</b> : jamais appelé automatiquement (installateur, démarrage).
    /// Un antivirus qui s'exclut silencieusement de Defender est un comportement de malware
    /// et échoue de toute façon quand la protection contre la falsification est active.
    /// Déclencheurs autorisés : Options → « Ajouter les exclusions Defender », argument
    /// <c>--defender-exclusions</c> (relance élevée), script <c>scripts/add-defender-exclusions.ps1</c>.
    /// </para>
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static class WindowsDefenderExclusionService
    {
        private static readonly string[] ProcessExclusions =
        {
            "optiCombat.exe",
            "optiCombat.Service.exe",
            "clamscan.exe",
            "freshclam.exe",
            "clamd.exe",
            "yara64.exe",
        };

        private static int _ensureInFlight;

        /// <summary>
        /// Action explicite de l'utilisateur (Options). Tente l'ajout ; si les droits manquent,
        /// propose une élévation UAC (relance <c>--defender-exclusions</c>).
        /// </summary>
        public static Task<DefenderExclusionOutcome> ApplyOnUserRequestAsync()
        {
            if (Interlocked.CompareExchange(ref _ensureInFlight, 1, 0) != 0)
                return Task.FromResult(DefenderExclusionOutcome.Busy);

            return Task.Run(() =>
            {
                try
                {
                    var result = EnsureOpticombatExclusions();
                    AppLogger.Info("DefenderExclusion", $"Demande utilisateur : {result.Status} ({result.AddedCount})");
                    return result.Status switch
                    {
                        DefenderExclusionStatus.Added => DefenderExclusionOutcome.Added,
                        DefenderExclusionStatus.AlreadyConfigured => DefenderExclusionOutcome.AlreadyConfigured,
                        DefenderExclusionStatus.NotApplicable or DefenderExclusionStatus.DefenderUnavailable
                            => DefenderExclusionOutcome.DefenderUnavailable,
                        _ when ElevationHelper.IsRunningElevated() => DefenderExclusionOutcome.Refused,
                        _ => ElevationHelper.RelaunchElevated(HeadlessScanArguments.DefenderExclusions, HeadlessScanArguments.Quiet)
                            ? DefenderExclusionOutcome.ElevationRequested
                            : DefenderExclusionOutcome.Refused,
                    };
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("DefenderExclusion", "ApplyOnUserRequestAsync", ex);
                    return DefenderExclusionOutcome.Refused;
                }
                finally
                {
                    Interlocked.Exchange(ref _ensureInFlight, 0);
                }
            });
        }

        /// <summary>Message utilisateur localisé pour un résultat de demande.</summary>
        public static string DescribeOutcome(DefenderExclusionOutcome outcome) => LocalizationService.GetString(outcome switch
        {
            DefenderExclusionOutcome.Added => "Def_Added",
            DefenderExclusionOutcome.AlreadyConfigured => "Def_AlreadyConfigured",
            DefenderExclusionOutcome.DefenderUnavailable => "Def_Unavailable",
            DefenderExclusionOutcome.ElevationRequested => "Def_ElevationRequested",
            DefenderExclusionOutcome.Busy => "Def_Busy",
            _ => "Def_Refused",
        });

        public static DefenderExclusionResult EnsureOpticombatExclusions()
        {
            if (!OperatingSystem.IsWindows())
                return DefenderExclusionResult.NotApplicable();

            if (!IsWindowsDefenderPresent())
                return DefenderExclusionResult.Unavailable("Windows Defender introuvable");

            var paths = CollectExclusionPaths();
            if (paths.Count == 0 && ProcessExclusions.Length == 0)
                return DefenderExclusionResult.AlreadyConfigured();

            var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
            {
                paths,
                processes = ProcessExclusions,
            })));

            const string script = """
                $ErrorActionPreference = 'Continue'
                $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__'))
                $data = $payload | ConvertFrom-Json
                try {
                    $status = Get-MpComputerStatus -ErrorAction Stop
                    if (-not $status.AMServiceEnabled) { Write-Output 'DEFENDER_DISABLED'; exit 2 }
                } catch {
                    Write-Output 'DEFENDER_UNAVAILABLE'
                    exit 2
                }
                try {
                    $pref = Get-MpPreference -ErrorAction Stop
                } catch {
                    Write-Output 'PREF_READ_FAILED'
                    exit 3
                }
                $pathExisting = @($pref.ExclusionPath)
                $procExisting = @($pref.ExclusionProcess)
                $added = 0
                $failures = @()
                foreach ($p in $data.paths) {
                    if (-not (Test-Path -LiteralPath $p)) { continue }
                    $norm = (Resolve-Path -LiteralPath $p).Path
                    $exists = $false
                    foreach ($e in $pathExisting) {
                        if ($e.Equals($norm, [System.StringComparison]::OrdinalIgnoreCase)) { $exists = $true; break }
                    }
                    if ($exists) { continue }
                    try {
                        Add-MpPreference -ExclusionPath $norm -ErrorAction Stop
                        $pathExisting += $norm
                        $added++
                    } catch {
                        $failures += "PATH:$norm"
                    }
                }
                foreach ($proc in $data.processes) {
                    $exists = $false
                    foreach ($e in $procExisting) {
                        if ($e.Equals([string]$proc, [System.StringComparison]::OrdinalIgnoreCase)) { $exists = $true; break }
                    }
                    if ($exists) { continue }
                    try {
                        Add-MpPreference -ExclusionProcess ([string]$proc) -ErrorAction Stop
                        $procExisting += [string]$proc
                        $added++
                    } catch {
                        $failures += "PROC:$proc"
                    }
                }
                if ($failures.Count -gt 0) {
                    Write-Output ('PARTIAL:' + ($failures -join ';') + ';ADDED=' + $added)
                    exit 4
                }
                Write-Output ('OK:' + $added)
                exit 0
                """;

            var run = RunPowerShell(script.Replace("__PAYLOAD__", payload, StringComparison.Ordinal));
            var result = ParseResult(run.ExitCode, run.Output);

            // Dossier exclu de Defender : le rendre inaccessible en écriture aux autres comptes locaux.
            if (result.Status is DefenderExclusionStatus.Added or DefenderExclusionStatus.AlreadyConfigured)
                DirectoryHardening.HardenDataDirectory(OpticombatProtectedPaths.GetLocalAppDataRoot());

            return result;
        }

        internal static IReadOnlyList<string> CollectExclusionPaths()
        {
            var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var root in OpticombatProtectedPaths.GetProtectedRoots())
            {
                if (string.IsNullOrWhiteSpace(root))
                    continue;
                try
                {
                    paths.Add(Path.GetFullPath(root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)));
                }
                catch
                {
                    /* chemin invalide */
                }
            }

            return paths.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
        }

        internal static bool IsWindowsDefenderPresent()
        {
            var mpcmd = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Windows Defender",
                "MpCmdRun.exe");
            return File.Exists(mpcmd);
        }

        private static DefenderExclusionResult ParseResult(int exitCode, string output)
        {
            var line = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .LastOrDefault() ?? string.Empty;

            if (exitCode == 0)
            {
                var added = 0;
                if (line.StartsWith("OK:", StringComparison.Ordinal))
                    int.TryParse(line.AsSpan(3), out added);
                return added > 0
                    ? DefenderExclusionResult.Added(added)
                    : DefenderExclusionResult.AlreadyConfigured();
            }

            if (exitCode == 2)
                return DefenderExclusionResult.Unavailable(line);

            if (exitCode == 3)
                return DefenderExclusionResult.AccessDenied();

            if (exitCode == 4 && line.StartsWith("PARTIAL:", StringComparison.Ordinal))
            {
                var added = 0;
                var idx = line.LastIndexOf("ADDED=", StringComparison.Ordinal);
                if (idx >= 0)
                    int.TryParse(line.AsSpan(idx + 6), out added);
                return DefenderExclusionResult.Partial(line, added);
            }

            return DefenderExclusionResult.Partial(line, 0);
        }

        private static (int ExitCode, string Output) RunPowerShell(string script)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-NonInteractive");
            psi.ArgumentList.Add("-ExecutionPolicy");
            psi.ArgumentList.Add("Bypass");
            psi.ArgumentList.Add("-Command");
            psi.ArgumentList.Add(script);

            using var proc = Process.Start(psi)
                ?? throw new InvalidOperationException("Impossible de lancer powershell.exe");

            var stdout = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit(60_000);

            var combined = string.IsNullOrWhiteSpace(stderr)
                ? stdout
                : stdout + Environment.NewLine + stderr;
            return (proc.ExitCode, combined.Trim());
        }

    }

    /// <summary>Résultat d'une demande explicite d'exclusions Defender.</summary>
    internal enum DefenderExclusionOutcome
    {
        Added,
        AlreadyConfigured,
        DefenderUnavailable,
        ElevationRequested,
        Refused,
        Busy,
    }

    internal enum DefenderExclusionStatus
    {
        NotApplicable,
        DefenderUnavailable,
        AlreadyConfigured,
        Added,
        PartialFailure,
        AccessDenied,
    }

    internal readonly struct DefenderExclusionResult
    {
        public DefenderExclusionStatus Status { get; }
        public int AddedCount { get; }
        public string Message { get; }

        private DefenderExclusionResult(DefenderExclusionStatus status, int addedCount, string message)
        {
            Status = status;
            AddedCount = addedCount;
            Message = message;
        }

        public static DefenderExclusionResult NotApplicable() =>
            new(DefenderExclusionStatus.NotApplicable, 0, string.Empty);

        public static DefenderExclusionResult Unavailable(string detail) =>
            new(DefenderExclusionStatus.DefenderUnavailable, 0, detail);

        public static DefenderExclusionResult AlreadyConfigured() =>
            new(DefenderExclusionStatus.AlreadyConfigured, 0, string.Empty);

        public static DefenderExclusionResult Added(int count) =>
            new(DefenderExclusionStatus.Added, count, string.Empty);

        public static DefenderExclusionResult AccessDenied() =>
            new(DefenderExclusionStatus.AccessDenied, 0, "Accès refusé");

        public static DefenderExclusionResult Partial(string detail, int added) =>
            new(DefenderExclusionStatus.PartialFailure, added, detail);
    }
}
