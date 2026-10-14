using optiCombat.Localization;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using System.Text;

namespace optiCombat.Services
{
    /// <summary>Une application dont une mise à jour est disponible via winget.</summary>
    public sealed class WingetPackageUpdate
    {
        public string Name { get; init; } = string.Empty;
        public string Id { get; init; } = string.Empty;
        public string InstalledVersion { get; init; } = string.Empty;
        public string AvailableVersion { get; init; } = string.Empty;
    }

    /// <summary>Issue d'une tentative de mise à niveau d'un paquet.</summary>
    public enum WingetUpgradeStatus
    {
        /// <summary>Mise à niveau appliquée avec succès.</summary>
        Succeeded,
        /// <summary>Rien à faire : winget considère le paquet déjà à jour.</summary>
        AlreadyUpToDate,
        /// <summary>Installée, mais un redémarrage est nécessaire pour finaliser.</summary>
        RebootRequired,
        /// <summary>Interrompue par l'utilisateur (UAC refusé, installateur annulé, Ctrl+C).</summary>
        CancelledByUser,
        /// <summary>Échec : le paquet reste à mettre à jour.</summary>
        Failed,
    }

    /// <summary>Résultat détaillé de la mise à niveau d'un paquet.</summary>
    public sealed class WingetUpgradeResult
    {
        public required WingetPackageUpdate Package { get; init; }
        public int ExitCode { get; init; }
        public WingetUpgradeStatus Status { get; init; }

        /// <summary>
        /// Vrai quand le paquet n'a plus lieu de figurer dans la liste des mises
        /// à jour disponibles (déjà appliquée, ou déjà à jour côté winget).
        /// </summary>
        public bool IsResolved =>
            Status is WingetUpgradeStatus.Succeeded or WingetUpgradeStatus.AlreadyUpToDate;
    }

    /// <summary>
    /// Mises à jour d'applications via winget (panneau Optimiser → Mises à jour).
    /// Port C# de l'utilitaire OptiWin (GUI/OptiWin-GUI.ps1) : localisation de
    /// winget.exe, parsing en colonnes de « winget upgrade », lancement des
    /// mises à niveau avec sortie streamée vers le journal de l'UI.
    /// Les mises à niveau demandent <c>--uninstall-previous</c> puis retirent
    /// les versions encore listées pour le même identifiant, afin d'éviter
    /// d'empiler v4, v5, v6… du même programme.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class WingetUpdateService
    {
        private string? _wingetPath;

        /// <summary>
        /// Localise winget.exe. Ordre : alias utilisateur (fonctionne sans
        /// élévation), PATH, puis dossier WindowsApps machine (lisible seulement
        /// en admin — dernier recours).
        /// </summary>
        public string? ResolveWingetPath()
        {
            if (!string.IsNullOrEmpty(_wingetPath) && File.Exists(_wingetPath))
                return _wingetPath;

            // 1. Alias per-user (%LOCALAPPDATA%\Microsoft\WindowsApps)
            var localAlias = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                @"Microsoft\WindowsApps\winget.exe");
            if (File.Exists(localAlias))
                return _wingetPath = localAlias;

            // 2. PATH
            var pathVar = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            foreach (var dir in pathVar.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    var candidate = Path.Combine(dir.Trim(), "winget.exe");
                    if (File.Exists(candidate))
                        return _wingetPath = candidate;
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("WingetUpdateService", $"Entrée PATH ignorée : {dir}", ex);
                }
            }

            // 3. WindowsApps machine (nécessite en pratique les droits admin)
            try
            {
                var windowsApps = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "WindowsApps");
                if (Directory.Exists(windowsApps))
                {
                    var candidate = Directory
                        .EnumerateDirectories(windowsApps, "Microsoft.DesktopAppInstaller_*_8wekyb3d8bbwe")
                        .OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase)
                        .Select(d => Path.Combine(d, "winget.exe"))
                        .FirstOrDefault(File.Exists);
                    if (candidate != null)
                        return _wingetPath = candidate;
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("WingetUpdateService", "Énumération WindowsApps impossible", ex);
            }

            return null;
        }

        /// <summary>
        /// Exécute « winget upgrade » et renvoie la liste des mises à jour
        /// disponibles. Renvoie une liste vide si winget est introuvable ou si
        /// la sortie n'est pas reconnue.
        /// </summary>
        public async Task<IReadOnlyList<WingetPackageUpdate>> GetAvailableUpdatesAsync(
            CancellationToken cancellationToken = default)
        {
            var winget = ResolveWingetPath();
            if (winget == null)
                return Array.Empty<WingetPackageUpdate>();

            var psi = new ProcessStartInfo
            {
                FileName = winget,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            psi.ArgumentList.Add("upgrade");
            psi.ArgumentList.Add("--include-unknown");
            psi.ArgumentList.Add("--accept-source-agreements");

            using var process = Process.Start(psi);
            if (process == null)
                return Array.Empty<WingetPackageUpdate>();

            // Lecture concurrente stdout/stderr pour éviter tout blocage de tampon.
            var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            var stdout = await stdoutTask.ConfigureAwait(false);
            _ = await stderrTask.ConfigureAwait(false);

            return ParseUpgradeOutput(stdout);
        }

        /// <summary>
        /// Parse la sortie en colonnes de « winget upgrade » (fr ou en).
        /// Les positions des colonnes sont déduites de la ligne d'en-tête
        /// (Nom/Name, Id, Version, Disponible/Available, Source).
        /// </summary>
        public static IReadOnlyList<WingetPackageUpdate> ParseUpgradeOutput(string output)
        {
            if (string.IsNullOrWhiteSpace(output))
                return Array.Empty<WingetPackageUpdate>();

            var lines = output
                .Replace("\r", string.Empty)
                .Split('\n');

            int headerIndex = -1;
            for (int i = 0; i < lines.Length; i++)
            {
                var l = lines[i];
                if ((l.StartsWith("Nom ", StringComparison.Ordinal) ||
                     l.StartsWith("Name ", StringComparison.Ordinal)) &&
                    l.Contains(" Id", StringComparison.Ordinal))
                {
                    headerIndex = i;
                    break;
                }
            }
            if (headerIndex < 0)
                return Array.Empty<WingetPackageUpdate>();

            var header = lines[headerIndex];
            int idxId = header.IndexOf("Id", StringComparison.Ordinal);
            int idxVersion = header.IndexOf("Version", StringComparison.Ordinal);
            int idxAvailable = header.IndexOf("Disponible", StringComparison.Ordinal);
            if (idxAvailable < 0)
                idxAvailable = header.IndexOf("Available", StringComparison.Ordinal);
            int idxSource = header.IndexOf("Source", StringComparison.Ordinal);
            if (idxSource < 0)
                idxSource = int.MaxValue;

            if (idxId <= 0 || idxVersion <= idxId || idxAvailable <= idxVersion)
                return Array.Empty<WingetPackageUpdate>();

            var result = new List<WingetPackageUpdate>();
            for (int i = headerIndex + 2; i < lines.Length; i++)
            {
                var l = lines[i];
                if (string.IsNullOrWhiteSpace(l))
                    break;
                // Ligne de bilan finale : « 12 mises à niveau disponibles. »
                if (char.IsDigit(l.TrimStart().FirstOrDefault()))
                    break;
                if (l.Length <= idxVersion)
                    continue;

                var id = SafeColumn(l, idxId, idxVersion);
                if (string.IsNullOrEmpty(id))
                    continue;

                result.Add(new WingetPackageUpdate
                {
                    Name = SafeColumn(l, 0, idxId),
                    Id = id,
                    InstalledVersion = SafeColumn(l, idxVersion, idxAvailable),
                    AvailableVersion = SafeColumn(l, idxAvailable, idxSource),
                });
            }
            return result;
        }

        private static string SafeColumn(string line, int start, int end)
        {
            if (start >= line.Length) return string.Empty;
            int realEnd = Math.Min(end, line.Length);
            return line[start..realEnd].Trim();
        }

        // ── Codes de sortie winget ───────────────────────────────────────────
        // Référence : https://github.com/microsoft/winget-cli/blob/master/doc/windows/package-manager/winget/returnCodes.md
        // Process.ExitCode est un int signé : les codes 0x8A15xxxx doivent être
        // convertis en unchecked pour être comparés correctement.
        // « Rien à faire » : le paquet est réellement à jour.
        private const int ErrUpdateNotApplicable = unchecked((int)0x8A15002B);      // No applicable update found
        private const int ErrUpgradeVersionNotNewer = unchecked((int)0x8A15004F);   // Upgrade version is not newer

        // Redémarrage impliqué (installation finalisée au reboot, ou à retenter après reboot).
        private const int ErrInstallRebootRequiredToFinish = unchecked((int)0x8A150109);
        private const int ErrInstallRebootRequiredForInstall = unchecked((int)0x8A15010A);
        private const int ErrInstallRebootInitiated = unchecked((int)0x8A15010B);
        private const int MsiRebootRequired = 3010;   // ERROR_SUCCESS_REBOOT_REQUIRED
        private const int MsiRebootInitiated = 1641;  // ERROR_SUCCESS_REBOOT_INITIATED

        // Interruption volontaire.
        private const int ErrInstallCancelledByUser = unchecked((int)0x8A15010C);
        private const int ErrCtrlSignalReceived = unchecked((int)0x8A150005);
        private const int ErrAppTerminationReceived = unchecked((int)0x8A15006A);
        private const int ErrAuthCancelledByUser = unchecked((int)0x8A150077);
        private const int ErrorCancelled = 1223;      // ERROR_CANCELLED (UAC refusé)
        private const int MsiUserExit = 1602;         // ERROR_INSTALL_USEREXIT

        // Ancien winget : --uninstall-previous n'existe pas encore.
        private const int ErrInvalidClArguments = unchecked((int)0x8A150010);

        /// <summary>
        /// Identifiants conçus pour cohabiter (runtimes). On n'y force pas la
        /// suppression des versions antérieures : d'autres programmes peuvent
        /// encore en dépendre.
        /// </summary>
        private static readonly string[] SideBySideIdPrefixes =
        {
            "Microsoft.VCRedist.",
            "Microsoft.DotNet.",
            "Microsoft.NET.",
            "Microsoft.DirectX",
        };

        /// <summary>
        /// Traduit un code de sortie winget en statut métier. Tout code inconnu
        /// est classé <see cref="WingetUpgradeStatus.Failed"/> : le paquet reste
        /// alors dans la liste, ce qui est le comportement prudent.
        /// <para>
        /// Attention aux faux amis : INSTALL_ALREADY_INSTALLED (0x8A15010D) et
        /// INSTALL_UPGRADE_NOT_SUPPORTED (0x8A150114) signifient que la mise à
        /// niveau n'a PAS eu lieu — ils restent donc des échecs.
        /// </para>
        /// </summary>
        public static WingetUpgradeStatus ClassifyExitCode(int exitCode) => exitCode switch
        {
            0 => WingetUpgradeStatus.Succeeded,

            // Rien à installer : winget considère le paquet à jour. Du point de
            // vue de l'utilisateur la ligne n'a plus lieu d'être affichée.
            ErrUpdateNotApplicable => WingetUpgradeStatus.AlreadyUpToDate,
            ErrUpgradeVersionNotNewer => WingetUpgradeStatus.AlreadyUpToDate,

            // Redémarrage impliqué : la ligne reste visible avec un marqueur,
            // car l'utilisateur a une action à faire avant de conclure.
            ErrInstallRebootRequiredToFinish => WingetUpgradeStatus.RebootRequired,
            ErrInstallRebootRequiredForInstall => WingetUpgradeStatus.RebootRequired,
            ErrInstallRebootInitiated => WingetUpgradeStatus.RebootRequired,
            MsiRebootRequired => WingetUpgradeStatus.RebootRequired,
            MsiRebootInitiated => WingetUpgradeStatus.RebootRequired,

            ErrInstallCancelledByUser => WingetUpgradeStatus.CancelledByUser,
            ErrCtrlSignalReceived => WingetUpgradeStatus.CancelledByUser,
            ErrAppTerminationReceived => WingetUpgradeStatus.CancelledByUser,
            ErrAuthCancelledByUser => WingetUpgradeStatus.CancelledByUser,
            ErrorCancelled => WingetUpgradeStatus.CancelledByUser,
            MsiUserExit => WingetUpgradeStatus.CancelledByUser,

            _ => WingetUpgradeStatus.Failed,
        };

        internal static bool AllowsPreviousVersionRemoval(string packageId)
        {
            if (string.IsNullOrWhiteSpace(packageId))
                return false;
            foreach (var prefix in SideBySideIdPrefixes)
            {
                if (packageId.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return false;
            }
            return true;
        }

        internal static bool IsUnknownVersion(string? version)
        {
            if (string.IsNullOrWhiteSpace(version))
                return true;
            var v = version.Trim();
            return v.Equals("Unknown", StringComparison.OrdinalIgnoreCase)
                || v.Equals("Inconnu", StringComparison.OrdinalIgnoreCase);
        }

        internal static IReadOnlyList<string> BuildUpgradePackageArguments(
            string packageId, bool uninstallPrevious)
        {
            var args = new List<string>
            {
                "upgrade", "--id", packageId, "--exact", "--include-unknown",
            };
            if (uninstallPrevious)
                args.Add("--uninstall-previous");
            args.Add("--accept-source-agreements");
            args.Add("--accept-package-agreements");
            return args;
        }

        internal static IReadOnlyList<string> BuildUpgradeAllArguments() =>
        [
            "upgrade", "--all", "--include-unknown",
            "--uninstall-previous",
            "--accept-source-agreements", "--accept-package-agreements",
        ];

        internal static IReadOnlyList<string> BuildListPackageArguments(string packageId) =>
        [
            "list", "--id", packageId, "--exact", "--accept-source-agreements",
        ];

        internal static IReadOnlyList<string> BuildUninstallVersionArguments(
            string packageId, string version) =>
        [
            "uninstall", "--id", packageId, "--version", version, "--exact",
            "--accept-source-agreements", "--disable-interactivity",
        ];

        /// <summary>
        /// Versions encore installées à retirer, seulement si la version à
        /// conserver est bien présente dans la liste. Sinon on ne touche à
        /// rien : la nouvelle version n'est peut-être pas encore enregistrée.
        /// </summary>
        internal static IReadOnlyList<string> SelectLeftoverVersions(
            IEnumerable<string> installedVersions,
            string versionToKeep)
        {
            if (IsUnknownVersion(versionToKeep))
                return Array.Empty<string>();

            var keep = versionToKeep.Trim();
            var installed = installedVersions
                .Select(v => v?.Trim() ?? string.Empty)
                .Where(v => v.Length > 0 && !IsUnknownVersion(v))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (!installed.Any(v => string.Equals(v, keep, StringComparison.OrdinalIgnoreCase)))
                return Array.Empty<string>();

            return installed
                .Where(v => !string.Equals(v, keep, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        /// <summary>
        /// Parse « winget list » (fr ou en) et renvoie les couples Id / Version.
        /// </summary>
        public static IReadOnlyList<(string Id, string Version)> ParseListOutput(string output)
        {
            if (string.IsNullOrWhiteSpace(output))
                return Array.Empty<(string, string)>();

            var lines = output
                .Replace("\r", string.Empty)
                .Split('\n');

            int headerIndex = -1;
            for (int i = 0; i < lines.Length; i++)
            {
                var l = lines[i];
                if ((l.StartsWith("Nom ", StringComparison.Ordinal) ||
                     l.StartsWith("Name ", StringComparison.Ordinal)) &&
                    l.Contains(" Id", StringComparison.Ordinal))
                {
                    headerIndex = i;
                    break;
                }
            }
            if (headerIndex < 0)
                return Array.Empty<(string, string)>();

            var header = lines[headerIndex];
            int idxId = header.IndexOf("Id", StringComparison.Ordinal);
            int idxVersion = header.IndexOf("Version", StringComparison.Ordinal);
            int idxAvailable = header.IndexOf("Disponible", StringComparison.Ordinal);
            if (idxAvailable < 0)
                idxAvailable = header.IndexOf("Available", StringComparison.Ordinal);
            int idxSource = header.IndexOf("Source", StringComparison.Ordinal);

            if (idxId <= 0 || idxVersion <= idxId)
                return Array.Empty<(string, string)>();

            int idxVersionEnd = int.MaxValue;
            if (idxAvailable > idxVersion)
                idxVersionEnd = idxAvailable;
            else if (idxSource > idxVersion)
                idxVersionEnd = idxSource;

            var result = new List<(string Id, string Version)>();
            for (int i = headerIndex + 2; i < lines.Length; i++)
            {
                var l = lines[i];
                if (string.IsNullOrWhiteSpace(l))
                    break;
                if (LooksLikeTableFooter(l))
                    break;
                if (l.Length <= idxVersion)
                    continue;

                var id = SafeColumn(l, idxId, idxVersion);
                if (string.IsNullOrEmpty(id))
                    continue;

                result.Add((id, SafeColumn(l, idxVersion, idxVersionEnd)));
            }
            return result;
        }

        private static bool LooksLikeTableFooter(string line)
        {
            var t = line.TrimStart();
            if (t.Length == 0)
                return true;
            if (!char.IsDigit(t[0]))
                return false;
            return t.Contains("disponible", StringComparison.OrdinalIgnoreCase)
                || t.Contains("available", StringComparison.OrdinalIgnoreCase)
                || t.Contains("installé", StringComparison.OrdinalIgnoreCase)
                || t.Contains("installed", StringComparison.OrdinalIgnoreCase)
                || t.Contains("package", StringComparison.OrdinalIgnoreCase)
                || t.Contains("paquet", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Met à niveau les paquets donnés (séquentiellement) en streamant la
        /// sortie vers <paramref name="onOutputLine"/>. Les installateurs
        /// déclenchent eux-mêmes l'invite UAC si nécessaire.
        /// <para>
        /// <paramref name="onPackageCompleted"/> est notifié après <b>chaque</b>
        /// paquet, ce qui permet à l'UI de retirer les lignes au fil de l'eau
        /// plutôt qu'à la fin du lot.
        /// </para>
        /// </summary>
        public async Task<IReadOnlyList<WingetUpgradeResult>> UpgradePackagesAsync(
            IEnumerable<WingetPackageUpdate> packages,
            Action<string> onOutputLine,
            IProgress<WingetUpgradeResult>? onPackageCompleted = null,
            CancellationToken cancellationToken = default)
        {
            var results = new List<WingetUpgradeResult>();

            var winget = ResolveWingetPath();
            if (winget == null)
                return results;

            foreach (var package in packages)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var uninstallPrevious = AllowsPreviousVersionRemoval(package.Id);
                var exitCode = await RunUpgradeAsync(
                    winget,
                    BuildUpgradePackageArguments(package.Id, uninstallPrevious),
                    onOutputLine,
                    cancellationToken).ConfigureAwait(false);

                var status = ClassifyExitCode(exitCode);
                if (status is WingetUpgradeStatus.Succeeded
                    or WingetUpgradeStatus.AlreadyUpToDate
                    or WingetUpgradeStatus.RebootRequired)
                {
                    await UninstallLeftoverVersionsAsync(
                        winget, package, onOutputLine, cancellationToken).ConfigureAwait(false);
                }

                var result = new WingetUpgradeResult
                {
                    Package = package,
                    ExitCode = exitCode,
                    Status = status,
                };
                results.Add(result);
                onPackageCompleted?.Report(result);
            }

            return results;
        }

        /// <summary>Met à niveau toutes les applications (« winget upgrade --all »).</summary>
        public async Task<int> UpgradeAllAsync(
            Action<string> onOutputLine,
            IEnumerable<WingetPackageUpdate>? packagesToClean = null,
            CancellationToken cancellationToken = default)
        {
            var winget = ResolveWingetPath();
            if (winget == null)
                return -1;

            var exitCode = await RunUpgradeAsync(
                winget,
                BuildUpgradeAllArguments(),
                onOutputLine,
                cancellationToken).ConfigureAwait(false);

            if (packagesToClean != null
                && ClassifyExitCode(exitCode) is not WingetUpgradeStatus.CancelledByUser)
            {
                foreach (var package in packagesToClean)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    await UninstallLeftoverVersionsAsync(
                        winget, package, onOutputLine, cancellationToken).ConfigureAwait(false);
                }
            }

            return exitCode;
        }

        /// <summary>
        /// Lance une mise à niveau. Si winget refuse <c>--uninstall-previous</c>
        /// (version trop ancienne), on retente sans ce drapeau.
        /// </summary>
        private static async Task<int> RunUpgradeAsync(
            string wingetPath,
            IReadOnlyList<string> arguments,
            Action<string> onOutputLine,
            CancellationToken cancellationToken)
        {
            var exitCode = await RunWingetStreamingAsync(
                wingetPath, arguments, onOutputLine, cancellationToken).ConfigureAwait(false);
            if (exitCode != ErrInvalidClArguments || !arguments.Contains("--uninstall-previous"))
                return exitCode;

            AppLogger.Warn(
                "WingetUpdateService",
                "winget ignore --uninstall-previous ; nouvel essai sans ce drapeau");
            var retry = arguments.Where(a => a != "--uninstall-previous").ToArray();
            return await RunWingetStreamingAsync(
                wingetPath, retry, onOutputLine, cancellationToken).ConfigureAwait(false);
        }

        private static async Task UninstallLeftoverVersionsAsync(
            string wingetPath,
            WingetPackageUpdate package,
            Action<string> onOutputLine,
            CancellationToken cancellationToken)
        {
            if (!AllowsPreviousVersionRemoval(package.Id))
                return;
            if (IsUnknownVersion(package.AvailableVersion))
                return;

            var installed = await GetInstalledVersionsAsync(
                wingetPath, package.Id, cancellationToken).ConfigureAwait(false);
            var leftovers = SelectLeftoverVersions(installed, package.AvailableVersion);
            foreach (var version in leftovers)
            {
                cancellationToken.ThrowIfCancellationRequested();
                onOutputLine(LocalizationService.Format(
                    "Upd_LogUninstallPrevious", package.Name, version));
                var exitCode = await RunWingetStreamingAsync(
                    wingetPath,
                    BuildUninstallVersionArguments(package.Id, version),
                    onOutputLine,
                    cancellationToken).ConfigureAwait(false);
                if (exitCode == 0)
                {
                    onOutputLine(LocalizationService.Format(
                        "Upd_LogUninstallPreviousDone", package.Name, version));
                }
                else
                {
                    AppLogger.Warn(
                        "WingetUpdateService",
                        $"Désinstallation {package.Id} {version} : code {exitCode}");
                    onOutputLine(LocalizationService.Format(
                        "Upd_LogUninstallPreviousFailed",
                        package.Name, version, $"0x{exitCode:X8}"));
                }
            }
        }

        private static async Task<IReadOnlyList<string>> GetInstalledVersionsAsync(
            string wingetPath,
            string packageId,
            CancellationToken cancellationToken)
        {
            var stdout = await RunWingetCaptureAsync(
                wingetPath,
                BuildListPackageArguments(packageId),
                cancellationToken).ConfigureAwait(false);
            return ParseListOutput(stdout)
                .Where(p => string.Equals(p.Id, packageId, StringComparison.OrdinalIgnoreCase))
                .Select(p => p.Version)
                .ToList();
        }

        private static async Task<string> RunWingetCaptureAsync(
            string wingetPath,
            IReadOnlyList<string> arguments,
            CancellationToken cancellationToken)
        {
            var psi = new ProcessStartInfo
            {
                FileName = wingetPath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            foreach (var a in arguments)
                psi.ArgumentList.Add(a);

            try
            {
                using var process = Process.Start(psi);
                if (process == null)
                    return string.Empty;

                var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
                var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                var stdout = await stdoutTask.ConfigureAwait(false);
                _ = await stderrTask.ConfigureAwait(false);
                return stdout;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("WingetUpdateService", "Lecture winget list", ex);
                return string.Empty;
            }
        }

        private static async Task<int> RunWingetStreamingAsync(
            string wingetPath,
            IReadOnlyList<string> arguments,
            Action<string> onOutputLine,
            CancellationToken cancellationToken)
        {
            var psi = new ProcessStartInfo
            {
                FileName = wingetPath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            foreach (var a in arguments)
                psi.ArgumentList.Add(a);

            using var process = new Process { StartInfo = psi };
            process.OutputDataReceived += (_, e) =>
            {
                if (!string.IsNullOrWhiteSpace(e.Data))
                    onOutputLine(e.Data.Trim());
            };
            process.ErrorDataReceived += (_, e) =>
            {
                if (!string.IsNullOrWhiteSpace(e.Data))
                    onOutputLine(e.Data.Trim());
            };

            try
            {
                if (!process.Start())
                    return -1;
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                return process.ExitCode;
            }
            catch (Exception ex)
            {
                AppLogger.Error("WingetUpdateService", "Exécution winget", ex);
                return -1;
            }
        }
    }
}
