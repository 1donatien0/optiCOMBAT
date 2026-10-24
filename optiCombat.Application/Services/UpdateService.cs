using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using optiCombat.Localization;
using optiCombat.Strings;

namespace optiCombat.Services
{
    /// <summary>État du contrôle de mise à jour du binaire optiCombat (pas des signatures).</summary>
    public enum AppUpdateChannelStatus
    {
        /// <summary>Aucune release publiée sur le canal (ou dépôt inaccessible publiquement).</summary>
        NotConfigured,

        /// <summary>Erreur d'accès au dossier local de préparation.</summary>
        StagingError,

        /// <summary>La version installée est la plus récente publiée.</summary>
        UpToDate,

        /// <summary>Une version plus récente est publiée (voir <see cref="AppUpdateCheckResult.ReleaseUrl"/>).</summary>
        UpdateAvailable,

        /// <summary>Le canal n'a pas pu être interrogé (réseau, quota GitHub, réponse invalide).</summary>
        CheckFailed,
    }

    /// <summary>Résultat explicite — évite les MessageBox codés en dur dans l'UI.</summary>
    public sealed class AppUpdateCheckResult
    {
        public AppUpdateChannelStatus Status { get; init; }
        public string CurrentVersion { get; init; } = string.Empty;
        public string ReleaseLabel { get; init; } = string.Empty;
        public string StagingDirectory { get; init; } = string.Empty;
        public string UserMessage { get; init; } = string.Empty;

        /// <summary>Version publiée la plus récente (vide si inconnue).</summary>
        public string LatestVersion { get; init; } = string.Empty;

        /// <summary>Page de la release à télécharger (vide si inconnue).</summary>
        public string ReleaseUrl { get; init; } = string.Empty;

        public bool Success => Status is AppUpdateChannelStatus.NotConfigured
            or AppUpdateChannelStatus.UpToDate
            or AppUpdateChannelStatus.UpdateAvailable;
    }

    /// <summary>
    /// Vérifie si une nouvelle version du binaire optiCombat est publiée (dernière release
    /// GitHub du dépôt). Les signatures sont gérées par <see cref="FreshclamUpdater"/> et
    /// <see cref="YaraForgeUpdater"/>.
    /// </summary>
    /// <remarks>
    /// Volontairement, rien n'est téléchargé ni installé : l'utilisateur est dirigé vers la page
    /// de la release (installateur signé). Une release absente, un dépôt privé ou une erreur réseau
    /// ramènent au message d'origine (téléchargement manuel).
    /// </remarks>
    public class UpdateService
    {
        private static readonly HttpClient SharedHttp = CreateSharedHttp();
        private static readonly System.Buffers.SearchValues<char> VersionSuffixStart =
            System.Buffers.SearchValues.Create("-+ ");

        private readonly HttpClient _http;
        private readonly string _localUpdatePath;

        public UpdateService()
            : this(SharedHttp, null)
        {
        }

        /// <summary>Constructeur de test : client HTTP et dossier de staging injectés.</summary>
        internal UpdateService(HttpClient http, string? stagingDirectory)
        {
            _http = http;
            _localUpdatePath = stagingDirectory ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "optiCombat", "Updates");
        }

        /// <summary>Dernière release publiée (API GitHub).</summary>
        public static string LatestReleaseApiUrl => OpticombatStrings.Urls.OpticombatReleasesApiLatest;

        /// <summary>Prépare le dossier de staging puis interroge le canal de releases.</summary>
        public async Task<AppUpdateCheckResult> CheckForUpdatesAsync(CancellationToken ct = default)
        {
            var version = ProductVersionInfo.SemVer;
            var release = ProductVersionInfo.ReleaseLabel;

            try
            {
                if (!Directory.Exists(_localUpdatePath))
                    Directory.CreateDirectory(_localUpdatePath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException
                                       or NotSupportedException)
            {
                AppLogger.Error("UpdateService", "Préparation dossier mises à jour", ex);
                return new AppUpdateCheckResult
                {
                    Status = AppUpdateChannelStatus.StagingError,
                    CurrentVersion = version,
                    ReleaseLabel = release,
                    StagingDirectory = _localUpdatePath,
                    UserMessage = LocalizationService.Format(
                        "Upd_StagingError", release, version, ex.Message, OpticombatStrings.Urls.OpticombatSourceForge),
                };
            }

            LatestRelease? latest;
            try
            {
                latest = await FetchLatestAsync(ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is HttpRequestException or JsonException
                                       || (ex is TaskCanceledException && !ct.IsCancellationRequested))
            {
                AppLogger.Warn("UpdateService", $"Canal de releases injoignable : {ex.Message}");
                return new AppUpdateCheckResult
                {
                    Status = AppUpdateChannelStatus.CheckFailed,
                    CurrentVersion = version,
                    ReleaseLabel = release,
                    StagingDirectory = _localUpdatePath,
                    UserMessage = LocalizationService.Format(
                        "Upd_CheckFailed", release, version, ex.Message, OpticombatStrings.Urls.OpticombatSourceForge),
                };
            }

            if (latest is null)
            {
                AppLogger.Info("UpdateService", $"Aucune release publiée — version locale {release} ({version})");
                return new AppUpdateCheckResult
                {
                    Status = AppUpdateChannelStatus.NotConfigured,
                    CurrentVersion = version,
                    ReleaseLabel = release,
                    StagingDirectory = _localUpdatePath,
                    UserMessage = LocalizationService.Format(
                        "Upd_NotConfigured", release, version, OpticombatStrings.Urls.OpticombatSourceForge, _localUpdatePath),
                };
            }

            var newer = IsNewer(latest.Version, version);
            return new AppUpdateCheckResult
            {
                Status = newer ? AppUpdateChannelStatus.UpdateAvailable : AppUpdateChannelStatus.UpToDate,
                CurrentVersion = version,
                ReleaseLabel = release,
                StagingDirectory = _localUpdatePath,
                LatestVersion = latest.Version,
                ReleaseUrl = latest.Url,
                UserMessage = newer
                    ? LocalizationService.Format("Upd_Available", release, version, latest.Version, latest.Url)
                    : LocalizationService.Format("Upd_UpToDate", release, version),
            };
        }

        internal sealed record LatestRelease(string Version, string Url);

        /// <summary>
        /// Dernière release non brouillon et non préliminaire, ou <c>null</c> si aucune n'est publiée
        /// (HTTP 404 : pas de release, ou dépôt non public).
        /// </summary>
        internal async Task<LatestRelease?> FetchLatestAsync(CancellationToken ct)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, LatestReleaseApiUrl);
            request.Headers.Accept.ParseAdd("application/vnd.github+json");
            using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.NotFound)
                return null;
            if (!response.IsSuccessStatusCode)
                throw new HttpRequestException(
                    string.Format(CultureInfo.InvariantCulture, "HTTP {0}", (int)response.StatusCode));

            var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return ParseRelease(json);
        }

        /// <summary>Extrait la version (tag sans « v ») et la page d'une release GitHub.</summary>
        internal static LatestRelease? ParseRelease(string json)
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                throw new JsonException("Réponse de release inattendue");
            if (IsTrue(root, "draft") || IsTrue(root, "prerelease"))
                return null;
            var tag = root.TryGetProperty("tag_name", out var t) && t.ValueKind == JsonValueKind.String
                ? t.GetString()
                : null;
            if (string.IsNullOrWhiteSpace(tag))
                return null;
            var url = root.TryGetProperty("html_url", out var u) && u.ValueKind == JsonValueKind.String
                ? u.GetString() ?? string.Empty
                : string.Empty;
            // Seule une page github.com est proposée à l'utilisateur.
            if (!url.StartsWith("https://github.com/", StringComparison.OrdinalIgnoreCase))
                url = OpticombatStrings.Urls.OpticombatReleasesPage;
            return new LatestRelease(NormalizeTag(tag), url);
        }

        private static bool IsTrue(JsonElement e, string name) =>
            e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

        internal static string NormalizeTag(string tag)
        {
            var t = tag.Trim();
            return t.StartsWith('v') || t.StartsWith('V') ? t[1..] : t;
        }

        /// <summary>
        /// <c>true</c> si <paramref name="latest"/> est strictement plus récente que
        /// <paramref name="current"/> (comparaison numérique, suffixes « -rc » / « +build » ignorés).
        /// Une version illisible n'est jamais considérée comme plus récente.
        /// </summary>
        internal static bool IsNewer(string latest, string current) =>
            TryParseVersion(latest, out var l) && TryParseVersion(current, out var c) && l > c;

        internal static bool TryParseVersion(string text, out Version version)
        {
            var core = NormalizeTag(text ?? string.Empty);
            var cut = core.AsSpan().IndexOfAny(VersionSuffixStart);
            if (cut >= 0)
                core = core[..cut];
            if (!core.Contains('.'))
                core += ".0";
            if (Version.TryParse(core, out var parsed))
            {
                version = new Version(parsed.Major, parsed.Minor, Math.Max(parsed.Build, 0), Math.Max(parsed.Revision, 0));
                return true;
            }
            version = new Version(0, 0);
            return false;
        }

        private static HttpClient CreateSharedHttp()
        {
            var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd(ProductVersionInfo.HttpUserAgent);
            return http;
        }
    }
}
