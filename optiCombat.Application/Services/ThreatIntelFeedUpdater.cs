using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Text;
using optiCombat.Localization;

namespace optiCombat.Services;

/// <summary>Description d'un export abuse.ch téléchargé dans le dossier de threat intel.</summary>
/// <param name="Name">Nom affiché (MalwareBazaar, URLhaus, ThreatFox).</param>
/// <param name="Host">Hôte de l'API d'export (<c>*-api.abuse.ch</c>).</param>
/// <param name="RemoteFile">Fichier distant (<c>recent.csv</c>, <c>online.csv</c>, <c>full.csv.zip</c>).</param>
/// <param name="LocalFile">Nom attendu par le cœur Rust (<c>dispatcher::threat_intel</c>).</param>
/// <param name="MaxDataLines">Plafond de lignes de données conservées (les plus récentes en tête d'export).</param>
public sealed record ThreatIntelFeedSpec(string Name, string Host, string RemoteFile, string LocalFile, int MaxDataLines);

/// <summary>Bilan d'une mise à jour des feeds.</summary>
public sealed class ThreatIntelUpdateResult
{
    public bool Success { get; init; }

    /// <summary>Rien n'a été tenté (pas de clé, déjà à jour, mise à jour déjà en cours).</summary>
    public bool Skipped { get; init; }

    public string Message { get; init; } = string.Empty;

    public int FeedsUpdated { get; init; }

    public IReadOnlyList<string> Errors { get; init; } = Array.Empty<string>();
}

/// <summary>Erreur de téléchargement présentable à l'utilisateur (sans la clé).</summary>
public sealed class ThreatIntelDownloadException(string message) : Exception(message);

/// <summary>
/// Télécharge les exports abuse.ch (MalwareBazaar, URLhaus, ThreatFox) dans
/// <c>%LocalAppData%\optiCombat\threat_intel\</c>, où le cœur Rust les lit hors-ligne
/// (<c>opticombat_load_threat_intel</c>).
/// </summary>
/// <remarks>
/// Depuis le 30 juin 2025, abuse.ch exige une Auth-Key gratuite (portail d'authentification
/// abuse.ch), placée dans le chemin : <c>https://&lt;service&gt;-api.abuse.ch/v2/files/exports/&lt;clé&gt;/&lt;fichier&gt;</c>.
/// Sans clé valide, aucune requête n'est émise. La clé n'apparaît jamais dans les journaux.
/// Un export refusé, vide ou invalide laisse le fichier précédent en place.
/// </remarks>
public class ThreatIntelFeedUpdater : ISignatureAutoUpdateTarget
{
    /// <summary>Exports téléchargés. Les noms locaux sont ceux lus par le cœur Rust.</summary>
    public static readonly IReadOnlyList<ThreatIntelFeedSpec> Feeds = new[]
    {
        new ThreatIntelFeedSpec("MalwareBazaar", "mb-api.abuse.ch", "recent.csv", "malwarebazaar.csv", 500_000),
        new ThreatIntelFeedSpec("URLhaus", "urlhaus-api.abuse.ch", "online.csv", "urlhaus.csv", 1_000_000),
        new ThreatIntelFeedSpec("ThreatFox", "threatfox-api.abuse.ch", "full.csv.zip", "threatfox.csv", 300_000),
    };

    /// <summary>Taille maximale d'un téléchargement (compressé ou non).</summary>
    public const long MaxDownloadBytes = 256L * 1024 * 1024;

    /// <summary>Taille maximale d'un CSV écrit (alignée sur le plafond de lecture du cœur Rust).</summary>
    public const long MaxOutputChars = 512L * 1024 * 1024;

    /// <summary>Ligne plus longue : ignorée (aucune ligne légitime n'approche cette taille).</summary>
    public const int MaxLineChars = 64 * 1024;

    /// <summary>Intervalle minimal entre deux mises à jour non forcées.</summary>
    public static readonly TimeSpan MinInterval = TimeSpan.FromHours(6);

    /// <summary>Intervalle par défaut de la mise à jour automatique.</summary>
    public static readonly TimeSpan DefaultAutoInterval = TimeSpan.FromHours(12);

    private const string MetaFileName = ".opticombat-intel-meta.txt";

    private static readonly HttpClient SharedHttp = CreateSharedHttp();

    private readonly IUserPreferencesAccessor _prefs;
    private readonly HttpClient _http;
    private readonly Func<DateTime> _utcNow;
    private System.Threading.Timer? _autoTimer;
    private int _updating;

    public ThreatIntelFeedUpdater(IUserPreferencesAccessor preferences)
        : this(preferences, null, SharedHttp, () => DateTime.UtcNow)
    {
    }

    /// <summary>Constructeur de test : dossier, client HTTP et horloge injectés.</summary>
    internal ThreatIntelFeedUpdater(
        IUserPreferencesAccessor preferences, string? directory, HttpClient http, Func<DateTime> utcNow)
    {
        _prefs = preferences;
        _http = http;
        _utcNow = utcNow;
        FeedDirectory = directory ?? DefaultDirectory;
        LastUpdateUtc = LoadMeta(FeedDirectory);
    }

    /// <summary>Dossier lu par le cœur Rust.</summary>
    public static string DefaultDirectory => OpticombatDataRoots.LocalFile("threat_intel");

    /// <summary>Dossier où les exports sont écrits.</summary>
    public string FeedDirectory { get; }

    /// <summary>Dernière mise à jour réussie (au moins un export), en UTC.</summary>
    public DateTime? LastUpdateUtc { get; private set; }

    public bool IsUpdating => Volatile.Read(ref _updating) == 1;

    public bool IsAutoUpdateEnabled => _autoTimer != null;

    /// <summary>Une clé abuse.ch au format attendu est enregistrée.</summary>
    public bool HasValidAuthKey => IsValidAuthKey(_prefs.Current.AbuseChAuthKey);

    /// <summary>Déclenché après une mise à jour qui a remplacé au moins un export.</summary>
    public event EventHandler<ThreatIntelUpdateResult>? FeedsUpdated;

    /// <summary>
    /// Clé abuse.ch plausible : 16 à 128 caractères alphanumériques ASCII. Le contrôle empêche
    /// aussi toute injection de chemin dans l'URL (la clé est un segment de chemin).
    /// </summary>
    public static bool IsValidAuthKey(string? key)
    {
        if (string.IsNullOrWhiteSpace(key))
            return false;
        var k = key.Trim();
        return k.Length is >= 16 and <= 128 && k.All(char.IsAsciiLetterOrDigit);
    }

    internal static string BuildUrl(ThreatIntelFeedSpec spec, string key) =>
        $"https://{spec.Host}/v2/files/exports/{key}/{spec.RemoteFile}";

    internal static string Redact(string text, string key) =>
        string.IsNullOrEmpty(key) ? text : text.Replace(key, "***", StringComparison.Ordinal);

    /// <summary>
    /// Télécharge les trois exports. Sans clé valide, ou si la dernière mise à jour date de
    /// moins de <see cref="MinInterval"/> (sauf <paramref name="force"/>), ne fait rien.
    /// </summary>
    public async Task<ThreatIntelUpdateResult> UpdateAsync(bool force = false, CancellationToken ct = default)
    {
        if (Interlocked.Exchange(ref _updating, 1) == 1)
            return SkippedResult(LocalizationService.GetString("ThreatIntel_AlreadyRunning"));

        try
        {
            var key = _prefs.Current.AbuseChAuthKey?.Trim() ?? string.Empty;
            if (!IsValidAuthKey(key))
                return SkippedResult(LocalizationService.GetString("ThreatIntel_NoAuthKey"));

            if (!force && LastUpdateUtc is { } last && _utcNow() - last < MinInterval)
                return SkippedResult(LocalizationService.GetString("ThreatIntel_UpToDate"));

            Directory.CreateDirectory(FeedDirectory);
            var updated = 0;
            var errors = new List<string>();
            foreach (var spec in Feeds)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var lines = await DownloadFeedAsync(spec, key, ct).ConfigureAwait(false);
                    updated++;
                    AppLogger.Info("ThreatIntel", $"{spec.Name} : {lines} entrées");
                }
                catch (ThreatIntelDownloadException ex)
                {
                    errors.Add($"{spec.Name} : {ex.Message}");
                }
                catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException
                                           or UnauthorizedAccessException
                                           || (ex is TaskCanceledException && !ct.IsCancellationRequested))
                {
                    var msg = Redact(ex.Message, key);
                    errors.Add($"{spec.Name} : {msg}");
                    AppLogger.Warn("ThreatIntel", $"{spec.Name} : {msg}");
                }
            }

            if (updated > 0)
            {
                LastUpdateUtc = _utcNow();
                SaveMeta(FeedDirectory, LastUpdateUtc.Value);
            }

            var result = new ThreatIntelUpdateResult
            {
                Success = errors.Count == 0,
                FeedsUpdated = updated,
                Errors = errors,
                Message = errors.Count == 0
                    ? LocalizationService.Format("ThreatIntel_Updated", updated)
                    : string.Join(" ; ", errors),
            };
            if (updated > 0)
                FeedsUpdated?.Invoke(this, result);
            return result;
        }
        finally
        {
            Interlocked.Exchange(ref _updating, 0);
        }
    }

    private async Task<int> DownloadFeedAsync(ThreatIntelFeedSpec spec, string key, CancellationToken ct)
    {
        using var response = await _http
            .GetAsync(BuildUrl(spec, key), HttpCompletionOption.ResponseHeadersRead, ct)
            .ConfigureAwait(false);

        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new ThreatIntelDownloadException(LocalizationService.GetString("ThreatIntel_KeyRejected"));
        if (!response.IsSuccessStatusCode)
            throw new ThreatIntelDownloadException(
                string.Format(CultureInfo.InvariantCulture, "HTTP {0}", (int)response.StatusCode));
        if (response.Content.Headers.ContentLength is > MaxDownloadBytes)
            throw new ThreatIntelDownloadException(LocalizationService.GetString("ThreatIntel_TooLarge"));

        var final = Path.Combine(FeedDirectory, spec.LocalFile);
        var raw = final + ".download";
        var tmp = final + ".tmp";
        try
        {
            await using (var source = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
            await using (var target = new FileStream(raw, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                await CopyCappedAsync(source, target, MaxDownloadBytes, ct).ConfigureAwait(false);
            }

            int lines;
            if (IsZip(raw))
            {
                using var zip = ZipFile.OpenRead(raw);
                var entry = zip.Entries.FirstOrDefault(e => e.FullName.EndsWith(".csv", StringComparison.OrdinalIgnoreCase))
                            ?? throw new ThreatIntelDownloadException(LocalizationService.GetString("ThreatIntel_EmptyFeed"));
                using var csv = entry.Open();
                lines = CopyCsvLines(csv, tmp, spec.MaxDataLines, ct);
            }
            else
            {
                using var csv = File.OpenRead(raw);
                lines = CopyCsvLines(csv, tmp, spec.MaxDataLines, ct);
            }

            if (lines == 0)
                throw new ThreatIntelDownloadException(LocalizationService.GetString("ThreatIntel_EmptyFeed"));

            File.Move(tmp, final, overwrite: true);
            return lines;
        }
        finally
        {
            TryDelete(raw);
            TryDelete(tmp);
        }
    }

    /// <summary>Copie au plus <paramref name="maxBytes"/> octets ; au-delà, l'export est refusé.</summary>
    internal static async Task CopyCappedAsync(Stream source, Stream target, long maxBytes, CancellationToken ct)
    {
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false)) > 0)
        {
            total += read;
            if (total > maxBytes)
                throw new ThreatIntelDownloadException(LocalizationService.GetString("ThreatIntel_TooLarge"));
            await target.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Recopie un CSV ligne par ligne : commentaires conservés, lignes trop longues ignorées,
    /// au plus <paramref name="maxDataLines"/> lignes de données. Renvoie le nombre de lignes de
    /// données (une ligne de données contient au moins une virgule) ; 0 signale une réponse qui
    /// n'est pas un export (page HTML, message d'erreur).
    /// </summary>
    internal static int CopyCsvLines(Stream source, string targetPath, int maxDataLines, CancellationToken ct = default)
    {
        var dataLines = 0;
        long written = 0;
        using var reader = new StreamReader(source, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        using var writer = new StreamWriter(targetPath, append: false, new UTF8Encoding(false));
        var line = new StringBuilder();
        var overlong = false;

        bool Flush()
        {
            if (overlong)
            {
                overlong = false;
                line.Clear();
                return true;
            }
            var text = line.ToString().TrimEnd('\r');
            line.Clear();
            var trimmed = text.TrimStart();
            if (trimmed.Length == 0)
                return true;
            var isComment = trimmed[0] == '#';
            if (!isComment)
            {
                if (trimmed[0] == '<' || !trimmed.Contains(','))
                    return true; // HTML ou texte libre : pas une ligne d'export
                if (dataLines >= maxDataLines)
                    return false;
                dataLines++;
            }
            written += text.Length + 1;
            if (written > MaxOutputChars)
                return false;
            writer.Write(text);
            writer.Write('\n');
            return true;
        }

        var buffer = new char[16384];
        int n;
        while ((n = reader.Read(buffer, 0, buffer.Length)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            for (var i = 0; i < n; i++)
            {
                var c = buffer[i];
                if (c == '\n')
                {
                    if (!Flush())
                        return dataLines;
                    continue;
                }
                if (overlong)
                    continue;
                if (line.Length >= MaxLineChars)
                {
                    overlong = true;
                    line.Clear();
                    continue;
                }
                line.Append(c);
            }
        }
        Flush();
        return dataLines;
    }

    private static bool IsZip(string path)
    {
        Span<byte> magic = stackalloc byte[4];
        using var fs = File.OpenRead(path);
        return fs.Read(magic) == 4 && magic[0] == (byte)'P' && magic[1] == (byte)'K' && magic[2] == 3 && magic[3] == 4;
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static DateTime? LoadMeta(string dir)
    {
        try
        {
            var path = Path.Combine(dir, MetaFileName);
            if (!File.Exists(path))
                return null;
            return DateTime.TryParse(File.ReadAllText(path).Trim(), CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var when)
                ? when
                : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static void SaveMeta(string dir, DateTime when)
    {
        try
        {
            File.WriteAllText(Path.Combine(dir, MetaFileName), when.ToString("O", CultureInfo.InvariantCulture));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            AppLogger.Warn("ThreatIntel", "Écriture de la date de mise à jour", ex);
        }
    }

    private static ThreatIntelUpdateResult SkippedResult(string message) =>
        new() { Success = true, Skipped = true, Message = message };

    private static HttpClient CreateSharedHttp()
    {
        var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd(ProductVersionInfo.HttpUserAgent);
        return http;
    }

    // ── Mise à jour automatique ───────────────────────────────────────────────

    /// <summary>Planifie une mise à jour périodique (sans effet tant qu'aucune clé n'est saisie).</summary>
    public void EnableAutoUpdate(TimeSpan? interval = null)
    {
        var period = interval ?? DefaultAutoInterval;
        _autoTimer?.Dispose();
        _autoTimer = new System.Threading.Timer(_ => _ = RunScheduledAsync(), null, period, period);
    }

    public void DisableAutoUpdate()
    {
        _autoTimer?.Dispose();
        _autoTimer = null;
    }

    /// <summary>Exécution planifiée : n'échoue jamais (journalise).</summary>
    internal async Task RunScheduledAsync()
    {
        try
        {
            var result = await UpdateAsync().ConfigureAwait(false);
            if (!result.Skipped && !result.Success)
                AppLogger.Warn("ThreatIntel", result.Message);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            AppLogger.Warn("ThreatIntel", "Mise à jour automatique", ex);
        }
    }
}
