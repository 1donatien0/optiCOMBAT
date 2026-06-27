using System.Collections.Concurrent;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using optiCombat.Localization;

namespace optiCombat.Services
{
    /// <summary>Consultation VirusTotal v3 (hash SHA-256) — clé API utilisateur.</summary>
    public sealed class ThreatReputationService : IThreatReputationService
    {
        private static readonly HttpClient DefaultHttp = new()
        {
            Timeout = TimeSpan.FromSeconds(25),
        };

        private static readonly ConcurrentDictionary<string, (ReputationResult Result, DateTime ExpiresUtc)> Cache = new();
        private static readonly TimeSpan CacheTtl = TimeSpan.FromHours(6);

        private readonly HttpClient _http;
        private readonly IUserPreferencesAccessor _prefs;

        public ThreatReputationService(
            HttpClient? http = null,
            IUserPreferencesAccessor? preferences = null)
        {
            _http = http ?? DefaultHttp;
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
        }

        public sealed class ReputationResult
        {
            public bool Success { get; init; }
            public string Summary { get; init; } = string.Empty;
            public string? Permalink { get; init; }
            public bool IsError { get; init; }
        }

        public async Task<ReputationResult> LookupFileAsync(string filePath, CancellationToken ct = default)
        {
            var apiKey = _prefs.Current.VirusTotalApiKey?.Trim();
            if (string.IsNullOrEmpty(apiKey))
            {
                return new ReputationResult
                {
                    Success = false,
                    IsError = true,
                    Summary = LocalizationService.GetString("VT_NoApiKey"),
                };
            }

            var hash = await FileContentHash.TryComputeSha256HexAsync(filePath, ct).ConfigureAwait(false);
            if (string.IsNullOrEmpty(hash))
            {
                return new ReputationResult
                {
                    Success = false,
                    IsError = true,
                    Summary = LocalizationService.GetString("VT_HashFailed"),
                };
            }

            if (Cache.TryGetValue(hash, out var cached) && cached.ExpiresUtc > DateTime.UtcNow)
                return cached.Result;

            try
            {
                using var req = new HttpRequestMessage(
                    HttpMethod.Get,
                    $"https://www.virustotal.com/api/v3/files/{hash}");
                req.Headers.Add("x-apikey", apiKey);
                req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
                var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

                if (!resp.IsSuccessStatusCode)
                {
                    return new ReputationResult
                    {
                        Success = false,
                        IsError = true,
                        Summary = LocalizationService.Format("VT_HttpError", ((int)resp.StatusCode).ToString()),
                    };
                }

                var result = ParseFileLookupJson(body, hash);
                Cache[hash] = (result, DateTime.UtcNow.Add(CacheTtl));
                return result;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ThreatReputation", "Lookup", ex);
                return new ReputationResult
                {
                    Success = false,
                    IsError = true,
                    Summary = LocalizationService.Format("VT_Error", ex.Message),
                };
            }
        }

        internal static ReputationResult ParseFileLookupJson(string json, string? sha256Hex = null)
        {
            using var doc = JsonDocument.Parse(json);
            var stats = doc.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("last_analysis_stats");
            int mal = stats.GetProperty("malicious").GetInt32();
            int sus = stats.GetProperty("suspicious").GetInt32();
            int harm = stats.GetProperty("harmless").GetInt32();
            int und = stats.GetProperty("undetected").GetInt32();

            string? link = !string.IsNullOrEmpty(sha256Hex)
                ? $"https://www.virustotal.com/gui/file/{sha256Hex}"
                : null;
            if (link == null
                && doc.RootElement.GetProperty("data").TryGetProperty("links", out var links)
                && links.TryGetProperty("self", out var self))
            {
                var selfUrl = self.GetString();
                if (!string.IsNullOrEmpty(selfUrl)
                    && selfUrl.Contains("/gui/file/", StringComparison.OrdinalIgnoreCase))
                    link = selfUrl;
            }

            var summary = LocalizationService.Format(
                "VT_Summary",
                mal.ToString(),
                sus.ToString(),
                harm.ToString(),
                und.ToString());

            return new ReputationResult
            {
                Success = true,
                Summary = summary,
                Permalink = link,
            };
        }

        internal static void ResetCacheForTests() => Cache.Clear();
    }
}

