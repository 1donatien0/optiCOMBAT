using optiCombat.Localization;
using optiCombat.Models;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace optiCombat.Services;

[SupportedOSPlatform("windows")]
public sealed record CleanSelection
{
    public bool TempWin { get; init; }
    public bool TempUser { get; init; }
    public bool Recycle { get; init; }
    public bool Logs { get; init; }
    public bool Edge { get; init; }
    public bool Chrome { get; init; }
    public bool Firefox { get; init; }
    public bool Brave { get; init; }
    public bool Opera { get; init; }
    public bool Vivaldi { get; init; }
    public bool Arc { get; init; }

    /// <summary>Cache de téléchargement Windows Update (SoftwareDistribution\Download) — nécessite l'élévation.</summary>
    public bool WUCache { get; init; }

    /// <summary>Vidage du cache DNS (ipconfig /flushdns).</summary>
    public bool Dns { get; init; }

    /// <summary>Historique de navigation des navigateurs Chromium (Edge, Chrome, Brave, Opera, Vivaldi, Arc).</summary>
    public bool History { get; init; }

    public bool AnySelected => TempWin || TempUser || Recycle || Logs || WUCache || Dns
        || Edge || Chrome || Firefox || Brave || Opera || Vivaldi || Arc;
}

public sealed record CleanAnalysisResult(
    long TempWinBytes,
    long TempUserBytes,
    long LogsBytes,
    long EdgeBytes,
    long ChromeBytes,
    long FirefoxBytes,
    long BraveBytes,
    long OperaBytes,
    long VivaldiBytes,
    long ArcBytes,
    long WuCacheBytes = 0,
    long HistoryBytes = 0)
{
    public long SystemTotal => TempWinBytes + TempUserBytes + LogsBytes + WuCacheBytes;
    public long BrowserTotal => EdgeBytes + ChromeBytes + FirefoxBytes + BraveBytes + OperaBytes + VivaldiBytes + ArcBytes + HistoryBytes;
    public long GrandTotal => SystemTotal + BrowserTotal;
}

public sealed record CleanExecutionResult(long BytesFreed, IReadOnlyList<string> LogLines);

[SupportedOSPlatform("windows")]
public static class SystemCleanService
{
    public static CleanAnalysisResult Analyze(CleanSelection sel)
    {
        return new CleanAnalysisResult(
            sel.TempWin ? MeasureDir(WindowsTempPath()) : 0,
            sel.TempUser ? MeasureDir(Path.GetTempPath()) : 0,
            sel.Logs ? MeasureDir(WindowsLogsPath()) : 0,
            sel.Edge ? MeasureDir(EdgeCachePath()) : 0,
            sel.Chrome ? MeasureDir(ChromeCachePath()) : 0,
            sel.Firefox ? MeasureDir(FirefoxCachePath()) : 0,
            sel.Brave ? MeasureDir(BraveCachePath()) : 0,
            sel.Opera ? MeasureDir(OperaCachePath()) : 0,
            sel.Vivaldi ? MeasureDir(VivaldiCachePath()) : 0,
            sel.Arc ? MeasureDir(ArcCachePath()) : 0,
            sel.WUCache ? MeasureDir(WindowsUpdateCachePath()) : 0,
            sel.History ? MeasureFiles(HistoryTargets(sel)) : 0);
    }

    public static CleanExecutionResult Execute(CleanSelection sel, Action<string>? log = null)
    {
        long freed = 0;
        var lines = new List<string>();

        void Log(string line)
        {
            lines.Add(line);
            log?.Invoke(line);
        }

        if (sel.TempWin)
        {
            long f = CleanDir(WindowsTempPath());
            freed += f;
            Log(LocalizationService.Format("Clean_LogFreedTempWin", ByteSizeFormat.Format(f)));
        }
        if (sel.TempUser)
        {
            long f = CleanDir(Path.GetTempPath());
            freed += f;
            Log(LocalizationService.Format("Clean_LogFreedTempUser", ByteSizeFormat.Format(f)));
        }
        if (sel.Recycle)
        {
            SHEmptyRecycleBin(IntPtr.Zero, null, 0x0007);
            Log(LocalizationService.GetString("Clean_LogRecycleEmptied"));
        }
        if (sel.Edge)
        {
            long f = CleanDir(EdgeCachePath());
            freed += f;
            Log(LocalizationService.Format("Clean_LogFreedCache", LocalizationService.GetString("Clean_Browser_Edge"), ByteSizeFormat.Format(f)));
        }
        if (sel.Chrome)
        {
            long f = CleanDir(ChromeCachePath());
            freed += f;
            Log(LocalizationService.Format("Clean_LogFreedCache", LocalizationService.GetString("Clean_Browser_Chrome"), ByteSizeFormat.Format(f)));
        }
        if (sel.Firefox)
        {
            long f = CleanDir(FirefoxCachePath());
            freed += f;
            Log(LocalizationService.Format("Clean_LogFreedCache", LocalizationService.GetString("Clean_Browser_Firefox"), ByteSizeFormat.Format(f)));
        }
        if (sel.Brave)
        {
            long f = CleanDir(BraveCachePath());
            freed += f;
            Log(LocalizationService.Format("Clean_LogFreedCache", LocalizationService.GetString("Clean_Browser_Brave"), ByteSizeFormat.Format(f)));
        }
        if (sel.Opera)
        {
            long f = CleanDir(OperaCachePath());
            freed += f;
            Log(LocalizationService.Format("Clean_LogFreedCache", LocalizationService.GetString("Clean_Browser_Opera"), ByteSizeFormat.Format(f)));
        }
        if (sel.Vivaldi)
        {
            long f = CleanDir(VivaldiCachePath());
            freed += f;
            Log(LocalizationService.Format("Clean_LogFreedCache", LocalizationService.GetString("Clean_Browser_Vivaldi"), ByteSizeFormat.Format(f)));
        }
        if (sel.Arc)
        {
            long f = CleanDir(ArcCachePath());
            freed += f;
            Log(LocalizationService.Format("Clean_LogFreedCache", LocalizationService.GetString("Clean_Browser_Arc"), ByteSizeFormat.Format(f)));
        }
        if (sel.Logs)
        {
            long f = CleanDir(WindowsLogsPath());
            freed += f;
            Log(LocalizationService.Format("Clean_LogFreedLogs", ByteSizeFormat.Format(f)));
        }
        if (sel.WUCache)
        {
            // Arrêt du service Windows Update nécessaire → script administrateur (une invite UAC).
            long before = MeasureDir(WindowsUpdateCachePath());
            var ok = SystemTweaksService.RunElevatedBatch(
                SystemTweaksService.ElevatedWindowsUpdateCacheCommands(), waitForExit: true);
            if (ok)
            {
                long f = Math.Max(0, before - MeasureDir(WindowsUpdateCachePath()));
                freed += f;
                Log(LocalizationService.Format("Clean_LogFreedWU", ByteSizeFormat.Format(f)));
            }
            else
            {
                Log(LocalizationService.GetString("Clean_LogWUDenied"));
            }
        }
        if (sel.Dns && SystemTweaksService.FlushDnsCache())
            Log(LocalizationService.GetString("Clean_LogDnsFlushed"));
        if (sel.History)
        {
            var (f, locked) = CleanFiles(HistoryTargets(sel));
            freed += f;
            Log(LocalizationService.Format("Clean_LogFreedHistory", ByteSizeFormat.Format(f)));
            if (locked > 0)
                Log(LocalizationService.Format("Clean_LogHistoryLocked", locked));
            if (sel.Firefox)
                Log(LocalizationService.GetString("Clean_LogHistoryFirefox"));
        }

        Log("─────────────────────────");
        Log(LocalizationService.Format("Clean_LogFreedTotal", ByteSizeFormat.Format(freed)));
        return new CleanExecutionResult(freed, lines);
    }

    public static string BuildTargetsSummary(CleanSelection sel)
    {
        var parts = new List<string>(12);
        if (sel.TempWin) parts.Add(LocalizationService.GetString("Clean_TempWinCb"));
        if (sel.TempUser) parts.Add(LocalizationService.GetString("Clean_TempUserCb"));
        if (sel.Recycle) parts.Add(LocalizationService.GetString("Clean_RecycleCb"));
        if (sel.Logs) parts.Add(LocalizationService.GetString("Clean_LogsCb"));
        if (sel.Edge) parts.Add(LocalizationService.GetString("Clean_Edge"));
        if (sel.Chrome) parts.Add(LocalizationService.GetString("Clean_Chrome"));
        if (sel.Firefox) parts.Add(LocalizationService.GetString("Clean_Firefox"));
        if (sel.Brave) parts.Add(LocalizationService.GetString("Clean_Brave"));
        if (sel.Opera) parts.Add(LocalizationService.GetString("Clean_Opera"));
        if (sel.Vivaldi) parts.Add(LocalizationService.GetString("Clean_Vivaldi"));
        if (sel.Arc) parts.Add(LocalizationService.GetString("Clean_Arc"));
        if (sel.WUCache) parts.Add(LocalizationService.GetString("Clean_WUCacheCb"));
        if (sel.Dns) parts.Add(LocalizationService.GetString("Clean_DnsCb"));
        if (sel.History) parts.Add(LocalizationService.GetString("Clean_HistoryCb"));
        return parts.Count == 0 ? "—" : string.Join(", ", parts);
    }

    private static string LocalApp => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static string WindowsTempPath() => Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "Temp");
    private static string WindowsLogsPath() => Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "Logs");
    private static string EdgeCachePath() => Path.Combine(LocalApp, @"Microsoft\Edge\User Data\Default\Cache");
    private static string ChromeCachePath() => Path.Combine(LocalApp, @"Google\Chrome\User Data\Default\Cache");
    private static string BraveCachePath() => Path.Combine(LocalApp, @"BraveSoftware\Brave-Browser\User Data\Default\Cache");
    private static string OperaCachePath() => Path.Combine(LocalApp, @"Opera Software\Opera Stable\Cache");
    private static string VivaldiCachePath() => Path.Combine(LocalApp, @"Vivaldi\User Data\Default\Cache");
    private static string ArcCachePath() => Path.Combine(LocalApp, @"Arc\User Data\Default\Cache");

    private static string WindowsUpdateCachePath() =>
        Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", @"SoftwareDistribution\Download");

    // Historique de navigation (Chromium uniquement) : fichiers « History » du dossier profil (parent du Cache).
    // Firefox est exclu : places.sqlite contient aussi les favoris.
    private static readonly string[] ChromiumHistoryFileNames = { "History", "History-journal", "Visited Links" };

    private static IEnumerable<string> ChromiumHistoryFiles(string cachePath)
    {
        var profileDir = string.IsNullOrEmpty(cachePath) ? null : Path.GetDirectoryName(cachePath);
        if (string.IsNullOrEmpty(profileDir))
            yield break;
        foreach (var name in ChromiumHistoryFileNames)
            yield return Path.Combine(profileDir, name);
    }

    private static List<string> HistoryTargets(CleanSelection sel)
    {
        var files = new List<string>();
        if (sel.Edge) files.AddRange(ChromiumHistoryFiles(EdgeCachePath()));
        if (sel.Chrome) files.AddRange(ChromiumHistoryFiles(ChromeCachePath()));
        if (sel.Brave) files.AddRange(ChromiumHistoryFiles(BraveCachePath()));
        if (sel.Opera) files.AddRange(ChromiumHistoryFiles(OperaCachePath()));
        if (sel.Vivaldi) files.AddRange(ChromiumHistoryFiles(VivaldiCachePath()));
        if (sel.Arc) files.AddRange(ChromiumHistoryFiles(ArcCachePath()));
        return files;
    }

    private static long MeasureFiles(IEnumerable<string> paths)
    {
        long total = 0;
        foreach (var p in paths)
        {
            try
            {
                if (File.Exists(p))
                    total += new FileInfo(p).Length;
            }
            catch (Exception ex) { AppLogger.Warn("SystemCleanService", $"Measure skip {p}", ex); }
        }
        return total;
    }

    /// <summary>Supprime les fichiers donnés. Renvoie (octets libérés, nombre de fichiers verrouillés).</summary>
    private static (long Freed, int Locked) CleanFiles(IEnumerable<string> paths)
    {
        long freed = 0;
        int locked = 0;
        foreach (var p in paths)
        {
            try
            {
                if (!File.Exists(p))
                    continue;
                long size = new FileInfo(p).Length;
                File.Delete(p);
                freed += size;
            }
            catch (Exception ex)
            {
                locked++;
                AppLogger.Warn("SystemCleanService", $"Delete skip {p}", ex);
            }
        }
        return (freed, locked);
    }

    private static string FirefoxCachePath()
    {
        var localProfilesBase = Path.Combine(LocalApp, @"Mozilla\Firefox\Profiles");
        if (!Directory.Exists(localProfilesBase))
            return string.Empty;

        var directories = Directory.EnumerateDirectories(localProfilesBase).ToList();
        var preferred = directories.FirstOrDefault(d => d.Contains(".default-release", StringComparison.OrdinalIgnoreCase))
            ?? directories.FirstOrDefault(d => d.Contains(".default", StringComparison.OrdinalIgnoreCase))
            ?? directories.FirstOrDefault();

        if (!string.IsNullOrEmpty(preferred))
        {
            var cache = Path.Combine(preferred, "cache2");
            if (Directory.Exists(cache))
                return cache;
        }

        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var profilesIni = Path.Combine(roaming, @"Mozilla\Firefox\profiles.ini");
        if (!File.Exists(profilesIni))
            return string.Empty;

        try
        {
            foreach (var line in File.ReadAllLines(profilesIni))
            {
                if (!line.StartsWith("Path=", StringComparison.OrdinalIgnoreCase))
                    continue;
                var relativeOrAbsolute = line["Path=".Length..].Trim();
                var profileName = Path.GetFileName(relativeOrAbsolute.TrimEnd('\\', '/'));
                if (string.IsNullOrEmpty(profileName))
                    continue;
                var localCandidate = Path.Combine(localProfilesBase, profileName, "cache2");
                if (Directory.Exists(localCandidate))
                    return localCandidate;
            }
        }
        catch (Exception ex)
        {
            AppLogger.Warn("SystemCleanService", "Firefox profiles.ini", ex);
        }

        return string.Empty;
    }

    private static long MeasureDir(string path)
    {
        if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            return 0;

        try
        {
            long total = 0;
            foreach (var f in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            {
                try { total += new FileInfo(f).Length; }
                catch (Exception ex) { AppLogger.Warn("SystemCleanService", $"Measure skip {f}", ex); }
            }
            return total;
        }
        catch (Exception ex)
        {
            AppLogger.Warn("SystemCleanService", $"Measure failed {path}", ex);
            return 0;
        }
    }

    private static long CleanDir(string path)
    {
        if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            return 0;

        long freed = 0;
        try
        {
            foreach (var f in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            {
                try
                {
                    long s = new FileInfo(f).Length;
                    File.Delete(f);
                    freed += s;
                }
                catch (Exception ex) { AppLogger.Warn("SystemCleanService", $"Delete skip {f}", ex); }
            }
        }
        catch (Exception ex)
        {
            AppLogger.Warn("SystemCleanService", $"Clean failed {path}", ex);
        }
        return freed;
    }

    [DllImport("Shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHEmptyRecycleBin(IntPtr hwnd, string? pszRootPath, uint dwFlags);
}
