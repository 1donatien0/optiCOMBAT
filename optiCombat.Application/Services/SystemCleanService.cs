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

    public bool AnySelected => TempWin || TempUser || Recycle || Logs
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
    long ArcBytes)
{
    public long SystemTotal => TempWinBytes + TempUserBytes + LogsBytes;
    public long BrowserTotal => EdgeBytes + ChromeBytes + FirefoxBytes + BraveBytes + OperaBytes + VivaldiBytes + ArcBytes;
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
            sel.Arc ? MeasureDir(ArcCachePath()) : 0);
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
