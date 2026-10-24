using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;
using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests.TestSupport;

/// <summary>
/// <see cref="ServiceContainer"/> complet mais isolé : préférences, exclusions, journaux et
/// quarantaine dans un dossier temporaire, moteurs ClamAV / YARA factices.
/// Aucun test qui l'utilise n'écrit dans le %APPDATA% réel du poste.
/// À n'utiliser que dans la collection <c>OpticombatPrefs</c> (non parallélisée).
/// </summary>
internal sealed class IsolatedServices : IDisposable
{
    public IsolatedServices(ScriptedClamBackend? clam = null, FakeHttpHandler? http = null)
    {
        Root = Path.Combine(Path.GetTempPath(), "opticombat_iso_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Root);
        OpticombatDataRoots.TestRootOverride = Root;
        LocalizationService.ApplyCulture("fr-FR");

        Prefs = new UserPreferences
        {
            UsePlatformProtectionService = false,
            ActionNotificationsEnabled = false,
            SignatureAutoUpdateEnabled = false,
            UiCulture = "fr-FR",
        };
        Exclusions = new ExclusionSettings { RealTimeEnabled = false, AutoQuarantineEnabled = false };
        PrefsAccessor = new FixedPreferencesAccessor(Prefs);
        ExclusionsAccessor = new FixedExclusionsAccessor(Exclusions);
        Clam = clam ?? new ScriptedClamBackend();
        Http = http ?? new FakeHttpHandler();
        // schtasks factice : aucune tâche planifiée réelle n'est créée par les tests.
        Schtasks = FakeTools.Install(Path.Combine(Root, "tools"), "schtasks.exe");

        Container = new ServiceContainer(services =>
        {
            services.AddSingleton<IUserPreferencesAccessor>(PrefsAccessor);
            services.AddSingleton<IExclusionSettingsAccessor>(ExclusionsAccessor);
            services.AddSingleton(new ScanLogManager(Path.Combine(Root, "logs")));
            services.AddSingleton(sp =>
                new ActivityLogService(sp.GetRequiredService<ScanLogManager>(), Path.Combine(Root, "logs")));
            services.AddSingleton(_ => new QuarantineManager(Path.Combine(Root, "quarantine"), PrefsAccessor));
            services.AddSingleton(_ =>
                new ScanOrchestrator(Clam, new NoopYaraBackend(), PrefsAccessor, ExclusionsAccessor, optiCombat: null));
            // Signatures : aucun freshclam.exe ni accès réseau réel.
            services.AddSingleton(_ => new FreshclamUpdater(Path.Combine(Root, "clamav")));
            services.AddSingleton(_ => new YaraForgeUpdater(Path.Combine(Root, "rules"), new HttpClient(Http)));
            // Threat intel abuse.ch : même faux serveur HTTP, dossier isolé.
            services.AddSingleton(_ => new ThreatIntelFeedUpdater(
                PrefsAccessor, Path.Combine(Root, "local", "threat_intel"), new HttpClient(Http), () => DateTime.UtcNow));
            services.AddSingleton(_ => new UpdateService(new HttpClient(Http), Path.Combine(Root, "updates")));
            services.AddSingleton(_ => new ScheduledScanService(Schtasks, Path.Combine(Root, "optiCombat.exe")));
            services.AddSingleton(_ => new ThreatReputationService(new HttpClient(Http), PrefsAccessor));
            services.AddSingleton(_ => new TamperProtectionService(PrefsAccessor, ExclusionsAccessor) { SchtasksPath = Schtasks });
        });
    }

    public string Root { get; }

    public UserPreferences Prefs { get; }

    public ExclusionSettings Exclusions { get; }

    public FixedPreferencesAccessor PrefsAccessor { get; }

    public FixedExclusionsAccessor ExclusionsAccessor { get; }

    public ScriptedClamBackend Clam { get; }

    public FakeHttpHandler Http { get; }

    /// <summary>Chemin du schtasks factice (scénario et appels via <see cref="FakeTools"/>).</summary>
    public string Schtasks { get; }

    public ServiceContainer Container { get; }

    /// <summary>Crée un fichier « suspect » dans le dossier isolé.</summary>
    public string CreateFile(string name, string content = "X5O!P%@AP-fake-sample")
    {
        var dir = Path.Combine(Root, "samples");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, name);
        File.WriteAllText(path, content);
        return path;
    }

    public void Dispose()
    {
        try { Container.Shutdown(); }
        catch { /* best effort */ }

        OpticombatDataRoots.TestRootOverride = TestDataRoot.Session;
        var production = new DefaultUserPreferencesAccessor();
        LocalizationService.ConfigurePreferencesAccessor(production);
        DistractionFreeMonitor.Initialize(production);
        PlatformProtectionBootstrap.Initialize(production);

        try { Directory.Delete(Root, recursive: true); }
        catch { /* fichiers encore ouverts : nettoyés par le système */ }
    }
}

/// <summary>Faux serveur HTTP : réponses par URL, 503 par défaut (jamais de réseau réel).</summary>
internal sealed class FakeHttpHandler : HttpMessageHandler
{
    public Dictionary<string, Func<HttpResponseMessage>> Routes { get; } = new(StringComparer.OrdinalIgnoreCase);

    public List<string> Requests { get; } = new();

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var url = request.RequestUri!.ToString();
        lock (Requests)
            Requests.Add(url);
        return Task.FromResult(Routes.TryGetValue(url, out var route)
            ? route()
            : new HttpResponseMessage(System.Net.HttpStatusCode.ServiceUnavailable));
    }
}

internal sealed class FixedPreferencesAccessor(UserPreferences prefs) : IUserPreferencesAccessor
{
    public UserPreferences Current { get; } = prefs;
}

internal sealed class FixedExclusionsAccessor(ExclusionSettings settings) : IExclusionSettingsAccessor
{
    public ExclusionSettings Current { get; } = settings;
}

/// <summary>Backend ClamAV piloté par le test (menaces, erreur, attente d'annulation).</summary>
internal sealed class ScriptedClamBackend : IClamAvOrchestratorBackend
{
    /// <summary>Signatures à renvoyer par fichier (clé = chemin complet).</summary>
    public Dictionary<string, string> ThreatsByPath { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Signatures par nom de fichier seul (fichiers temporaires au chemin imprévisible).</summary>
    public Dictionary<string, string> ThreatsByFileName { get; } = new(StringComparer.OrdinalIgnoreCase);

    public Exception? ThrowOnScan { get; set; }

    /// <summary>Bloque le scan jusqu'à l'annulation du jeton.</summary>
    public bool WaitForCancellation { get; set; }

    public int Calls { get; private set; }

    /// <summary>
    /// Si faux, le scan de dossier ne liste pas les fichiers. Le quick scan réel
    /// parcourt Bureau, Téléchargements et Windows\Temp : les énumérer bloque ou
    /// lève UnauthorizedAccessException sur un poste de développement.
    /// </summary>
    public bool ListFiles { get; set; } = true;

    public bool IsClamAvInstalled() => true;

    public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
        RunAsync(new[] { filePath }, filePath, ScanType.File, progress, ct);

    public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
    {
        string[] files;
        if (!ListFiles || !Directory.Exists(folderPath))
            files = Array.Empty<string>();
        else
        {
            try
            {
                files = Directory.GetFiles(folderPath, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { files = Array.Empty<string>(); }
            catch (IOException) { files = Array.Empty<string>(); }
        }
        return RunAsync(files, folderPath, ScanType.Folder, progress, ct);
    }

    public Task<ScanResult> ScanFileListAsync(IReadOnlyList<string> files, string targetPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
        RunAsync(files, targetPath, ScanType.Folder, progress, ct);

    private async Task<ScanResult> RunAsync(
        IReadOnlyList<string> files, string target, ScanType type, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        Calls++;
        if (ThrowOnScan != null)
            throw ThrowOnScan;
        if (WaitForCancellation)
            await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);

        var result = new ScanResult
        {
            Type = type,
            TargetPath = target,
            Status = ScanStatus.Completed,
            StartedAt = DateTime.Now,
            FinishedAt = DateTime.Now,
            FilesScanned = files.Count,
        };
        foreach (var f in files)
        {
            progress?.Report(new ScanProgress { CurrentFilePath = f, FilesScanned = 1 });
            if (ThreatsByPath.TryGetValue(f, out var sig) || ThreatsByFileName.TryGetValue(Path.GetFileName(f), out sig))
                result.Threats.Add(ThreatInfo.FromClamAv(f, sig, new FileInfo(f).Exists ? new FileInfo(f).Length : -1));
        }
        return result;
    }
}

internal sealed class NoopYaraBackend : IYaraOrchestratorBackend
{
    public bool IsAvailable => false;

    public int RulesCount => 0;

    public Task<List<YaraMatch>> ScanFileAsync(string filePath, CancellationToken ct = default) =>
        Task.FromResult(new List<YaraMatch>());

    public Task<List<YaraMatch>> ScanFolderAsync(string folderPath, IProgress<string>? progress = null, CancellationToken ct = default) =>
        Task.FromResult(new List<YaraMatch>());

    public Task<List<YaraMatch>> ScanFilesAsync(IReadOnlyList<string> files, IProgress<string>? progress = null, CancellationToken ct = default) =>
        Task.FromResult(new List<YaraMatch>());
}

/// <summary>Confirmation scriptée : enregistre chaque message et répond <see cref="Answer"/>.</summary>
internal sealed class RecordingConfirmService : IUserConfirmService
{
    public bool Answer { get; set; }

    public List<(string Message, string Title, bool Warning)> Questions { get; } = new();

    public List<string> Infos { get; } = new();

    public List<string> Warnings { get; } = new();

    public bool ConfirmYesNo(string message, string title, bool warning = true)
    {
        Questions.Add((message, title, warning));
        return Answer;
    }

    public void Inform(string message, string title) => Infos.Add(message);

    public void Warn(string message, string title) => Warnings.Add(message);
}

/// <summary>Contexte qui exécute les rappels un par un (équivalent du thread UI pour <see cref="Progress{T}"/>).</summary>
internal sealed class SerialSynchronizationContext : SynchronizationContext
{
    private readonly object _gate = new();

    public override void Post(SendOrPostCallback d, object? state) =>
        ThreadPool.QueueUserWorkItem(_ =>
        {
            lock (_gate)
            {
                var previous = Current;
                SetSynchronizationContext(this);
                try { d(state); }
                finally { SetSynchronizationContext(previous); }
            }
        });

    public override void Send(SendOrPostCallback d, object? state)
    {
        lock (_gate)
            d(state);
    }

    public override SynchronizationContext CreateCopy() => this;
}

internal static class Eventually
{
    /// <summary>Attend qu'une condition devienne vraie (rapports <see cref="Progress{T}"/> asynchrones).</summary>
    public static async Task TrueAsync(Func<bool> condition, int timeoutMs = 5000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
                throw new TimeoutException("Condition non atteinte dans le délai imparti.");
            await Task.Delay(20).ConfigureAwait(false);
        }
    }
}
