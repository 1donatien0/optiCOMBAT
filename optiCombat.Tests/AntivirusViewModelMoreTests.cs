using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.Tests;

[Collection("OpticombatPrefs")]
public sealed class AntivirusViewModelMoreTests : IDisposable
{
    private readonly IsolatedServices _env = new();
    private readonly RecordingConfirmService _confirm = new();

    public AntivirusViewModelMoreTests() => ThreatReputationService.ResetCacheForTests();

    public void Dispose()
    {
        ThreatReputationService.ResetCacheForTests();
        _env.Dispose();
    }

    private async Task<AntivirusViewModel> CreateAsync()
    {
        var vm = new AntivirusViewModel(_env.Container) { Confirm = _confirm };
        await Eventually.TrueAsync(() => !vm.IsInitializing, 15000);
        return vm;
    }

    [Fact]
    public async Task Reputation_without_key_warns_and_with_report_informs_with_permalink()
    {
        var file = _env.CreateFile("rep.exe", "contenu réputation " + Guid.NewGuid());
        var vm = await CreateAsync();

        await vm.ShowReputationAsync(null);
        Assert.Empty(_confirm.Warnings);

        await vm.ShowReputationAsync(file);
        Assert.Single(_confirm.Warnings); // pas de clé VirusTotal

        _env.Prefs.VirusTotalApiKey = "vt-key";
        var sha = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file))).ToLowerInvariant();
        _env.Http.Routes["https://www.virustotal.com/api/v3/files/" + sha] = () => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                """{"data":{"attributes":{"last_analysis_stats":{"malicious":3,"suspicious":0,"harmless":1,"undetected":60}}}}""",
                Encoding.UTF8, "application/json"),
        };
        await vm.ShowReputationAsync(file);
        var info = Assert.Single(_confirm.Infos);
        Assert.Contains("https://www.virustotal.com/gui/file/" + sha, info, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Signature_update_can_be_stopped_and_concurrent_update_is_refused()
    {
        // Règles : l'API GitHub ne répond jamais (attente) → la mise à jour reste en cours.
        var gate = new TaskCompletionSource();
        _env.Http.Routes[YaraForgeApi] = () =>
        {
            gate.Task.Wait(TimeSpan.FromSeconds(20));
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        };
        var vm = await CreateAsync();

        // Le faux serveur répond de façon synchrone : lancer hors du thread du test.
        var running = Task.Run(vm.UpdateSignaturesAsync);
        await Eventually.TrueAsync(() => vm.IsUpdating, 10_000);

        await vm.UpdateSignaturesAsync(); // déjà en cours
        Assert.False(string.IsNullOrEmpty(vm.StatusMessage));

        vm.StopSignatureUpdate();
        gate.SetResult();
        await running;
        Assert.False(vm.IsUpdating);
    }

    private static string YaraForgeApi => optiCombat.Strings.OpticombatStrings.Urls.YaraForgeApiLatest;
}
