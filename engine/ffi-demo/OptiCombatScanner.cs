// OptiCombatScanner.cs — service de scan de haut niveau adossé au cœur Rust.
//
// Drop-in pour optiCombat.Service : enrobe OptiCombatNative (P/Invoke) derrière
// une interface injectable, à brancher dans ProtectionServiceHost à la place
// (ou en complément) des moteurs managés. Compile contre .NET 8.
using System;
using System.Text.Json;

namespace OptiCombat.Service.Interop
{
    /// <summary>Résultat de scan normalisé exposé au reste du service.</summary>
    public sealed record OptiCombatResult(
        OptiCombatVerdict Verdict,
        int Score,
        string Severity,
        string RawJson);

    /// <summary>Contrat de scan consommé par ProtectionServiceHost / RTP.</summary>
    public interface IOptiCombatScanner
    {
        OptiCombatResult Scan(string path);
        string EngineVersion { get; }
    }

    /// <summary>
    /// Implémentation adossée à la bibliothèque native optiCombat.
    /// Sans état → enregistrable en singleton dans le conteneur DI.
    /// </summary>
    public sealed class OptiCombatScanner : IOptiCombatScanner
    {
        public string EngineVersion => OptiCombatNative.Version();

        public OptiCombatResult Scan(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentException("chemin vide", nameof(path));

            var verdict = OptiCombatNative.ScanPath(path);
            var json = OptiCombatNative.ScanJson(path) ?? "{}";

            int score = 0;
            string severity = "Clean";
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.TryGetProperty("score", out var s)) score = s.GetInt32();
                if (root.TryGetProperty("severity", out var sev)) severity = sev.GetString() ?? "Clean";
            }
            catch (JsonException)
            {
                // JSON inattendu : on conserve le verdict, score/severity par défaut.
            }

            return new OptiCombatResult(verdict, score, severity, json);
        }
    }
}

// ─── Enregistrement DI (extrait à placer dans ServiceContainer) ───────────────
//
//   services.AddSingleton<IOptiCombatScanner, OptiCombatScanner>();
//
// Utilisation dans un coordinateur / ProtectionServiceHost :
//
//   var result = _scanner.Scan(filePath);
//   if (result.Verdict == OptiCombatVerdict.Malicious)
//   {
//       _quarantineManager.Quarantine(filePath);   // réutilise l'existant
//       _activityLog.ThreatDetected(filePath, result.Severity, result.RawJson);
//   }
