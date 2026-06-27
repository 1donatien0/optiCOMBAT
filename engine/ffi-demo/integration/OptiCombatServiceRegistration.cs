// OptiCombatServiceRegistration.cs — bascule DI vers le cœur Rust optiCombat.
//
// FICHIER D'INTÉGRATION (à copier dans optiCombat/Services/OptiCombat/).
// Appeler APRÈS AddOpticombatCoreServices : en MS.DI, la dernière inscription de
// IScanEngine l'emporte pour GetRequiredService<IScanEngine>().
using Microsoft.Extensions.DependencyInjection;
using optiCombat.Services.OptiCombat;

namespace optiCombat.Services.DependencyInjection
{
    public static class OptiCombatServiceRegistration
    {
        /// <summary>
        /// Remplace le moteur de scan par le cœur Rust optiCombat.
        /// Conserve un repli automatique sur ClamAV si la DLL native est absente.
        /// </summary>
        public static IServiceCollection UseOptiCombatEngine(this IServiceCollection services)
        {
            services.AddSingleton<OptiCombatScanEngine>();
            services.AddSingleton<IScanEngine>(sp =>
            {
                var native = sp.GetRequiredService<OptiCombatScanEngine>();
                // Repli : si la bibliothèque native n'est pas déployée, on garde
                // l'adaptateur ClamAV managé déjà enregistré.
                return native.IsAvailable
                    ? native
                    : sp.GetRequiredService<ClamAvScanEngineAdapter>();
            });
            return services;
        }
    }
}

// ─── Câblage (dans App.OnStartup / ServiceContainer, après le core) ───────────
//
//   services.AddOpticombatCoreServices();
//   services.UseOptiCombatEngine();   // ← bascule sur le cœur Rust, repli ClamAV
//
// Déploiement : placer opticombat.dll (build `cargo build -p opticombat-ffi
// --release`) à côté de optiCombat.exe. Aucun autre changement : ScanOrchestrator,
// QuarantineManager, l'UI et le RTP consomment IScanEngine inchangé.
