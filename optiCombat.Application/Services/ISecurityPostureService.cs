using optiCombat.Models;

namespace optiCombat.Services
{
    /// <summary>Évalue la note de posture sécurité (/100) et les contrôles associés.</summary>
    public interface ISecurityPostureService
    {
        SecurityPostureReport Evaluate(SecurityPostureContext context);
    }
}
