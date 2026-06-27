using optiCombat.Models;

namespace optiCombat.ViewModels
{
    /// <summary>Ligne menace dans le détail Historique — état fichier / quarantaine pour les actions.</summary>
    public sealed class HistoryThreatRow
    {
        public HistoryThreatRow(ThreatInfo threat, HistoryViewModel vm)
        {
            Threat = threat;
            IsQuarantined = vm.IsFileStillQuarantined(threat.FilePath);
            IsFileAccessible = vm.IsThreatFileAccessible(threat.FilePath);
        }

        public ThreatInfo Threat { get; }
        public string FilePath => Threat.FilePath;
        public string VirusName => Threat.VirusName;
        public bool IsQuarantined { get; }
        public bool IsFileAccessible { get; }
        public bool CanQuarantine => IsFileAccessible && !IsQuarantined;
        public bool CanViewInQuarantine => IsQuarantined;
        public bool CanDismiss => !IsFileAccessible && !IsQuarantined;
    }
}