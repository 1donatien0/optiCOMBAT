using optiCombat.Models;
using optiCombat.Services;
using System.Windows;

namespace optiCombat.Coordinators;

/// <summary>Données nécessaires aux exports HTML/PDF depuis la fenêtre principale.</summary>
public sealed record ExportContext(
    Window Owner,
    ScanLogManager? Log,
    IEnumerable<ThreatInfo> Threats,
    IEnumerable<QuarantineEntry> Quarantine,
    Action<string, bool, bool> SetStatus);
