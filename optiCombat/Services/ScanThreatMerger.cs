using optiCombat.Models;

namespace optiCombat.Services
{
    /// <summary>
    /// Fusionne les menaces ClamAV et YARA dans un <see cref="ScanResult"/> unique
    /// (une ligne par fichier infecté, comme les suites multi-moteurs type 360).
    /// </summary>
    internal static class ScanThreatMerger
    {
        /// <summary>
        /// Fusionne deux résultats moteur. Statistiques : un seul compteur de fichiers/octets
        /// (<see cref="ScanResult.FilesScanned"/> = max des moteurs, octets = ClamAV).
        /// </summary>
        public static ScanResult Merge(
            ScanType type,
            string target,
            ScanResult clamResult,
            ScanResult yaraResult,
            IExclusionSettingsAccessor? exclusions = null)
        {
            var merged = new ScanResult
            {
                Type = type,
                TargetPath = target,
                StartedAt = clamResult.StartedAt < yaraResult.StartedAt ? clamResult.StartedAt : yaraResult.StartedAt,
                FinishedAt = DateTime.Now,
                FilesScanned = Math.Max(clamResult.FilesScanned, yaraResult.FilesScanned),
                FilesSkipped = clamResult.FilesSkipped,
                TotalBytesScanned = clamResult.TotalBytesScanned,
                Status = (clamResult.Status == ScanStatus.Cancelled || yaraResult.Status == ScanStatus.Cancelled)
                    ? ScanStatus.Cancelled
                    : ScanStatus.Completed
            };

            var excl = (exclusions ?? new DefaultExclusionSettingsAccessor()).Current;
            var clamByPath = AggregateThreatsByPath(
                clamResult.Threats.Where(t => !excl.IsFileExcluded(t.FilePath)));
            var yaraByPath = AggregateThreatsByPath(
                yaraResult.Threats.Where(t => !excl.IsFileExcluded(t.FilePath)));

            var allPaths = new HashSet<string>(clamByPath.Keys, StringComparer.OrdinalIgnoreCase);
            foreach (var p in yaraByPath.Keys)
                allPaths.Add(p);

            foreach (var path in allPaths)
            {
                clamByPath.TryGetValue(path, out var clamT);
                yaraByPath.TryGetValue(path, out var yaraT);

                if (clamT != null && yaraT != null)
                    merged.Threats.Add(MergeThreatPair(clamT, yaraT));
                else if (clamT != null)
                    merged.Threats.Add(clamT);
                else if (yaraT != null)
                    merged.Threats.Add(yaraT);
            }

            return merged;
        }

        /// <summary>Ajoute ou fusionne une menace dans une liste (agrégation multi-zones).</summary>
        public static void AddOrMergeThreat(IList<ThreatInfo> threats, ThreatInfo incoming)
        {
            for (var i = 0; i < threats.Count; i++)
            {
                if (!string.Equals(threats[i].FilePath, incoming.FilePath, StringComparison.OrdinalIgnoreCase))
                    continue;
                threats[i] = MergeThreatPair(threats[i], incoming);
                return;
            }

            threats.Add(incoming);
        }

        /// <summary>
        /// Une entrée par chemin ; plusieurs signatures ou règles → libellé joint.
        /// </summary>
        internal static Dictionary<string, ThreatInfo> AggregateThreatsByPath(IEnumerable<ThreatInfo> threats)
        {
            var byPath = new Dictionary<string, ThreatInfo>(StringComparer.OrdinalIgnoreCase);
            var namesByPath = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

            foreach (var t in threats)
            {
                if (!byPath.TryGetValue(t.FilePath, out var existing))
                {
                    byPath[t.FilePath] = t;
                    namesByPath[t.FilePath] = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { t.VirusName };
                    continue;
                }

                namesByPath[t.FilePath].Add(t.VirusName);
                if (t.DetectedAt < existing.DetectedAt)
                    existing.DetectedAt = t.DetectedAt;
                if (t.FileSize >= 0 && existing.FileSize < 0)
                    existing.FileSize = t.FileSize;
            }

            foreach (var kv in namesByPath)
            {
                if (kv.Value.Count <= 1) continue;
                byPath[kv.Key].VirusName = string.Join(" / ", kv.Value.OrderBy(s => s, StringComparer.Ordinal));
            }

            return byPath;
        }

        /// <summary>Alias historique (tests ClamAV).</summary>
        internal static Dictionary<string, ThreatInfo> AggregateClamByPath(IEnumerable<ThreatInfo> clamThreats) =>
            AggregateThreatsByPath(clamThreats);

        internal static ThreatInfo MergeThreatPair(ThreatInfo a, ThreatInfo b)
        {
            if (!string.Equals(a.FilePath, b.FilePath, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Les menaces doivent concerner le même fichier.");

            var clamNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var yaraNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            CollectSignatureNames(a, clamNames, yaraNames);
            CollectSignatureNames(b, clamNames, yaraNames);

            var detectedBy = ResolveDetectedBy(a.DetectedBy, b.DetectedBy);
            var virusName = FormatCombinedVirusName(clamNames, yaraNames);

            var merged = a.DetectedAt <= b.DetectedAt ? a : b;
            return new ThreatInfo
            {
                FilePath = merged.FilePath,
                VirusName = virusName,
                DetectedAt = merged.DetectedAt,
                Status = merged.Status,
                FileSize = Math.Max(a.FileSize, b.FileSize),
                QuarantinePath = merged.QuarantinePath,
                DetectedBy = detectedBy,
            };
        }

        private static void CollectSignatureNames(ThreatInfo t, HashSet<string> clamNames, HashSet<string> yaraNames)
        {
            var yaraOnly = string.Equals(t.DetectedBy, "YARA", StringComparison.OrdinalIgnoreCase);
            foreach (var part in t.VirusName.Split(" / ", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (part.StartsWith("YARA:", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (var rule in part.Substring(5).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                        yaraNames.Add(rule);
                }
                else if (yaraOnly)
                {
                    yaraNames.Add(part);
                }
                else
                {
                    clamNames.Add(part);
                }
            }
        }

        private static string FormatCombinedVirusName(HashSet<string> clamNames, HashSet<string> yaraNames)
        {
            var parts = new List<string>();
            if (clamNames.Count > 0)
                parts.Add(string.Join(" / ", clamNames.OrderBy(s => s, StringComparer.Ordinal)));
            if (yaraNames.Count > 0)
                parts.Add("YARA:" + string.Join(",", yaraNames.OrderBy(s => s, StringComparer.Ordinal)));
            return parts.Count > 0 ? string.Join(" / ", parts) : string.Empty;
        }

        private static string ResolveDetectedBy(string a, string b)
        {
            static bool HasClam(string d) =>
                d.Contains("ClamAV", StringComparison.OrdinalIgnoreCase);
            static bool HasYara(string d) =>
                d.Contains("YARA", StringComparison.OrdinalIgnoreCase);

            var clam = HasClam(a) || HasClam(b);
            var yara = HasYara(a) || HasYara(b);
            if (clam && yara) return "ClamAV+YARA";
            if (yara) return "YARA";
            return "ClamAV";
        }
    }
}
