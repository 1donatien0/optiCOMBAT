using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace optiCombat.Services
{
    /// <summary>
    /// Empreinte et validité du cache <c>_compiled.yarc</c> / <c>_compiled.stamp</c>.
    /// </summary>
    internal static class YaraRulesCacheSupport
    {
        /// <summary>
        /// <c>true</c> si le binaire compilé et le stamp correspondent aux .yar actuels.
        /// </summary>
        public static bool IsCompiledUpToDate(string rulesDirectory, string compiledRulesPath, string compiledStampPath)
        {
            if (!File.Exists(compiledRulesPath)) return false;
            if (!File.Exists(compiledStampPath)) return false;
            try
            {
                var files = Directory.GetFiles(rulesDirectory, "*.yar");
                if (files.Length == 0) return false;
                Array.Sort(files, StringComparer.OrdinalIgnoreCase);
                var currentStamp = ComputeRulesDirectoryFingerprint(files);
                var savedStamp = File.ReadAllText(compiledStampPath, Encoding.UTF8).Trim();
                return string.Equals(currentStamp, savedStamp, StringComparison.Ordinal);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Empreinte du dossier de règles (chemin + taille + LastWriteTimeUtc).</summary>
        public static string ComputeRulesDirectoryFingerprint(string[] sortedAbsolutePaths)
        {
            using var ms = new MemoryStream();
            foreach (var p in sortedAbsolutePaths)
            {
                if (!File.Exists(p))
                    continue;
                var fi = new FileInfo(p);
                var line = $"{p}|{fi.Length}|{fi.LastWriteTimeUtc.Ticks}\n";
                var b = Encoding.UTF8.GetBytes(line);
                ms.Write(b, 0, b.Length);
            }

            return ms.Length == 0
                ? "EMPTY"
                : Convert.ToHexString(SHA256.HashData(ms.ToArray()));
        }

        public static void WriteCompiledStamp(string compiledStampPath, string[] sortedYarFiles)
        {
            var stamp = ComputeRulesDirectoryFingerprint(sortedYarFiles);
            File.WriteAllText(compiledStampPath, stamp, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        }
    }
}
