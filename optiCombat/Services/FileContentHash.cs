using System.IO;
using System.Security.Cryptography;

namespace optiCombat.Services
{
    /// <summary>Hash SHA-256 du contenu fichier (réputation cloud).</summary>
    public static class FileContentHash
    {
        public static async Task<string?> TryComputeSha256HexAsync(string filePath, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                return null;

            try
            {
                await using var stream = new FileStream(
                    filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
                var hash = await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false);
                return Convert.ToHexString(hash);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("FileContentHash", filePath, ex);
                return null;
            }
        }
    }
}
