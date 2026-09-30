using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace optiCombat.Services;

/// <summary>
/// Intégrité des paquets de règles YARA-Forge téléchargés : signature ZIP, taille annoncée
/// et digest SHA-256 publiés par l'API GitHub Releases (champ <c>digest</c> = <c>sha256:…</c>).
/// Un paquet altéré (miroir, proxy, MITM) ne doit jamais remplacer les règles installées.
/// Aligné sur optiSCAN-stable : le digest GitHub est obligatoire.
/// </summary>
internal static class YaraForgePackageIntegrity
{
    private const string Sha256Prefix = "sha256:";

    /// <summary>Taille maximale acceptée (garde-fou mémoire) : 256 Mo.</summary>
    public const long MaxPackageBytes = 256L * 1024 * 1024;

    /// <summary>Lit la taille et le digest attendus d'un asset GitHub.</summary>
    public static void ReadExpected(JsonNode? asset, out long? size, out byte[]? sha256)
    {
        size = null;
        sha256 = null;
        if (asset is null)
            return;

        try { size = asset["size"]?.GetValue<long>(); }
        catch (Exception) { size = null; }

        string? digest;
        try { digest = asset["digest"]?.GetValue<string>(); }
        catch (Exception) { digest = null; }

        if (TryParseDigest(digest, out var parsed))
            sha256 = parsed;
    }

    /// <summary>Parse <c>sha256:&lt;64 hex&gt;</c>.</summary>
    public static bool TryParseDigest(string? digest, out byte[] sha256)
    {
        sha256 = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(digest))
            return false;

        var trimmed = digest.Trim();
        if (!trimmed.StartsWith(Sha256Prefix, StringComparison.OrdinalIgnoreCase))
            return false;

        var hex = trimmed[Sha256Prefix.Length..];
        if (hex.Length != 64)
            return false;

        try
        {
            sha256 = Convert.FromHexString(hex);
            return sha256.Length == 32;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Vérifie le contenu téléchargé. Le digest SHA-256 est obligatoire (optiSCAN-stable).
    /// Signature ZIP et taille maximale sont toujours contrôlées ; la taille annoncée l'est si fournie.
    /// </summary>
    public static bool Validate(byte[] content, long? expectedSize, byte[]? expectedSha256)
    {
        if (content is null || content.Length < 4 || content.LongLength > MaxPackageBytes)
            return false;

        // En-tête ZIP local « PK\x03\x04 »
        if (content[0] != 0x50 || content[1] != 0x4B || content[2] != 0x03 || content[3] != 0x04)
            return false;

        if (expectedSize is > 0 && content.LongLength != expectedSize.Value)
            return false;

        if (expectedSha256 is not { Length: 32 })
            return false;

        var actual = SHA256.HashData(content);
        return CryptographicOperations.FixedTimeEquals(actual, expectedSha256);
    }
}
