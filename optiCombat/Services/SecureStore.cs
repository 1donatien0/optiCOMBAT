using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace optiCombat.Services
{
    /// <summary>
    /// Persistance JSON sécurisée :
    ///   - Sérialisation JSON
    ///   - HMAC-SHA256 sur le contenu (clé aléatoire 256 bits protégée par DPAPI)
    ///   - Chiffrement DPAPI (CurrentUser scope) sur le tout
    ///
    /// Format du fichier :
    ///   <DPAPI_blob> = encrypt({ "Hmac": "...base64...", "Json": "..." })
    ///
    /// Migration : les fichiers signés avec l’ancienne dérivation déterministe
    /// (profil utilisateur) sont rechargés puis ré-enregistrés avec la nouvelle clé.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class SecureStore
    {
        private const string HmacInfo = "optiCombat-securestore-hmac";

        private static string HmacKeyPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "optiCombat", ".securestore_hmac.key");

        /// <summary>
        /// Charge un objet T depuis un fichier sécurisé. Retourne default(T)
        /// si le fichier n'existe pas, est corrompu, ou si HMAC invalide.
        /// </summary>
        public static T? Load<T>(string path) where T : class
        {
            if (!File.Exists(path)) return null;

            try
            {
                var encrypted = File.ReadAllBytes(path);
                var decrypted = ProtectedData.Unprotect(encrypted, optionalEntropy: null, DataProtectionScope.CurrentUser);

                var envelope = JsonSerializer.Deserialize<Envelope>(Encoding.UTF8.GetString(decrypted));
                if (envelope == null || string.IsNullOrEmpty(envelope.Json))
                    return null;

                if (!string.IsNullOrEmpty(envelope.Hmac))
                {
                    var dpapiKey = TryLoadDpapiHmacKey();
                    try
                    {
                        if (dpapiKey != null && TryVerifyHmac(envelope, dpapiKey))
                            return JsonSerializer.Deserialize<T>(envelope.Json);

                        var legacyKey = DeriveLegacyHmacKey();
                        try
                        {
                            if (TryVerifyHmac(envelope, legacyKey))
                            {
                                var migrated = JsonSerializer.Deserialize<T>(envelope.Json);
                                if (migrated != null)
                                {
                                    Save(path, migrated);
                                    AppLogger.Info("SecureStore",
                                        $"Clé HMAC migrée (DPAPI) pour {Path.GetFileName(path)}");
                                }
                                return migrated;
                            }
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(legacyKey);
                        }

                        AppLogger.Fatal("SecureStore",
                            $"HMAC invalide pour {Path.GetFileName(path)} — refus de chargement");
                        return null;
                    }
                    finally
                    {
                        if (dpapiKey != null)
                            CryptographicOperations.ZeroMemory(dpapiKey);
                    }
                }

                // Enveloppe legacy sans HMAC (pre-v2) — re-sauvegarde signée une fois.
                var unsigned = JsonSerializer.Deserialize<T>(envelope.Json);
                if (unsigned != null)
                {
                    Save(path, unsigned);
                    AppLogger.Info("SecureStore",
                        $"Migration enveloppe non signée → HMAC : {Path.GetFileName(path)}");
                }
                return unsigned;
            }
            catch (CryptographicException ex)
            {
                AppLogger.Warn("SecureStore", $"DPAPI Unprotect échoué pour {Path.GetFileName(path)}", ex);
                return null;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SecureStore", $"Lecture {Path.GetFileName(path)}", ex);
                return null;
            }
        }

        /// <summary>
        /// Sauvegarde un objet T dans un fichier sécurisé (DPAPI + HMAC).
        /// </summary>
        public static void Save<T>(string path, T value) where T : class
        {
            try
            {
                var json = JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = false });

                var key = GetOrCreateDpapiHmacKeyMaterial();
                string hmacB64;
                try
                {
                    using var hmac = new HMACSHA256(key);
                    var sig = hmac.ComputeHash(Encoding.UTF8.GetBytes(json));
                    hmacB64 = Convert.ToBase64String(sig);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key);
                }

                var envelope = new Envelope { Json = json, Hmac = hmacB64 };
                var envelopeBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(envelope));

                var encrypted = ProtectedData.Protect(envelopeBytes, optionalEntropy: null, DataProtectionScope.CurrentUser);

                AtomicFile.WriteAllBytes(path, encrypted);
            }
            catch (Exception ex)
            {
                AppLogger.Error("SecureStore", $"Save {Path.GetFileName(path)}", ex);
            }
        }

        /// <summary>
        /// Tente de migrer un fichier JSON en clair (legacy) vers le format
        /// sécurisé. Retourne l'objet désérialisé si réussite, null sinon.
        /// Le fichier en clair est renommé en .legacy à la fin.
        /// </summary>
        public static T? MigrateFromPlaintext<T>(string plaintextPath, string securePath) where T : class
        {
            if (!File.Exists(plaintextPath)) return null;
            try
            {
                var json = File.ReadAllText(plaintextPath);
                var obj = JsonSerializer.Deserialize<T>(json);
                if (obj == null) return null;

                Save(securePath, obj);

                try { File.Move(plaintextPath, plaintextPath + ".legacy", overwrite: true); }
                catch (Exception ex) { AppLogger.Warn("SecureStore", $"Migration cleanup {plaintextPath}", ex); }

                AppLogger.Info("SecureStore", $"Migration {Path.GetFileName(plaintextPath)} → format sécurisé");
                return obj;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SecureStore", $"Migration {plaintextPath}", ex);
                return null;
            }
        }

        // ── Helpers privés ───────────────────────────────────────────────────────

        private static bool TryVerifyHmac(Envelope envelope, byte[] key)
        {
            try
            {
                using var hmac = new HMACSHA256(key);
                var expected = hmac.ComputeHash(Encoding.UTF8.GetBytes(envelope.Json));
                var actual = Convert.FromBase64String(envelope.Hmac);
                return CryptographicOperations.FixedTimeEquals(expected, actual);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Ancienne dérivation — conservée uniquement pour migration S2.</summary>
        private static byte[] DeriveLegacyHmacKey()
        {
            var identity =
                HmacInfo + "|" +
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "|" +
                Environment.UserDomainName + "|" +
                Environment.UserName;
            return SHA256.HashData(Encoding.UTF8.GetBytes(identity));
        }

        private static byte[]? TryLoadDpapiHmacKey()
        {
            if (!File.Exists(HmacKeyPath))
                return null;
            try
            {
                var dec = ProtectedData.Unprotect(
                    File.ReadAllBytes(HmacKeyPath),
                    optionalEntropy: null,
                    DataProtectionScope.CurrentUser);
                return dec.Length == 32 ? dec : null;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SecureStore", "Lecture clé HMAC DPAPI", ex);
                return null;
            }
        }

        /// <summary>Clé aléatoire 256 bits persistée sous DPAPI.</summary>
        private static byte[] GetOrCreateDpapiHmacKeyMaterial()
        {
            var existing = TryLoadDpapiHmacKey();
            if (existing != null)
                return existing;

            var key = RandomNumberGenerator.GetBytes(32);
            try
            {
                var enc = ProtectedData.Protect(key, optionalEntropy: null, DataProtectionScope.CurrentUser);
                var dir = Path.GetDirectoryName(HmacKeyPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);
                AtomicFile.WriteAllBytes(HmacKeyPath, enc);
                try { File.SetAttributes(HmacKeyPath, FileAttributes.Hidden | FileAttributes.System); }
                catch { /* best effort */ }
            }
            catch (Exception ex)
            {
                AppLogger.Error("SecureStore", "Persistance clé HMAC DPAPI", ex);
            }
            return key;
        }

        private class Envelope
        {
            public string Json { get; set; } = string.Empty;
            public string Hmac { get; set; } = string.Empty;
        }
    }
}
