using optiCombat.Models;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace optiCombat.Services
{
    /// <summary>
    /// Quarantaine sécurisée :
    ///   - Chiffrement par fichier en AES-256-GCM (authentifié), en-tête OPTQ + nonce + tag.
    ///   - Clé maîtresse 256 bits stockée chiffrée par DPAPI (CurrentUser)
    ///   - Chaque fichier reçoit un nonce 96 bits aléatoire unique
    ///   - Le manifest est signé en HMAC-SHA256 — un manifest manipulé est rejeté
    ///
    /// Format des fichiers .quar (binaire) :
    ///   Magic:    4 octets   "OPTQ"
    ///   Version:  1 octet    0x02
    ///   Nonce:    12 octets
    ///   Tag:      16 octets  (GCM auth tag)
    ///   Cipher:   N octets   (taille = taille du fichier original)
    ///
    /// Format manifest.json :
    ///   { "Version": 2, "Hmac": "...base64...", "Entries": [...] }
    ///
    /// Pagination : <see cref="GetEntriesPaged"/> pour les grosses listes.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class QuarantineManager : IThreatStore
    {
        // ── Constantes format ────────────────────────────────────────────────────
        private const byte FormatVersion = 0x02;
        private const byte RawBufferXorConstant = 0x5A;
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("OPTQ");
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int HeaderSize = 4 + 1 + NonceSize + TagSize; // 33 octets

        /// <summary>Limite de taille fichier en quarantaine (plainte) pour éviter un pic RAM + OOM.</summary>
        private const long MaxQuarantinePlaintextBytes = 256L * 1024 * 1024;

        // ── Chemins ──────────────────────────────────────────────────────────────
        private readonly string _quarantineDir;
        private readonly string _manifestPath;
        private readonly string _keyPath;       // clé maîtresse chiffrée DPAPI

        // ── État ─────────────────────────────────────────────────────────────────
        private readonly byte[] _masterKey;     // 32 octets (déchiffrés en RAM)
        private QuarantineDocument _doc;
        private readonly object _lock = new();
        private ActivityLogService? _activityLog;
        private readonly IUserPreferencesAccessor _prefs;

        // ── Construction ─────────────────────────────────────────────────────────

        public QuarantineManager(string? quarantineDir = null, IUserPreferencesAccessor? preferences = null)
        {
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
            _quarantineDir = quarantineDir ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "optiCombat", "Quarantine");

            _manifestPath = Path.Combine(_quarantineDir, "manifest.json");
            _keyPath = Path.Combine(_quarantineDir, ".key");

            EnsureDirectoryExists(_quarantineDir);
            _masterKey = LoadOrCreateMasterKey();
            _doc = LoadManifest();
            MigrateUnsignedManifestIfNeeded();
            _ = Task.Run(EnsureQuarantineBlobLayout);
        }

        public void BindActivityLog(ActivityLogService activityLog) => _activityLog = activityLog;

        /// <summary>Legacy v1 : signe le manifeste au premier chargement. v2+ non signé : rejet.</summary>
        private void MigrateUnsignedManifestIfNeeded()
        {
            if (!string.IsNullOrEmpty(_doc.Hmac))
                return;

            if (_doc.Entries.Count == 0)
                return;

            if (_doc.Version >= 2)
            {
                AppLogger.Fatal("QuarantineManager", "Manifeste v2 sans HMAC — entrées ignorées");
                _doc = new QuarantineDocument { Version = 2 };
                SaveManifest();
                return;
            }

            AppLogger.Info("QuarantineManager", "Migration manifeste legacy (v1) → HMAC v2");
            _doc.Version = 2;
            SaveManifest();
        }

        // ── Clé maîtresse (DPAPI) ────────────────────────────────────────────────

        /// <summary>
        /// Charge la clé maîtresse chiffrée par DPAPI, ou en génère une nouvelle.
        /// DPAPI CurrentUser : seul l'utilisateur courant peut déchiffrer la clé,
        /// même un autre admin de la machine ne pourra pas l'utiliser.
        /// </summary>
        private byte[] LoadOrCreateMasterKey()
        {
            try
            {
                if (File.Exists(_keyPath))
                {
                    var encrypted = File.ReadAllBytes(_keyPath);
                    return ProtectedData.Unprotect(encrypted, optionalEntropy: null, DataProtectionScope.CurrentUser);
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("QuarantineManager", "Lecture clé maîtresse", ex);
                // Clé corrompue → on la régénère. Les .quar existants deviennent illisibles sans cette clé (comportement attendu).
            }

            // Génération d'une clé 256 bits aléatoire et stockage chiffré DPAPI.
            var key = RandomNumberGenerator.GetBytes(32);
            try
            {
                var encrypted = ProtectedData.Protect(key, optionalEntropy: null, DataProtectionScope.CurrentUser);
                AtomicFile.WriteAllBytes(_keyPath, encrypted);

                // Sur Windows, on tente de marquer le fichier comme caché + system
                // pour éviter la curiosité utilisateur (best effort).
                try { File.SetAttributes(_keyPath, FileAttributes.Hidden | FileAttributes.System); }
                catch { /* best effort */ }
            }
            catch (Exception ex)
            {
                AppLogger.Error("QuarantineManager", "Persistance clé maîtresse échouée", ex);
            }
            return key;
        }

        // ── Quarantaine ──────────────────────────────────────────────────────────

        bool IThreatStore.Quarantine(ThreatInfo threat) => Quarantine(threat, default);

        int IThreatStore.QuarantineAll(IEnumerable<ThreatInfo> threats) => QuarantineAll(threats, default);

        public bool Quarantine(ThreatInfo threat, Guid sourceSessionId = default)
        {
            try
            {
                if (_prefs.Current.BackupBeforeQuarantine)
                    ThreatRemediationService.TryCreateSafetyCopy(threat);

                var id = Guid.NewGuid().ToString("N");
                var qPath = Path.Combine(_quarantineDir, id + ".quar");

                byte[] plaintext;
                long len;
                try
                {
                    using var fs = new FileStream(
                        threat.FilePath,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.Read);
                    len = fs.Length;
                    if (len > MaxQuarantinePlaintextBytes)
                    {
                        AppLogger.Warn("QuarantineManager",
                            $"Fichier trop volumineux pour la quarantaine ({len} octets > {MaxQuarantinePlaintextBytes}) : {threat.FilePath}");
                        return false;
                    }

                    plaintext = new byte[len];
                    int offset = 0;
                    while (offset < len)
                    {
                        int read = fs.Read(plaintext, offset, (int)(len - offset));
                        if (read == 0)
                            break;
                        offset += read;
                    }
                }
                catch (FileNotFoundException)
                {
                    return false;
                }
                catch (DirectoryNotFoundException)
                {
                    return false;
                }

                // 2. Hash SHA-256 du plaintext (pour détecter une corruption à la
                //    restauration et tracer l'identité du fichier).
                var sha256 = SHA256.HashData(plaintext);

                // 3. Chiffrement AES-GCM avec nonce aléatoire unique.
                var nonce = RandomNumberGenerator.GetBytes(NonceSize);
                var ciphertext = new byte[plaintext.Length];
                var tag = new byte[TagSize];

                using (var aes = new AesGcm(_masterKey, TagSize))
                {
                    aes.Encrypt(nonce, plaintext, ciphertext, tag);
                }

                // 4. Écriture du fichier quarantaine au format binaire versionné.
                using (var fs = new FileStream(qPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    fs.Write(Magic, 0, Magic.Length);
                    fs.WriteByte(FormatVersion);
                    fs.Write(nonce, 0, nonce.Length);
                    fs.Write(tag, 0, tag.Length);
                    fs.Write(ciphertext, 0, ciphertext.Length);
                    fs.Flush(flushToDisk: true);
                }

                // 5. Suppression du fichier original (après écriture confirmée).
                try
                {
                    File.Delete(threat.FilePath);
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("QuarantineManager",
                        $"Suppression originale échouée après quarantaine ({threat.FilePath})", ex);
                    try { File.Delete(qPath); } catch { /* rollback blob */ }
                    return false;
                }

                threat.Status = ThreatStatus.Quarantined;
                threat.QuarantinePath = qPath;

                lock (_lock)
                {
                    var entry = new QuarantineEntry
                    {
                        Id = id,
                        OriginalPath = threat.FilePath,
                        QuarantinePath = qPath,
                        VirusName = threat.VirusName,
                        QuarantinedAt = DateTime.Now,
                        OriginalSize = threat.FileSize,
                        Sha256 = Convert.ToHexString(sha256),
                        SourceSessionId = sourceSessionId != Guid.Empty ? sourceSessionId : null,
                    };
                    _doc.Entries.Add(entry);
                    if (!TrySaveManifest())
                    {
                        _doc.Entries.Remove(entry);
                        try { File.Delete(qPath); } catch { /* best effort */ }
                        return false;
                    }
                    _activityLog?.RecordThreatQuarantined(entry, sourceSessionId);
                }

                // 6. Wipe du plaintext en RAM (réduit la fenêtre d'exposition mémoire).
                CryptographicOperations.ZeroMemory(plaintext);

                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Error("QuarantineManager", $"Quarantine échec ({threat.FilePath})", ex);
                return false;
            }
        }

        public int QuarantineAll(IEnumerable<ThreatInfo> threats, Guid sourceSessionId = default)
        {
            int count = 0;
            foreach (var t in threats)
                if (Quarantine(t, sourceSessionId)) count++;
            return count;
        }

        // ── Restauration ─────────────────────────────────────────────────────────

        public bool Restore(string quarantineId)
        {
            QuarantineEntry? entry;
            lock (_lock) { entry = _doc.Entries.Find(e => e.Id == quarantineId); }
            if (entry == null) return false;
            return RestoreToPath(entry, entry.OriginalPath);
        }

        /// <summary>
        /// Restauration vers le chemin d'origine y compris emplacements système (outil admin / script élevé).
        /// L'UI standard utilise <see cref="Restore"/> qui refuse System32, Program Files, etc.
        /// </summary>
        public bool RestoreAdministrative(string quarantineId)
        {
            QuarantineEntry? entry;
            lock (_lock) { entry = _doc.Entries.Find(e => e.Id == quarantineId); }
            if (entry == null) return false;
            return RestoreToPath(entry, entry.OriginalPath, allowSensitivePath: true);
        }

        public bool RestoreTo(string quarantineId, string destinationFolder)
        {
            QuarantineEntry? entry;
            lock (_lock) { entry = _doc.Entries.Find(e => e.Id == quarantineId); }
            if (entry == null) return false;

            try
            {
                if (!Directory.Exists(destinationFolder))
                    Directory.CreateDirectory(destinationFolder);

                var destPath = Path.Combine(destinationFolder, entry.FileName);
                if (File.Exists(destPath))
                {
                    destPath = Path.Combine(destinationFolder,
                        Path.GetFileNameWithoutExtension(entry.FileName) + "_restored" +
                        Path.GetExtension(entry.FileName));
                }

                if (!IsResolvedPathUnderDirectory(destPath, destinationFolder))
                {
                    AppLogger.Warn("QuarantineManager",
                        $"RestoreTo: chemin hors dossier autorisé ({destPath})");
                    return false;
                }

                return RestoreToPath(entry, destPath);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("QuarantineManager", $"RestoreTo: {ex.Message}", ex);
                return false;
            }
        }

        private bool RestoreToPath(QuarantineEntry entry, string destination, bool allowSensitivePath = false)
        {
            if (!File.Exists(entry.QuarantinePath)) return false;

            // Sécurité : on refuse les chemins de restauration aberrants.
            // Une entrée manipulée pourrait demander une écriture vers System32.
            // Le manifest est signé HMAC, donc cela ne devrait jamais arriver,
            // mais défense en profondeur (contournable via RestoreAdministrative).
            try
            {
                var fullDest = Path.GetFullPath(destination);
                if (!allowSensitivePath && IsSensitivePath(fullDest))
                {
                    AppLogger.Warn("QuarantineManager", $"Restauration refusée vers chemin sensible: {fullDest}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("QuarantineManager", $"Résolution chemin restauration: {destination}", ex);
                return false;
            }

            try
            {
                byte[] plaintext = DecryptQuarantineFile(entry.QuarantinePath);

                // Vérification d'intégrité via SHA-256 stocké dans le manifest.
                if (!string.IsNullOrEmpty(entry.Sha256))
                {
                    var actual = Convert.ToHexString(SHA256.HashData(plaintext));
                    if (!string.Equals(actual, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        AppLogger.Warn("QuarantineManager", $"SHA-256 mismatch pour {entry.Id}");
                        CryptographicOperations.ZeroMemory(plaintext);
                        return false;
                    }
                }

                var dir = Path.GetDirectoryName(destination);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                File.WriteAllBytes(destination, plaintext);
                CryptographicOperations.ZeroMemory(plaintext);

                File.Delete(entry.QuarantinePath);
                lock (_lock)
                {
                    _activityLog?.RecordThreatRestored(entry);
                    _doc.Entries.Remove(entry);
                    SaveManifest();
                }
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("QuarantineManager", $"RestoreToPath ({entry.Id})", ex);
                return false;
            }
        }

        /// <summary>Vérifie que <paramref name="candidatePath"/> résolu reste sous <paramref name="destinationFolder"/>.</summary>
        internal static bool IsResolvedPathUnderDirectory(string candidatePath, string destinationFolder)
        {
            var root = Path.GetFullPath(destinationFolder);
            if (!root.EndsWith(Path.DirectorySeparatorChar))
                root += Path.DirectorySeparatorChar;

            var full = Path.GetFullPath(candidatePath);
            return full.StartsWith(root, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Refuse la restauration vers les emplacements système critiques (tests via InternalsVisibleTo).</summary>
        internal static bool IsSensitivePath(string fullPath)
        {
            // Chemin vide/blanc : non sensible (conserve le comportement d'origine
            // et évite que Path.GetFullPath ne lève sur une chaîne vide).
            if (string.IsNullOrWhiteSpace(fullPath))
                return false;

            string[] forbidden =
            {
                Environment.GetFolderPath(Environment.SpecialFolder.System),       // System32
                Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),    // SysWOW64
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),      // C:\Windows
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), // ProgramData
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            };

            // Comparaison par segment de chemin : « C:\WindowsApps » ne doit PAS être
            // considéré comme étant sous « C:\Windows ». On normalise et on exige soit
            // l'égalité exacte, soit un séparateur de répertoire après le préfixe.
            static string Normalize(string p) =>
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(p));

            var target = Normalize(fullPath);
            foreach (var f in forbidden)
            {
                if (string.IsNullOrEmpty(f)) continue;
                var root = Normalize(f);
                if (target.Equals(root, StringComparison.OrdinalIgnoreCase)
                    || target.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        /// <summary>Déchiffre un fichier .quar en contenu clair.</summary>
        private byte[] DecryptQuarantineFile(string path)
        {
            byte[] raw = File.ReadAllBytes(path);

            // En-tête OPTQ : AES-GCM ; sinon lecture directe du buffer.
            bool isV2 = raw.Length >= HeaderSize
                && raw[0] == Magic[0] && raw[1] == Magic[1]
                && raw[2] == Magic[2] && raw[3] == Magic[3];

            if (!isV2)
                return DecryptWithoutQuarantineHeader(raw);

            byte version = raw[4];
            if (version != FormatVersion)
                throw new InvalidDataException($"Version quarantaine inconnue : {version}");

            var nonce = new byte[NonceSize];
            var tag = new byte[TagSize];
            Array.Copy(raw, 5, nonce, 0, NonceSize);
            Array.Copy(raw, 5 + NonceSize, tag, 0, TagSize);

            int cipherLen = raw.Length - HeaderSize;
            var ciphertext = new byte[cipherLen];
            Array.Copy(raw, HeaderSize, ciphertext, 0, cipherLen);

            var plaintext = new byte[cipherLen];
            using (var aes = new AesGcm(_masterKey, TagSize))
            {
                aes.Decrypt(nonce, ciphertext, tag, plaintext);
            }
            return plaintext;
        }

        /// <summary>Au démarrage (arrière-plan) : aligne les fichiers du manifeste sur le format .quar attendu.</summary>
        private void EnsureQuarantineBlobLayout()
        {
            try
            {
                int filesUpdated = 0;
                lock (_lock)
                {
                    foreach (var entry in _doc.Entries.ToList())
                    {
                        try
                        {
                            if (!File.Exists(entry.QuarantinePath))
                                continue;
                            var raw = File.ReadAllBytes(entry.QuarantinePath);
                            if (IsV2QuarantineBlob(raw))
                                continue;

                            var plaintext = DecryptWithoutQuarantineHeader(raw);
                            if (!string.IsNullOrEmpty(entry.Sha256))
                            {
                                var actual = Convert.ToHexString(SHA256.HashData(plaintext));
                                if (!string.Equals(actual, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                                {
                                    AppLogger.Warn("QuarantineManager",
                                        $"Migration blob legacy — SHA-256 invalide pour {entry.Id}");
                                    CryptographicOperations.ZeroMemory(plaintext);
                                    continue;
                                }
                            }

                            var blob = BuildV2QuarantineBlob(plaintext);
                            CryptographicOperations.ZeroMemory(plaintext);
                            AtomicFile.WriteAllBytes(entry.QuarantinePath, blob);
                            filesUpdated++;
                        }
                        catch (Exception ex)
                        {
                            AppLogger.Warn("QuarantineManager", $"Fichier quarantaine ({entry.Id})", ex);
                        }
                    }

                    if (filesUpdated > 0)
                    {
                        SaveManifest();
                        AppLogger.Info("QuarantineManager",
                            $"Quarantaine : {filesUpdated} fichier(s) mis à jour.");
                    }
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("QuarantineManager", "Alignement stockage quarantaine", ex);
            }
        }

        private static bool IsV2QuarantineBlob(byte[] raw) =>
            raw.Length >= HeaderSize
            && raw[0] == Magic[0] && raw[1] == Magic[1]
            && raw[2] == Magic[2] && raw[3] == Magic[3];

        private static byte[] DecryptWithoutQuarantineHeader(byte[] raw)
        {
            var buffer = new byte[raw.Length];
            for (int i = 0; i < raw.Length; i++)
                buffer[i] = (byte)(raw[i] ^ RawBufferXorConstant);
            return buffer;
        }

        private byte[] BuildV2QuarantineBlob(byte[] plaintext)
        {
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagSize];
            using (var aes = new AesGcm(_masterKey, TagSize))
                aes.Encrypt(nonce, plaintext, ciphertext, tag);

            var blob = new byte[HeaderSize + ciphertext.Length];
            Buffer.BlockCopy(Magic, 0, blob, 0, 4);
            blob[4] = FormatVersion;
            Buffer.BlockCopy(nonce, 0, blob, 5, NonceSize);
            Buffer.BlockCopy(tag, 0, blob, 5 + NonceSize, TagSize);
            Buffer.BlockCopy(ciphertext, 0, blob, HeaderSize, ciphertext.Length);
            return blob;
        }

        // ── Suppression / Purge ──────────────────────────────────────────────────

        public bool DeletePermanently(string quarantineId)
        {
            QuarantineEntry? entry;
            lock (_lock) { entry = _doc.Entries.Find(e => e.Id == quarantineId); }
            if (entry == null) return false;

            try
            {
                if (File.Exists(entry.QuarantinePath))
                    File.Delete(entry.QuarantinePath);

                lock (_lock)
                {
                    _activityLog?.RecordQuarantineDeleted(entry);
                    _doc.Entries.Remove(entry);
                    SaveManifest();
                }
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("QuarantineManager", $"DeletePermanently ({quarantineId})", ex);
                return false;
            }
        }

        public int PurgeAll()
        {
            int count = 0;
            QuarantineEntry[] snapshot;
            lock (_lock) { snapshot = _doc.Entries.ToArray(); }
            foreach (var entry in snapshot)
                if (DeletePermanently(entry.Id)) count++;
            return count;
        }

        /// <summary>
        /// Fenêtre paginée sur les entrées — évite de copier toute la liste côté UI.
        /// </summary>
        public IReadOnlyList<QuarantineEntry> GetEntriesPaged(int offset, int count)
        {
            if (offset < 0) offset = 0;
            if (count <= 0)
                return Array.Empty<QuarantineEntry>();
            lock (_lock)
            {
                var list = _doc.Entries;
                if (offset >= list.Count)
                    return Array.Empty<QuarantineEntry>();
                var take = Math.Min(count, list.Count - offset);
                return list.GetRange(offset, take);
            }
        }

        public IReadOnlyList<QuarantineEntry> GetEntries()
        {
            lock (_lock) { return _doc.Entries.AsReadOnly(); }
        }

        public int Count
        {
            get { lock (_lock) { return _doc.Entries.Count; } }
        }

        public long TotalSize
        {
            get { lock (_lock) { return _doc.Entries.Sum(e => e.OriginalSize > 0 ? e.OriginalSize : 0); } }
        }

        // ── Manifest avec HMAC-SHA256 ────────────────────────────────────────────

        /// <summary>
        /// Charge le manifest en vérifiant la signature HMAC.
        /// Si la signature ne correspond pas, on log et on retourne un manifest vide
        /// — refus de charger un manifest manipulé.
        /// </summary>
        private QuarantineDocument LoadManifest()
        {
            return AtomicFile.ReadWithBackup(
                _manifestPath,
                json =>
                {
                    var doc = JsonSerializer.Deserialize<QuarantineDocument>(json) ?? new QuarantineDocument();

                    // Vérification HMAC : on recalcule sur la liste d'entries
                    // sérialisée canoniquement, et compare avec le HMAC stocké.
                    if (!string.IsNullOrEmpty(doc.Hmac))
                    {
                        var expected = ComputeHmac(doc.Entries);
                        if (!CryptographicOperations.FixedTimeEquals(
                                Convert.FromBase64String(doc.Hmac),
                                expected))
                        {
                            AppLogger.Fatal("QuarantineManager", "HMAC manifest invalide — refus de chargement");
                            throw new InvalidDataException("Manifest HMAC invalide");
                        }
                    }
                    else if (doc.Entries.Count > 0 && doc.Version >= 2)
                    {
                        AppLogger.Fatal("QuarantineManager", "Manifeste v2 sans HMAC — refus de chargement");
                        throw new InvalidDataException("Manifest unsigned");
                    }

                    return doc;
                },
                fallbackValue: new QuarantineDocument());
        }

        private bool TrySaveManifest()
        {
            try
            {
                _doc.Version = 2;
                _doc.Hmac = Convert.ToBase64String(ComputeHmac(_doc.Entries));

                var json = JsonSerializer.Serialize(_doc, new JsonSerializerOptions
                {
                    WriteIndented = true,
                });
                AtomicFile.WriteAllText(_manifestPath, json);
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Error("QuarantineManager", "SaveManifest", ex);
                return false;
            }
        }

        private void SaveManifest()
        {
            if (!TrySaveManifest())
                AppLogger.Warn("QuarantineManager", "SaveManifest ignoré (échec silencieux évité)");
        }

        /// <summary>
        /// Calcule le HMAC-SHA256 sur la sérialisation canonique des entries.
        /// La clé HMAC est dérivée de la clé maîtresse via HKDF (label différent
        /// pour ne pas réutiliser la même clé entre AES-GCM et HMAC).
        /// </summary>
        private byte[] ComputeHmac(List<QuarantineEntry> entries)
        {
            // Dérivation : HMAC-key = HKDF(_masterKey, "optiCombat-manifest-hmac")
            var hmacKey = HKDF.DeriveKey(
                hashAlgorithmName: HashAlgorithmName.SHA256,
                ikm: _masterKey,
                outputLength: 32,
                salt: null,
                info: Encoding.ASCII.GetBytes("optiCombat-manifest-hmac"));

            // Sérialisation canonique : on prend les entries sans le champ Hmac
            // pour éviter la circularité, dans un ordre stable.
            var canonical = JsonSerializer.Serialize(
                entries.OrderBy(e => e.Id, StringComparer.Ordinal).ToList());

            using var hmac = new HMACSHA256(hmacKey);
            var sig = hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical));

            CryptographicOperations.ZeroMemory(hmacKey);
            return sig;
        }

        private static void EnsureDirectoryExists(string dir)
        {
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
        }
    }

    // ── Document persisté ────────────────────────────────────────────────────────

    /// <summary>Container persisté du manifest (versionné + signé).</summary>
    public class QuarantineDocument
    {
        public int Version { get; set; } = 2;

        /// <summary>Signature HMAC-SHA256 base64 du contenu Entries.</summary>
        public string Hmac { get; set; } = string.Empty;

        public List<QuarantineEntry> Entries { get; set; } = new();
    }

    public class QuarantineEntry
    {
        public string Id { get; set; } = string.Empty;
        public string OriginalPath { get; set; } = string.Empty;
        public string QuarantinePath { get; set; } = string.Empty;
        public string VirusName { get; set; } = string.Empty;
        public DateTime QuarantinedAt { get; set; }
        public long OriginalSize { get; set; }

        /// <summary>Hash SHA-256 hex du fichier original (vérifié à la restauration).</summary>
        public string Sha256 { get; set; } = string.Empty;

        /// <summary>Session scan d'origine si connue (traçabilité Historique).</summary>
        public Guid? SourceSessionId { get; set; }

        public string FileName => Path.GetFileName(OriginalPath);
        public string SizeDisplay => OriginalSize >= 0
            ? OriginalSize < 1024 ? $"{OriginalSize} o"
            : OriginalSize < 1048576 ? $"{OriginalSize / 1024.0:F1} Ko"
            : $"{OriginalSize / 1048576.0:F1} Mo"
            : "Inconnu";
    }
}
