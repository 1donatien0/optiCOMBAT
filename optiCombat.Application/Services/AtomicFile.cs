using System.IO;
using System.Text;

namespace optiCombat.Services
{
    /// <summary>
    /// Écritures atomiques : tempfile + rename + .bak.
    ///
    /// Pourquoi : <see cref="File.WriteAllText(string, string)"/> n'est pas atomique.
    /// Si le process crashe en cours d'écriture, le fichier final est tronqué et
    /// inutilisable. Lors du chargement suivant, le code retournera silencieusement
    /// une liste vide → perte totale de l'historique de quarantaine, des préférences,
    /// ou de l'historique des scans.
    ///
    /// Cette classe utilise le pattern recommandé pour Windows :
    ///   1. Écriture des nouvelles données dans <c>target.tmp</c>
    ///   2. Flush + close
    ///   3. <see cref="File.Replace(string, string, string?)"/> qui :
    ///        - garantit le renommage atomique (NTFS)
    ///        - sauvegarde l'ancienne version dans <c>target.bak</c>
    ///   4. Si <see cref="File.Replace"/> n'est pas disponible (premier write),
    ///      repli sur <see cref="File.Move"/>.
    /// </summary>
    public static class AtomicFile
    {
        /// <summary>Écrit le texte donné de manière atomique en UTF-8 sans BOM.</summary>
        public static void WriteAllText(string path, string content)
        {
            // UTF-8 sans BOM par défaut — évite les soucis avec parseurs stricts
            // (cf. bug freshclam.conf historique).
            var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
            WriteAllBytes(path, encoding.GetBytes(content));
        }

        /// <summary>Écrit le texte donné avec un encoding explicite, de manière atomique.</summary>
        public static void WriteAllText(string path, string content, Encoding encoding)
        {
            WriteAllBytes(path, encoding.GetBytes(content));
        }

        /// <summary>Écrit le buffer donné de manière atomique.</summary>
        public static void WriteAllBytes(string path, byte[] bytes)
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            var tmp = path + ".tmp";
            var bak = path + ".bak";

            // 1. Écriture dans le fichier temporaire (jamais directement dans la cible).
            //    FileShare.None pour éviter qu'un autre process lise un fichier partiel.
            using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                fs.Write(bytes, 0, bytes.Length);
                fs.Flush(flushToDisk: true); // force le flush vers le disque physique
            }

            try
            {
                if (File.Exists(path))
                {
                    // 2a. File.Replace : renommage atomique avec sauvegarde de l'ancien.
                    //     Ignore les éventuelles erreurs de permission sur le .bak
                    //     (3ème argument = backupFileName, null = pas de backup).
                    File.Replace(tmp, path, bak, ignoreMetadataErrors: true);
                }
                else
                {
                    // 2b. Premier write : pas de cible existante, simple Move.
                    File.Move(tmp, path);
                }
            }
            catch
            {
                // En cas d'échec du renommage, on tente un cleanup du tmp pour ne
                // pas laisser de fichier orphelin, puis on relève l'exception au
                // caller pour qu'il puisse la logger.
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { /* approche prudente */ }
                throw;
            }
        }

        /// <summary>
        /// Lit un fichier en tentant la version courante, puis le .bak en repli
        /// si la version courante est corrompue ou inexistante.
        ///
        /// <paramref name="parser"/> doit lever une exception si le contenu est
        /// invalide — c'est le signal pour basculer sur le .bak.
        /// </summary>
        public static T ReadWithBackup<T>(string path, Func<string, T> parser, T fallbackValue)
        {
            // Tentative 1 : fichier principal
            if (File.Exists(path))
            {
                try { return parser(File.ReadAllText(path)); }
                catch (Exception ex)
                {
                    AppLogger.Warn("AtomicFile", $"Parse principal échoué ({path}), tentative .bak", ex);
                }
            }

            // Tentative 2 : sauvegarde
            var bak = path + ".bak";
            if (File.Exists(bak))
            {
                try { return parser(File.ReadAllText(bak)); }
                catch (Exception ex)
                {
                    AppLogger.Warn("AtomicFile", $"Parse .bak échoué ({bak})", ex);
                }
            }

            return fallbackValue;
        }
    }
}
