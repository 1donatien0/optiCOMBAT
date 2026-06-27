/*
 * opticombat.h — interface C ABI stable du cœur moteur optiCombat.
 *
 * Bibliothèque générée : opticombat.dll (Windows) / libopticombat.so (Linux).
 * Contrat de propriété mémoire :
 *   - les chaînes renvoyées par opticombat_scan_json() doivent être libérées
 *     par opticombat_string_free() (jamais par free()) ;
 *   - opticombat_version() renvoie une chaîne statique : NE PAS libérer.
 *
 * En-tête écrit à la main et maintenu en parallèle de la crate Rust
 * (équivalent à une génération cbindgen, sans dépendance de build).
 */
#ifndef OPTICOMBAT_H
#define OPTICOMBAT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Codes de verdict (identiques aux codes de sortie de la CLI). */
#define OC_CLEAN       0
#define OC_SUSPICIOUS  1
#define OC_MALICIOUS   2
#define OC_ERROR      (-1)

/* Scanne un fichier ; renvoie un code OC_* ci-dessus. */
int opticombat_scan_path(const char *path);

/* Scanne un fichier ; renvoie un JSON explicable (verdict, score, détections).
 * À libérer avec opticombat_string_free(). NULL en cas d'erreur. */
char *opticombat_scan_json(const char *path);

/* Libère une chaîne renvoyée par cette bibliothèque. */
void opticombat_string_free(char *s);

/* Version de la bibliothèque (chaîne statique, NE PAS libérer). */
const char *opticombat_version(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* OPTICOMBAT_H */
