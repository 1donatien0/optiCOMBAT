/*
 * opticombat.h — interface C ABI stable du cœur moteur optiCombat.
 *
 * Bibliothèque générée : opticombat_engine.dll (Windows) / libopticombat_engine.so (Linux).
 * Contrat de propriété mémoire :
 *   - les chaînes renvoyées par opticombat_scan_json() et
 *     opticombat_threat_intel_stats() doivent être libérées par
 *     opticombat_string_free() (jamais par free()) ;
 *   - opticombat_version() renvoie une chaîne statique : NE PAS libérer.
 *
 * En-tête écrit à la main et maintenu en parallèle de la crate Rust
 * (équivalent à une génération cbindgen, sans dépendance de build).
 */
#ifndef OPTICOMBAT_H
#define OPTICOMBAT_H

#include <stdint.h>

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

/* Charge (ou recharge) les feeds abuse.ch d'un dossier local
 * (malwarebazaar.csv, malwarebazaar_sha256.txt, urlhaus.csv, urlhaus.txt,
 * threatfox.csv) et remplace le dispatcher partagé.
 * Renvoie le nombre d'entrées chargées, ou -1 si le dossier est invalide. */
int64_t opticombat_load_threat_intel(const char *dir);

/* Compteurs de la threat intel chargée, en JSON
 * {"malwarebazaar":N,"urlhaus":N,"threatfox":N,"total":N}.
 * À libérer avec opticombat_string_free(). */
char *opticombat_threat_intel_stats(void);

/* Libère une chaîne renvoyée par cette bibliothèque. */
void opticombat_string_free(char *s);

/* Version de la bibliothèque (chaîne statique, NE PAS libérer). */
const char *opticombat_version(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* OPTICOMBAT_H */
