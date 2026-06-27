# Conformité RGPD / vie privée — optiCOMBAT

Note d'analyse des traitements de données d'optiCOMBAT, destinée à préparer une politique de confidentialité pour une diffusion (notamment en Europe). Ce n'est pas un avis juridique.

---

## 1. Données traitées localement (jamais transmises)

| Donnée | Où | Rétention |
|---|---|---|
| Historique de scans | `%LOCALAPPDATA%\optiCombat` | Jusqu'à suppression par l'utilisateur |
| Fichiers en quarantaine | `%LOCALAPPDATA%\optiCombat` (chiffrés AES‑GCM) | Idem |
| Préférences / exclusions | `%LOCALAPPDATA%\optiCombat` | Idem |
| Journaux applicatifs | `%LOCALAPPDATA%\optiCombat\Logs` | **30 jours** (rotation auto) |

- Les **chemins de fichiers** dans les journaux sont **caviardés** (`PathRedaction`) pour limiter l'exposition de données personnelles (noms d'utilisateur, etc.).
- La quarantaine est **chiffrée** (clé AES‑GCM enveloppée par DPAPI, portée utilisateur).

Aucune de ces données ne quitte le poste.

## 2. Données transmises à des tiers

### VirusTotal (réputation de menaces) — **opt-in**

- **Ce qui est envoyé** : uniquement le **hash SHA‑256** d'un fichier (jamais le fichier lui‑même), via `GET https://www.virustotal.com/api/v3/files/{hash}`.
- **Condition** : uniquement si l'utilisateur a saisi **sa propre clé API VirusTotal**. Sans clé, aucune requête n'est émise.
- **Donnée personnelle ?** Un hash de fichier n'est normalement pas une donnée personnelle, mais il est transmis à un tiers (Google/VirusTotal) soumis à ses propres conditions.
- **Recommandation** : mentionner ce traitement dans la politique de confidentialité, indiquer qu'il est **désactivé par défaut**, et lier la politique de VirusTotal.

### Mises à jour de signatures (ClamAV/YARA)

- `freshclam` et le téléchargement des règles contactent les serveurs de signatures (téléchargement de bases publiques). Pas d'envoi de données utilisateur ; échange réseau standard de mise à jour.

## 3. Points à formaliser pour le RGPD

1. **Politique de confidentialité** publiée et accessible (dans l'app + site).
2. **Base légale** : intérêt légitime (sécurité) pour le fonctionnement local ; **consentement** explicite pour l'envoi de hash à VirusTotal (déjà opt-in via saisie de clé).
3. **Minimisation** : confirmée (hash seul, pas de fichier ; logs caviardés ; rétention 30 j).
4. **Droits** : l'utilisateur peut supprimer toutes ses données (la désinstallation propose explicitement la purge ; suppression manuelle possible dans `%LOCALAPPDATA%\optiCombat`).
5. **Transferts hors UE** : VirusTotal (États‑Unis) — à mentionner si la fonction est utilisée.
6. **Pas de télémétrie** tierce intrusive détectée — à confirmer et à déclarer (« optiCOMBAT ne collecte pas de télémétrie d'usage »).

## 4. Verdict

Le design est **respectueux de la vie privée** : traitement local par défaut, chiffrement de la quarantaine, caviardage des logs, rétention bornée, et le seul envoi externe (hash VirusTotal) est **opt-in**. Le principal travail restant est **documentaire** (politique de confidentialité + mention du traitement VirusTotal), pas technique.
