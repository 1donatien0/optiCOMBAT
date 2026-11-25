# Politique de confidentialité — optiCombat

**Dernière mise à jour :** 30 septembre 2026  
**Éditeur :** Dona By — optiCombat (édition ClamAV)

Ce document décrit comment optiCombat traite vos données. Il complète la licence GNU GPL v3 ([LICENSE.txt](../LICENSE.txt)) et la note interne [CONFORMITE_RGPD.md](CONFORMITE_RGPD.md). Ce n'est pas un avis juridique.

---

## 1. Principe général

optiCombat est conçu pour fonctionner **localement sur votre ordinateur**. Par défaut, **aucune donnée personnelle n'est collectée, vendue ou transmise** à l'éditeur.

---

## 2. Données stockées sur votre poste

| Donnée | Emplacement | Durée |
|--------|-------------|-------|
| Historique des analyses (chiffré) | `%LOCALAPPDATA%\optiCombat` | Rotation automatique ou suppression par vous |
| Fichiers en quarantaine (chiffrés AES-GCM) | `%LOCALAPPDATA%\optiCombat\Quarantine` | Jusqu'à suppression par vous |
| Exclusions (chiffrées) | `%LOCALAPPDATA%\optiCombat` | Idem |
| Préférences, dont votre clé VirusTotal (chiffrées) | `%APPDATA%\optiCombat` | Idem |
| Copies de sécurité avant quarantaine — **uniquement si vous activez l'option** | `%LOCALAPPDATA%\optiCombat\SafetyBackups` | Idem |
| Rapports PDF | `%LOCALAPPDATA%\optiCombat\Reports` | Idem |
| Journaux applicatifs | `%LOCALAPPDATA%\optiCombat\Logs` | **30 jours** (rotation automatique) ; journal de plantage limité à 1 Mo |

- Les chemins de fichiers dans les journaux sont **caviardés** pour limiter l'exposition d'informations identifiables.
- La quarantaine est chiffrée ; la clé est protégée par DPAPI (portée utilisateur Windows).

**Ces données ne quittent pas votre machine**, sauf si vous les exportez vous-même (rapports HTML/PDF) ou les copiez manuellement.

---

## 3. Connexions réseau

### 3.1 Mises à jour de signatures (par défaut)

- **ClamAV** : téléchargement des bases antivirus depuis les serveurs officiels.
- **Règles YARA** : téléchargement depuis GitHub (YARA-Forge).

Aucune information personnelle identifiable n'est envoyée ; seuls des téléchargements de fichiers publics sont effectués.

### 3.1 bis Mises à jour de logiciels et installation

- L'onglet **Optimiser → Mises à jour** utilise `winget` (outil Microsoft), **uniquement quand vous le lancez** ; il contacte les sources de Microsoft selon leurs propres conditions.
- L'installateur est **autonome** (*self-contained*) : le runtime .NET est embarqué dans optiCombat, l'installation ne télécharge donc aucun composant d'exécution.

### 3.2 VirusTotal — **désactivé par défaut (opt-in)**

Si vous saisissez **votre propre clé API VirusTotal** dans les options :

- optiCombat envoie uniquement le **hash SHA-256** d'un fichier (jamais le fichier complet) à `virustotal.com`.
- Ce traitement est soumis à la [politique de confidentialité de VirusTotal](https://www.virustotal.com/gui/privacy-policy).
- Des transferts hors de l'Union européenne peuvent s'appliquer si vous utilisez cette fonction.

Sans clé API, **aucune requête VirusTotal** n'est émise.

---

## 4. Ce que optiCombat ne fait pas

- Pas de télémétrie d'usage vers l'éditeur.
- Pas de publicité ni de profilage.
- Pas de compte utilisateur obligatoire.
- Pas de vente de données.

---

## 5. Vos droits et choix

Vous pouvez à tout moment :

- Supprimer vos données locales en désinstallant optiCombat (l'assistant propose la purge) ou en supprimant `%LOCALAPPDATA%\optiCombat` et `%APPDATA%\optiCombat`.
- Retirer votre clé VirusTotal pour stopper tout envoi de hash.
- Désactiver les mises à jour automatiques dans les options.

Pour toute question : [page SourceForge de l'auteur](https://sourceforge.net/u/donaby).

---

## 6. Modifications

Cette politique peut être mise à jour lors des versions majeures du logiciel. La date en tête de document indique la dernière révision.
