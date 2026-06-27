//! sandbox — analyse comportementale légère (feuille de route §6).
//!
//! État actuel : scoring statique sur chaînes/API et séquences ordonnées.
//! Prochaine profondeur : émulation dynamique légère (hooks API simulés,
//! chronologie temporelle) — voir PLAN_TRANSITION_optiCombat.md § Phase 4+.
//!
//! Sans machine virtuelle complète : on relève les **indicateurs de
//! comportement** présents dans la cible (appels d'API, séquences) et on en
//! déduit un **score comportemental**. La feuille de route décrit la chaîne
//! CreateFile → WriteFile → RegCreateKey → WinInet/WinHTTP → Powershell →
//! cmd.exe → WMI ; on la modélise par des indicateurs pondérés et des
//! **combinaisons ordonnées** (ex. téléchargement *avant* exécution).
//!
//! Périmètre actuel : extraction statique des indicateurs (rapide, sûr). La
//! cible §6 est une émulation d'API en bac à sable ; l'interface (score
//! comportemental normalisé) est déjà celle qu'un émulateur alimenterait.

use engine_core::{
    Detection, Engine, EngineError, EngineResult, FileKind, ScanContext, Severity, Verdict,
};

/// Indicateur comportemental unitaire : présence d'un motif d'API.
struct Indicator {
    id: &'static str,
    needle: &'static [u8],
    weight: i32,
    why: &'static str,
}

/// Indicateurs unitaires (chaîne d'API de la feuille de route + persistance).
const INDICATORS: &[Indicator] = &[
    Indicator {
        id: "FS_WRITE",
        needle: b"WriteFile",
        weight: 5,
        why: "écriture fichier (WriteFile)",
    },
    Indicator {
        id: "REG_PERSIST",
        needle: b"RegCreateKey",
        weight: 15,
        why: "création de clé de registre (persistance)",
    },
    Indicator {
        id: "RUN_KEY",
        needle: b"CurrentVersion\\Run",
        weight: 25,
        why: "clé d'auto-démarrage (Run)",
    },
    Indicator {
        id: "NET_WININET",
        needle: b"WinInet",
        weight: 15,
        why: "accès réseau (WinInet)",
    },
    Indicator {
        id: "NET_WINHTTP",
        needle: b"WinHttp",
        weight: 15,
        why: "accès réseau (WinHTTP)",
    },
    Indicator {
        id: "NET_URLDL",
        needle: b"URLDownloadToFile",
        weight: 25,
        why: "téléchargement de fichier (URLDownloadToFile)",
    },
    Indicator {
        id: "EXEC_POWERSHELL",
        needle: b"powershell",
        weight: 20,
        why: "lancement de PowerShell",
    },
    Indicator {
        id: "EXEC_CMD",
        needle: b"cmd.exe",
        weight: 15,
        why: "lancement de cmd.exe",
    },
    Indicator {
        id: "EXEC_WMI",
        needle: b"winmgmts:",
        weight: 20,
        why: "exécution via WMI",
    },
    Indicator {
        id: "SHELL_EXEC",
        needle: b"ShellExecute",
        weight: 15,
        why: "exécution de processus (ShellExecute)",
    },
    Indicator {
        id: "INJECT_ALLOC",
        needle: b"VirtualAllocEx",
        weight: 20,
        why: "allocation mémoire distante (injection)",
    },
    Indicator {
        id: "INJECT_WRITE",
        needle: b"WriteProcessMemory",
        weight: 25,
        why: "écriture mémoire distante (injection)",
    },
    Indicator {
        id: "INJECT_THREAD",
        needle: b"CreateRemoteThread",
        weight: 30,
        why: "création de thread distant (injection)",
    },
];

/// Marqueurs « téléchargement » et « exécution » pour la combinaison ordonnée.
const DOWNLOAD_MARKERS: &[&[u8]] = &[
    b"URLDownloadToFile",
    b"WinInet",
    b"WinHttp",
    b"DownloadString",
];
const EXEC_MARKERS: &[&[u8]] = &[
    b"ShellExecute",
    b"WinExec",
    b"CreateProcess",
    b"powershell",
    b"cmd.exe",
];
const INJECTION_MARKERS: &[&[u8]] = &[
    b"VirtualAllocEx",
    b"WriteProcessMemory",
    b"CreateRemoteThread",
];

/// Événement comportemental ordonné (émulation statique légère).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BehaviorEvent {
    pub id: &'static str,
    pub offset: usize,
}

/// Extrait une chronologie d'indicateurs dans l'ordre d'apparition.
pub fn behavior_timeline(data: &[u8]) -> Vec<BehaviorEvent> {
    let mut events = Vec::new();
    for ind in INDICATORS {
        if let Some(offset) = find(data, ind.needle) {
            events.push(BehaviorEvent {
                id: ind.id,
                offset,
            });
        }
    }
    events.sort_by_key(|e| e.offset);
    events
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BehaviorBand {
    Benign,
    Suspicious,
    Malicious,
}

/// Classe un score comportemental (mêmes seuils que l'heuristique).
pub fn band(score: i32) -> BehaviorBand {
    if score >= 80 {
        BehaviorBand::Malicious
    } else if score >= 40 {
        BehaviorBand::Suspicious
    } else {
        BehaviorBand::Benign
    }
}

pub struct Sandbox;

impl Sandbox {
    pub fn new() -> Self {
        Self
    }

    /// Calcule le score comportemental et les détections sur un buffer.
    pub fn analyze(&self, data: &[u8]) -> (i32, Vec<Detection>) {
        let mut score = 0;
        let mut dets = Vec::new();
        for ind in INDICATORS {
            if find(data, ind.needle).is_some() {
                score += ind.weight;
                dets.push(Detection {
                    engine: "sandbox".into(),
                    name: ind.id.into(),
                    score: ind.weight,
                    severity: Severity::Informational,
                    explanation: ind.why.into(),
                });
            }
        }
        // Combinaison ordonnée : téléchargement PUIS exécution → forte intention.
        if let (Some(dl), Some(ex)) = (
            first_of(data, DOWNLOAD_MARKERS),
            first_of(data, EXEC_MARKERS),
        ) {
            if dl < ex {
                score += 30;
                dets.push(Detection {
                    engine: "sandbox".into(),
                    name: "SEQ_DOWNLOAD_EXEC".into(),
                    score: 30,
                    severity: Severity::Major,
                    explanation: "séquence téléchargement → exécution".into(),
                });
            }
        }
        if ordered_sequence(data, INJECTION_MARKERS) {
            score += 35;
            dets.push(Detection {
                engine: "sandbox".into(),
                name: "SEQ_INJECT_EXEC".into(),
                score: 35,
                severity: Severity::Major,
                explanation: "séquence injection processus (alloc → write → thread)".into(),
            });
        }
        (score, dets)
    }
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::new()
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Offset de la première occurrence d'un des marqueurs.
fn first_of(data: &[u8], markers: &[&[u8]]) -> Option<usize> {
    markers.iter().filter_map(|m| find(data, m)).min()
}

/// Vérifie qu'une série de marqueurs apparaît dans l'ordre (émulation statique).
fn ordered_sequence(data: &[u8], markers: &[&[u8]]) -> bool {
    let mut last = 0usize;
    for marker in markers {
        let Some(rel) = find(&data[last..], marker) else {
            return false;
        };
        last = last.saturating_add(rel).saturating_add(marker.len());
    }
    true
}

impl Engine for Sandbox {
    fn name(&self) -> &str {
        "sandbox"
    }

    fn applicable(&self, ctx: &ScanContext) -> bool {
        matches!(
            ctx.kind,
            FileKind::PortableExecutable | FileKind::Script | FileKind::OfficeDocument
        )
    }

    fn scan(&self, ctx: &ScanContext) -> Result<EngineResult, EngineError> {
        let data = std::fs::read(&ctx.path)?;
        let (score, dets) = self.analyze(&data);
        let verdict = match band(score) {
            BehaviorBand::Benign => Verdict::Clean,
            BehaviorBand::Suspicious => Verdict::Suspicious,
            BehaviorBand::Malicious => Verdict::Malicious,
        };
        let mut detections = dets;
        if score > 0 {
            detections.insert(
                0,
                Detection {
                    engine: "sandbox".into(),
                    name: format!("BEHAVIOR_SCORE_{score}"),
                    score: 0, // chapeau : la somme est portée par les indicateurs individuels
                    severity: if score >= 80 {
                        Severity::Major
                    } else if score >= 40 {
                        Severity::Minor
                    } else {
                        Severity::Informational
                    },
                    explanation: format!("Score comportemental {score} → {:?}", band(score)),
                },
            );
        }
        Ok(EngineResult {
            engine: "sandbox".into(),
            verdict,
            detections,
            elapsed_ms: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telechargement_puis_execution() {
        // URLDownloadToFile apparaît avant ShellExecute → séquence + indicateurs.
        let data = b"...URLDownloadToFile... puis ...ShellExecute... cmd.exe";
        let (score, dets) = Sandbox::new().analyze(data);
        assert!(score >= 80, "score={score}");
        assert!(dets.iter().any(|d| d.name == "SEQ_DOWNLOAD_EXEC"));
        assert_eq!(band(score), BehaviorBand::Malicious);
    }

    #[test]
    fn persistance_registre() {
        let data = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run RegCreateKey";
        let (score, _) = Sandbox::new().analyze(data);
        assert!(score >= 40, "score={score}");
    }

    #[test]
    fn contenu_benin() {
        let (score, dets) = Sandbox::new().analyze(b"document de traitement de texte ordinaire");
        assert_eq!(score, 0);
        assert!(dets.is_empty());
        assert_eq!(band(score), BehaviorBand::Benign);
    }

    #[test]
    fn injection_sequence() {
        let data = b"VirtualAllocEx ... WriteProcessMemory ... CreateRemoteThread";
        let (score, dets) = Sandbox::new().analyze(data);
        assert!(score >= 80, "score={score}");
        assert!(dets.iter().any(|d| d.name == "SEQ_INJECT_EXEC"));
        let timeline = behavior_timeline(data);
        assert!(timeline.len() >= 3);
    }
}
