//! memory-scanner — analyse de la mémoire (architecture : « Memory Scanner »).
//!
//! Scanne un **buffer mémoire** (région d'un processus, dump, charge utile
//! déballée) avec les règles YARA et des indicateurs propres à la mémoire
//! (shellcode, code injecté). La logique de scan est **portable et testable** ;
//! l'énumération des régions d'un processus vivant (`ReadProcessMemory` sous
//! Windows) est la couche plateforme qui alimente ce scanner.

use engine_core::{Detection, EngineError, EngineResult, Severity, Verdict};
use yara_engine::YaraEngine;

/// Région mémoire à analyser (identifiant + octets).
pub struct MemoryRegion<'a> {
    pub label: String,
    pub bytes: &'a [u8],
}

/// Indicateur mémoire : motif d'octets caractéristique de code en mémoire.
struct MemIndicator {
    id: &'static str,
    needle: &'static [u8],
    score: i32,
    why: &'static str,
}

/// Motifs courants de shellcode / staging en mémoire.
const MEM_INDICATORS: &[MemIndicator] = &[
    // Prologue GetPC (récupération de RIP) : CALL $+5 ; POP eax.
    MemIndicator {
        id: "GETPC_CALLPOP",
        needle: &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x58],
        score: 40,
        why: "prologue GetPC (call/pop) typique de shellcode",
    },
    // Marche du PEB via GS (x64) : 65 48 8B (mov rax, gs:[..]).
    MemIndicator {
        id: "PEB_WALK_GS",
        needle: &[0x65, 0x48, 0x8B],
        score: 35,
        why: "accès PEB via GS (résolution d'API en mémoire)",
    },
    // Hachage d'API ROR13 fréquemment précédé de 0x0C 0x0F (heuristique grossière).
    MemIndicator {
        id: "STACK_STRINGS_WINEXEC",
        needle: b"WinExec",
        score: 20,
        why: "chaîne d'API exécutée présente dans la région mémoire",
    },
];

pub struct MemoryScanner {
    yara: YaraEngine,
}

impl MemoryScanner {
    pub fn new() -> Self {
        Self {
            yara: YaraEngine::new(),
        }
    }

    /// Analyse une région mémoire : indicateurs mémoire + règles YARA.
    pub fn scan_region(&self, region: &MemoryRegion) -> EngineResult {
        let mut detections = Vec::new();

        for ind in MEM_INDICATORS {
            if find(region.bytes, ind.needle).is_some() {
                detections.push(Detection {
                    engine: "memory".into(),
                    name: ind.id.into(),
                    score: ind.score,
                    severity: Severity::Major,
                    explanation: format!("[{}] {}", region.label, ind.why),
                });
            }
        }

        // Réutilise le moteur YARA sur le contenu mémoire (mêmes règles).
        for mut d in self.yara.match_bytes(region.bytes) {
            d.explanation = format!("[{}] {}", region.label, d.explanation);
            detections.push(d);
        }

        let verdict = if detections.is_empty() {
            Verdict::Clean
        } else {
            Verdict::Malicious
        };
        EngineResult {
            engine: "memory".into(),
            verdict,
            detections,
            elapsed_ms: 0,
        }
    }

    /// Analyse plusieurs régions et agrège les résultats.
    pub fn scan_regions(&self, regions: &[MemoryRegion]) -> Result<EngineResult, EngineError> {
        let mut detections = Vec::new();
        for r in regions {
            detections.extend(self.scan_region(r).detections);
        }
        let verdict = if detections.is_empty() {
            Verdict::Clean
        } else {
            Verdict::Malicious
        };
        Ok(EngineResult {
            engine: "memory".into(),
            verdict,
            detections,
            elapsed_ms: 0,
        })
    }
}

impl Default for MemoryScanner {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shellcode_getpc_detecte() {
        // CALL $+5 ; POP eax (E8 00000000 58) noyé dans du bruit.
        let mut buf = vec![0x90u8; 16];
        buf.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00, 0x58]);
        buf.extend_from_slice(&[0x90; 8]);
        let region = MemoryRegion {
            label: "pid:1234:0x401000".into(),
            bytes: &buf,
        };
        let r = MemoryScanner::new().scan_region(&region);
        assert_eq!(r.verdict, Verdict::Malicious);
        assert!(r.detections.iter().any(|d| d.name == "GETPC_CALLPOP"));
    }

    #[test]
    fn eicar_en_memoire_via_yara() {
        let data = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let region = MemoryRegion {
            label: "dump".into(),
            bytes: data,
        };
        let r = MemoryScanner::new().scan_region(&region);
        assert!(r.detections.iter().any(|d| d.name == "EICAR_Test"));
    }

    #[test]
    fn memoire_propre() {
        let region = MemoryRegion {
            label: "heap".into(),
            bytes: b"des donnees applicatives parfaitement ordinaires",
        };
        let r = MemoryScanner::new().scan_region(&region);
        assert_eq!(r.verdict, Verdict::Clean);
    }
}
