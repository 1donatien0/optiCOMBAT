//! pe-analysis — parseur PE basé sur `goblin` (feuille de route §5).
//!
//! Extrait les structures réelles du binaire : table d'imports, sections
//! (nom, characteristics, entropie par section), détection de packer. Ces
//! caractéristiques alimentent directement le moteur heuristique (§4).
//!
//! Robustesse : on complète la table d'imports goblin par un scan de chaînes
//! pour les API surveillées, afin de rester pertinent même si l'IAT est
//! masquée (binaire packé) — cas fréquent pour les injecteurs.

use std::path::Path;

/// Flags de characteristics de section (winnt.h).
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Détail d'une section PE.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub characteristics: u32,
    pub entropy: f64,
    pub virtual_size: u32,
    pub raw_size: u32,
}

impl SectionInfo {
    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }
    pub fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }
    /// Violation W^X : section à la fois exécutable et inscriptible.
    pub fn is_exec_and_writable(&self) -> bool {
        self.is_executable() && self.is_writable()
    }
}

/// Caractéristiques extraites d'un binaire PE, consommées par `heuristics`.
#[derive(Debug, Clone, Default)]
pub struct PeFeatures {
    pub is_pe: bool,
    pub is_64bit: bool,
    pub import_names: Vec<String>,
    pub sections: Vec<SectionInfo>,
    pub max_section_entropy: f64,
    pub has_executable_writable_section: bool,
    pub modified_upx: bool,
    /// Nombre de sections au nom non standard (indice de packer).
    pub nonstandard_section_count: usize,
}

impl PeFeatures {
    pub fn empty() -> Self {
        Self::default()
    }
    /// L'un des imports correspond-il (insensible à la casse) ?
    pub fn imports(&self, api: &str) -> bool {
        self.import_names
            .iter()
            .any(|n| n.eq_ignore_ascii_case(api))
    }
    /// Heuristique RunPE : trio classique du process hollowing.
    pub fn runpe_combo(&self) -> bool {
        self.imports("WriteProcessMemory")
            && (self.imports("SetThreadContext") || self.imports("ResumeThread"))
            && self.imports("VirtualAllocEx")
    }
}

#[derive(Debug)]
pub struct PeError(pub String);
impl std::fmt::Display for PeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for PeError {}

/// Analyse un fichier et renvoie ses caractéristiques PE.
pub fn analyze(path: &Path) -> Result<PeFeatures, PeError> {
    let data = std::fs::read(path).map_err(|e| PeError(e.to_string()))?;
    analyze_bytes(&data)
}

/// Noms de sections standard d'un PE bien formé.
const STANDARD_SECTIONS: &[&str] = &[
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".pdata", ".reloc", ".rsrc", ".tls",
    ".debug", ".CRT", ".gfids", ".didat",
];

/// API surveillées (sous-ensemble de la table heuristique) pour le scan de
/// chaînes de secours quand l'IAT est masquée.
const WATCHED_APIS: &[&str] = &[
    "VirtualAlloc",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "SetThreadContext",
    "ResumeThread",
    "LoadLibraryA",
    "GetProcAddress",
    "WinExec",
    "ShellExecuteA",
    "URLDownloadToFileA",
];

/// Cœur d'analyse (séparé pour les tests sans I/O).
pub fn analyze_bytes(data: &[u8]) -> Result<PeFeatures, PeError> {
    let mut f = PeFeatures::default();
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return Ok(f); // pas un PE → caractéristiques vides, non bloquant.
    }

    // goblin peut échouer sur un PE volontairement malformé : on ne propage
    // pas l'erreur (un malware peut être un PE invalide), on renvoie ce qu'on a.
    let pe = match goblin::pe::PE::parse(data) {
        Ok(pe) => pe,
        Err(_) => {
            // Repli : indices issus du scan de chaînes uniquement.
            f.is_pe = true;
            f.import_names = scan_known_apis(data);
            f.max_section_entropy = shannon_entropy(data);
            return Ok(f);
        }
    };

    f.is_pe = true;
    f.is_64bit = pe.is_64;

    // Imports réels (IAT).
    let mut imports: Vec<String> = pe.imports.iter().map(|i| i.name.to_string()).collect();
    // Union avec le scan de chaînes (IAT masquée / packers).
    for api in scan_known_apis(data) {
        if !imports.iter().any(|n| n.eq_ignore_ascii_case(&api)) {
            imports.push(api);
        }
    }
    f.import_names = imports;

    // Sections réelles : entropie par section + characteristics.
    let mut max_entropy = 0.0f64;
    for s in &pe.sections {
        let name = String::from_utf8_lossy(&s.name)
            .trim_end_matches(['\0', ' '])
            .to_string();
        let start = s.pointer_to_raw_data as usize;
        let size = s.size_of_raw_data as usize;
        let entropy = if start < data.len() {
            let end = (start + size).min(data.len());
            shannon_entropy(&data[start..end])
        } else {
            0.0
        };
        if entropy > max_entropy {
            max_entropy = entropy;
        }
        let info = SectionInfo {
            name: name.clone(),
            characteristics: s.characteristics,
            entropy,
            virtual_size: s.virtual_size,
            raw_size: s.size_of_raw_data,
        };
        if info.is_exec_and_writable() {
            f.has_executable_writable_section = true;
        }
        let std_name = name.is_empty()
            || STANDARD_SECTIONS
                .iter()
                .any(|n| n.eq_ignore_ascii_case(&name));
        if !std_name {
            f.nonstandard_section_count += 1;
        }
        f.sections.push(info);
    }
    f.max_section_entropy = max_entropy;

    // UPX modifié : section UPXx présente mais marqueur usuel absent.
    let has_upx_section = f
        .sections
        .iter()
        .any(|s| s.name.to_ascii_uppercase().starts_with("UPX"));
    let has_upx_marker = window_contains(data, b"$Info: This file is packed with the UPX");
    f.modified_upx = has_upx_section && !has_upx_marker;

    Ok(f)
}

fn scan_known_apis(data: &[u8]) -> Vec<String> {
    WATCHED_APIS
        .iter()
        .filter(|api| window_contains(data, api.as_bytes()))
        .map(|api| (*api).to_string())
        .collect()
}

fn window_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Entropie de Shannon (0..8 bits/octet) — proxy de contenu chiffré/packé.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_pe() {
        let f = analyze_bytes(b"not an executable").unwrap();
        assert!(!f.is_pe);
        assert!(f.import_names.is_empty());
    }

    #[test]
    fn entropie_bornee() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        let uniforme: Vec<u8> = (0..=255u8).collect();
        let h = shannon_entropy(&uniforme);
        assert!((h - 8.0).abs() < 1e-9, "h={h}");
    }

    #[test]
    fn pe_malforme_repli_sur_chaines() {
        // En-tête MZ + PE\0\0 mais structure incomplète → goblin échoue,
        // on doit quand même remonter les API par scan de chaînes.
        let mut data = vec![0u8; 0x40];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C] = 0x40;
        data.extend_from_slice(b"PE\0\0");
        data.extend_from_slice(b"....WriteProcessMemory....VirtualAllocEx....");
        let f = analyze_bytes(&data).unwrap();
        assert!(f.is_pe);
        assert!(f.imports("WriteProcessMemory"));
    }

    #[test]
    fn section_wx() {
        let s = SectionInfo {
            name: ".evil".into(),
            characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE,
            entropy: 7.9,
            virtual_size: 0x1000,
            raw_size: 0x1000,
        };
        assert!(s.is_exec_and_writable());
    }
}
