//! pe-analysis — parseur PE basé sur `goblin` (feuille de route §5).
//!
//! Extrait les structures réelles du binaire : table d'imports, sections
//! (nom, characteristics, entropie par section), détection de packer. Ces
//! caractéristiques alimentent directement le moteur heuristique (§4).
//!
//! Robustesse : on complète la table d'imports goblin par un scan de chaînes
//! pour les API surveillées, afin de rester pertinent même si l'IAT est
//! masquée (binaire packé) — cas fréquent pour les injecteurs.

use engine_core::{masked, unmask_bytes};
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
    /// Variante de [`PeFeatures::imports`] pour un nom d'API stocké masqué.
    pub fn imports_masked(&self, masked_api: &[u8]) -> bool {
        let api = unmask_bytes(masked_api);
        self.import_names
            .iter()
            .any(|n| n.as_bytes().eq_ignore_ascii_case(&api))
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
/// Inclut les sections émises par MSVC récents (`.00cfg`, `_RDATA`, `.voltbl`,
/// `.fptable`, `.retplne`…) et par MinGW/GCC : leur absence faisait compter
/// `vcruntime140.dll` comme « packé » (audit 360).
const STANDARD_SECTIONS: &[&str] = &[
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".pdata", ".reloc", ".rsrc", ".tls",
    ".debug", ".CRT", ".gfids", ".didat", ".00cfg", "_RDATA", ".voltbl", ".fptable", ".retplne",
    ".gehcont", ".giats", ".gljmp", ".xdata", ".rodata", ".eh_fram", ".buildid", ".hexpthk",
    ".a64xrm", ".textbss", ".msvcjmc", ".nep", ".wpp_sf", "PAGE", "INIT", ".sdata",
];

/// Section au nom standard (MinGW écrit les noms longs sous la forme `/4`, `/19`…).
fn is_standard_section(name: &str) -> bool {
    name.is_empty()
        || STANDARD_SECTIONS
            .iter()
            .any(|n| n.eq_ignore_ascii_case(name))
        || (name.starts_with('/') && name[1..].chars().all(|c| c.is_ascii_digit()))
}

/// En dessous de ce nombre d'imports, l'IAT est considérée comme masquée.
const MIN_NORMAL_IAT_IMPORTS: usize = 8;

/// API surveillées (sous-ensemble de la table heuristique) pour le scan de
/// chaînes de secours quand l'IAT est masquée.
/// Stockées masquées (voir `engine_core::masked!`) pour ne pas apparaître en
/// clair dans `opticombat_engine.dll`.
const WATCHED_APIS: &[&[u8]] = &[
    masked!(b"VirtualAlloc"),
    masked!(b"VirtualAllocEx"),
    masked!(b"WriteProcessMemory"),
    masked!(b"CreateRemoteThread"),
    masked!(b"SetThreadContext"),
    masked!(b"ResumeThread"),
    masked!(b"LoadLibraryA"),
    masked!(b"GetProcAddress"),
    masked!(b"WinExec"),
    masked!(b"ShellExecuteA"),
    masked!(b"URLDownloadToFileA"),
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
    // Union avec le scan de chaînes seulement si l'IAT semble masquée (packer :
    // une poignée d'imports). Sur un binaire à IAT normale, le simple texte
    // « WriteProcessMemory » (débogueurs, antivirus, documentation embarquée)
    // était compté comme un import réel (audit 360).
    if imports.len() < MIN_NORMAL_IAT_IMPORTS {
        for api in scan_known_apis(data) {
            if !imports.iter().any(|n| n.eq_ignore_ascii_case(&api)) {
                imports.push(api);
            }
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
        if !is_standard_section(&name) {
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
        .map(|masked_api| unmask_bytes(masked_api))
        .filter(|api| window_contains(data, api))
        .map(|api| String::from_utf8_lossy(&api).into_owned())
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

/// Générateur de PE minimaux valides, pour les tests des crates du moteur
/// (aucun binaire réel n'est versionné dans le dépôt).
pub mod fixtures {
    /// Section à placer dans le PE généré.
    pub struct FixtureSection<'a> {
        pub name: &'a str,
        pub characteristics: u32,
        pub data: &'a [u8],
    }

    /// Caractéristiques usuelles.
    pub const CODE: u32 = 0x6000_0020; // CNT_CODE | MEM_EXECUTE | MEM_READ
    pub const DATA: u32 = 0xC000_0040; // INITIALIZED_DATA | MEM_READ | MEM_WRITE
    pub const RWX: u32 = 0xE000_0020; // CODE | EXECUTE | READ | WRITE

    const FILE_ALIGN: usize = 0x200;
    const SECT_ALIGN: u32 = 0x1000;

    fn align(v: usize, a: usize) -> usize {
        v.div_ceil(a) * a
    }

    /// Construit un PE32 (x86) ou PE32+ (x64) sans imports, avec les sections données,
    /// suivies de `overlay` (octets bruts après la dernière section).
    pub fn build_pe(sections: &[FixtureSection<'_>], pe64: bool, overlay: &[u8]) -> Vec<u8> {
        let opt_size: usize = if pe64 { 0xF0 } else { 0xE0 };
        let e_lfanew = 0x80usize;
        let headers_len = e_lfanew + 4 + 20 + opt_size + 40 * sections.len();
        let size_of_headers = align(headers_len, FILE_ALIGN);

        let mut raw_offsets = Vec::new();
        let mut cursor = size_of_headers;
        for s in sections {
            raw_offsets.push(cursor);
            cursor += align(s.data.len().max(1), FILE_ALIGN);
        }
        let image_size = SECT_ALIGN as usize * (1 + sections.len()) + SECT_ALIGN as usize;

        let mut out = vec![0u8; cursor];
        out[0] = b'M';
        out[1] = b'Z';
        out[0x3C..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
        let mut p = e_lfanew;
        out[p..p + 4].copy_from_slice(b"PE\0\0");
        p += 4;
        // COFF
        let machine: u16 = if pe64 { 0x8664 } else { 0x014c };
        out[p..p + 2].copy_from_slice(&machine.to_le_bytes());
        out[p + 2..p + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        out[p + 16..p + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        out[p + 18..p + 20].copy_from_slice(&0x0102u16.to_le_bytes()); // EXECUTABLE | 32BIT
        p += 20;
        // Optional header
        let o = p;
        out[o..o + 2].copy_from_slice(&(if pe64 { 0x20bu16 } else { 0x10bu16 }).to_le_bytes());
        out[o + 16..o + 20].copy_from_slice(&SECT_ALIGN.to_le_bytes()); // AddressOfEntryPoint
        out[o + 20..o + 24].copy_from_slice(&SECT_ALIGN.to_le_bytes()); // BaseOfCode
        let (img_base_off, rest) = if pe64 {
            (24usize, 32usize)
        } else {
            (28usize, 32usize)
        };
        if pe64 {
            out[o + img_base_off..o + img_base_off + 8]
                .copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        } else {
            out[o + 24..o + 28].copy_from_slice(&(2 * SECT_ALIGN).to_le_bytes()); // BaseOfData
            out[o + img_base_off..o + img_base_off + 4]
                .copy_from_slice(&0x0040_0000u32.to_le_bytes());
        }
        out[o + rest..o + rest + 4].copy_from_slice(&SECT_ALIGN.to_le_bytes());
        out[o + rest + 4..o + rest + 8].copy_from_slice(&(FILE_ALIGN as u32).to_le_bytes());
        out[o + 40..o + 42].copy_from_slice(&6u16.to_le_bytes()); // MajorOSVersion
        out[o + 48..o + 50].copy_from_slice(&6u16.to_le_bytes()); // MajorSubsystemVersion
        out[o + 56..o + 60].copy_from_slice(&(image_size as u32).to_le_bytes());
        out[o + 60..o + 64].copy_from_slice(&(size_of_headers as u32).to_le_bytes());
        out[o + 68..o + 70].copy_from_slice(&3u16.to_le_bytes()); // CUI
        let nrva_off = if pe64 { 108 } else { 92 };
        out[o + nrva_off..o + nrva_off + 4].copy_from_slice(&16u32.to_le_bytes());
        p += opt_size;
        // Section headers
        for (i, s) in sections.iter().enumerate() {
            let h = p + 40 * i;
            let name = s.name.as_bytes();
            out[h..h + name.len().min(8)].copy_from_slice(&name[..name.len().min(8)]);
            let va = SECT_ALIGN * (1 + i as u32);
            out[h + 8..h + 12].copy_from_slice(&(s.data.len().max(1) as u32).to_le_bytes());
            out[h + 12..h + 16].copy_from_slice(&va.to_le_bytes());
            let raw = align(s.data.len().max(1), FILE_ALIGN) as u32;
            out[h + 16..h + 20].copy_from_slice(&raw.to_le_bytes());
            out[h + 20..h + 24].copy_from_slice(&(raw_offsets[i] as u32).to_le_bytes());
            out[h + 36..h + 40].copy_from_slice(&s.characteristics.to_le_bytes());
            out[raw_offsets[i]..raw_offsets[i] + s.data.len()].copy_from_slice(s.data);
        }
        out.extend_from_slice(overlay);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{build_pe, FixtureSection, CODE, DATA, RWX};
    use super::*;

    #[test]
    fn pe32_valide_analyse_par_goblin() {
        let code = [0x90u8; 64];
        let data = b"donnees ordinaires";
        let pe = build_pe(
            &[
                FixtureSection {
                    name: ".text",
                    characteristics: CODE,
                    data: &code,
                },
                FixtureSection {
                    name: ".data",
                    characteristics: DATA,
                    data,
                },
            ],
            false,
            b"",
        );
        assert!(
            goblin::pe::PE::parse(&pe).is_ok(),
            "fixture refusée par goblin"
        );
        let f = analyze_bytes(&pe).unwrap();
        assert!(f.is_pe);
        assert!(!f.is_64bit);
        assert_eq!(f.sections.len(), 2);
        assert_eq!(f.sections[0].name, ".text");
        assert!(f.sections[0].is_executable());
        assert!(!f.sections[0].is_writable());
        assert!(f.sections[1].is_writable());
        assert!(!f.has_executable_writable_section);
        assert_eq!(f.nonstandard_section_count, 0);
        assert!(!f.modified_upx);
        assert!(f.max_section_entropy >= 0.0);
    }

    #[test]
    fn pe64_section_rwx_et_noms_non_standard() {
        let noisy: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let pe = build_pe(
            &[
                FixtureSection {
                    name: "UPX0",
                    characteristics: RWX,
                    data: &noisy,
                },
                FixtureSection {
                    name: ".zz",
                    characteristics: DATA,
                    data: b"x",
                },
                FixtureSection {
                    name: "/4",
                    characteristics: DATA,
                    data: b"y",
                },
            ],
            true,
            b"",
        );
        let f = analyze_bytes(&pe).unwrap();
        assert!(f.is_64bit);
        assert!(f.has_executable_writable_section);
        assert_eq!(f.nonstandard_section_count, 2, "{:?}", f.sections);
        assert!(f.modified_upx, "UPX sans marqueur = UPX modifié");
        assert!(f.max_section_entropy > 7.0, "{}", f.max_section_entropy);
    }

    #[test]
    fn upx_avec_marqueur_n_est_pas_modifie() {
        let pe = build_pe(
            &[FixtureSection {
                name: "UPX1",
                characteristics: CODE,
                data: b"code",
            }],
            false,
            b"$Info: This file is packed with the UPX executable packer",
        );
        assert!(!analyze_bytes(&pe).unwrap().modified_upx);
    }

    #[test]
    fn iat_vide_completee_par_le_scan_de_chaines() {
        let pe = build_pe(
            &[FixtureSection {
                name: ".rdata",
                characteristics: DATA,
                data: b"..VirtualAllocEx..WriteProcessMemory..CreateRemoteThread..",
            }],
            false,
            b"",
        );
        let f = analyze_bytes(&pe).unwrap();
        assert!(f.imports("VirtualAllocEx"));
        assert!(
            f.imports("writeprocessmemory"),
            "comparaison insensible à la casse"
        );
        assert!(!f.runpe_combo(), "sans SetThreadContext/ResumeThread");
    }

    #[test]
    fn analyze_lit_le_fichier_et_signale_l_erreur_d_io() {
        let p = std::env::temp_dir().join(format!("oc_pe_{}.exe", std::process::id()));
        std::fs::write(
            &p,
            build_pe(
                &[FixtureSection {
                    name: ".text",
                    characteristics: CODE,
                    data: b"c",
                }],
                false,
                b"",
            ),
        )
        .unwrap();
        assert!(analyze(&p).unwrap().is_pe);
        let _ = std::fs::remove_file(&p);
        let err = analyze(Path::new("/oc/absent.exe")).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn section_hors_fichier_a_une_entropie_nulle() {
        let mut pe = build_pe(
            &[FixtureSection {
                name: ".text",
                characteristics: CODE,
                data: b"c",
            }],
            false,
            b"",
        );
        // PointerToRawData de la première section → au-delà de la fin du fichier.
        let sh = 0x80 + 4 + 20 + 0xE0;
        pe[sh + 20..sh + 24].copy_from_slice(&0x00FF_0000u32.to_le_bytes());
        if let Ok(f) = analyze_bytes(&pe) {
            if let Some(s) = f.sections.first() {
                assert_eq!(s.entropy, 0.0);
            }
        }
    }

    #[test]
    fn imports_masques_et_runpe() {
        let f = PeFeatures {
            import_names: vec![
                "WriteProcessMemory".into(),
                "ResumeThread".into(),
                "VirtualAllocEx".into(),
            ],
            ..PeFeatures::empty()
        };
        assert!(f.runpe_combo());
        assert!(f.imports_masked(masked!(b"VirtualAllocEx")));
        assert!(!f.imports_masked(masked!(b"LoadLibraryA")));
        assert!(is_standard_section(""));
        assert!(is_standard_section(".TEXT"));
        assert!(!window_contains(b"ab", b""));
        assert!(!window_contains(b"ab", b"abc"));
    }

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
