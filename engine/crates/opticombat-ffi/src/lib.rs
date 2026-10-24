//! opticombat-ffi — frontière C ABI du cœur moteur (feuille de route : Antivirus API).
//!
//! Expose une API C stable que `optiCombat.Service` (C#) consomme via P/Invoke.
//! Contrat de propriété mémoire explicite :
//!   - les chaînes rendues par la bibliothèque sont libérées par
//!     [`opticombat_string_free`] (jamais par `free` côté appelant) ;
//!   - les chaînes passées en entrée appartiennent à l'appelant.
//!
//! Sûreté : chaque point d'entrée est enveloppé dans `catch_unwind` ; combiné
//! au profil release `panic = "abort"`, aucun panic Rust ne traverse la
//! frontière FFI en comportement indéfini.

use std::ffi::{c_char, c_int, CStr, CString};
use std::panic::catch_unwind;
use std::path::Path;
use std::sync::{Arc, RwLock};

use dispatcher::Dispatcher;
use engine_core::Verdict;

/// Codes de verdict renvoyés par l'ABI (alignés sur les codes de sortie CLI).
pub const OC_CLEAN: c_int = 0;
pub const OC_SUSPICIOUS: c_int = 1;
pub const OC_MALICIOUS: c_int = 2;
pub const OC_ERROR: c_int = -1;

/// Dispatcher partagé, construit au premier appel puis réutilisé : auparavant
/// chaque appel FFI recompilait les automates YARA et sondait clamd.
///
/// Il est remplaçable à chaud par [`opticombat_load_threat_intel`] : les analyses en
/// cours gardent leur `Arc` vers l'ancienne instance, les suivantes voient la nouvelle.
static DISPATCHER: RwLock<Option<Arc<Dispatcher>>> = RwLock::new(None);

fn dispatcher() -> Arc<Dispatcher> {
    if let Some(d) = DISPATCHER
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
    {
        return Arc::clone(d);
    }
    let mut slot = DISPATCHER.write().unwrap_or_else(|e| e.into_inner());
    Arc::clone(slot.get_or_insert_with(|| Arc::new(Dispatcher::new())))
}

fn install_dispatcher(d: Dispatcher) {
    *DISPATCHER.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(d));
}

fn into_c_string(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn verdict_code(v: Verdict) -> c_int {
    match v {
        Verdict::Clean | Verdict::Inconclusive => OC_CLEAN,
        Verdict::Suspicious => OC_SUSPICIOUS,
        Verdict::Malicious => OC_MALICIOUS,
    }
}

/// Convertit un `*const c_char` C en `&str` Rust, ou None si invalide.
///
/// # Safety
/// `path` doit être un pointeur nul ou une chaîne C valide terminée par `\0`.
unsafe fn cstr_to_str<'a>(path: *const c_char) -> Option<&'a str> {
    if path.is_null() {
        return None;
    }
    CStr::from_ptr(path).to_str().ok()
}

/// Scanne un fichier et renvoie un code de verdict (voir `OC_*`).
///
/// # Safety
/// `path` doit pointer vers une chaîne C valide ou être nul.
#[no_mangle]
pub unsafe extern "C" fn opticombat_scan_path(path: *const c_char) -> c_int {
    catch_unwind(|| {
        let Some(p) = cstr_to_str(path) else {
            return OC_ERROR;
        };
        match dispatcher().scan_path(Path::new(p)) {
            Ok(decision) => verdict_code(decision.verdict),
            Err(_) => OC_ERROR,
        }
    })
    .unwrap_or(OC_ERROR)
}

/// Scanne un fichier et renvoie un résultat JSON explicable (verdict, score,
/// détections). La chaîne renvoyée doit être libérée par
/// [`opticombat_string_free`]. Renvoie un pointeur nul en cas d'erreur.
///
/// # Safety
/// `path` doit pointer vers une chaîne C valide ou être nul.
#[no_mangle]
pub unsafe extern "C" fn opticombat_scan_json(path: *const c_char) -> *mut c_char {
    let result = catch_unwind(|| {
        let p = cstr_to_str(path)?;
        let d = dispatcher();
        let decision = d.scan_path(Path::new(p)).ok()?;
        Some(decision_to_json(p, &decision, d.clamd_available()))
    });
    match result {
        Ok(Some(json)) => into_c_string(json),
        _ => std::ptr::null_mut(),
    }
}

/// Charge (ou recharge) la threat intel abuse.ch depuis un dossier local et
/// remplace le dispatcher partagé. Fichiers reconnus : voir `dispatcher::threat_intel`.
///
/// Renvoie le nombre total d'entrées chargées (0 si le dossier ne contient aucun
/// feed exploitable), ou `-1` si `dir` est nul, n'est pas de l'UTF-8 valide ou ne
/// désigne pas un dossier existant (le dispatcher courant est alors conservé).
///
/// # Safety
/// `dir` doit pointer vers une chaîne C valide ou être nul.
#[no_mangle]
pub unsafe extern "C" fn opticombat_load_threat_intel(dir: *const c_char) -> i64 {
    catch_unwind(|| {
        let Some(d) = cstr_to_str(dir) else {
            return -1;
        };
        let path = Path::new(d);
        if !path.is_dir() {
            return -1;
        }
        let next = Dispatcher::with_threat_intel_dir(path);
        let total = next.threat_intel_stats().total() as i64;
        install_dispatcher(next);
        total
    })
    .unwrap_or(-1)
}

/// Compteurs de la threat intel chargée, en JSON :
/// `{"malwarebazaar":N,"urlhaus":N,"threatfox":N,"total":N}`.
/// À libérer par [`opticombat_string_free`].
#[no_mangle]
pub extern "C" fn opticombat_threat_intel_stats() -> *mut c_char {
    catch_unwind(|| dispatcher().threat_intel_stats().to_json())
        .map(into_c_string)
        .unwrap_or(std::ptr::null_mut())
}

/// Libère une chaîne précédemment renvoyée par l'ABI.
///
/// # Safety
/// `s` doit provenir d'une fonction de cette bibliothèque, et ne pas être
/// libéré deux fois.
#[no_mangle]
pub unsafe extern "C" fn opticombat_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Renvoie la version de la bibliothèque (chaîne statique, NE PAS libérer).
#[no_mangle]
pub extern "C" fn opticombat_version() -> *const c_char {
    // Chaîne statique terminée par \0, valide pour toute la durée du programme.
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

fn decision_to_json(target: &str, d: &correlator::FinalDecision, clamd: bool) -> String {
    let mut s = String::new();
    s.push('{');
    s.push_str(&format!("\"target\":\"{}\",", json_escape(target)));
    // false = signatures ClamAV réduites à EICAR (clamd injoignable).
    s.push_str(&format!("\"clamd\":{clamd},"));
    s.push_str(&format!("\"verdict\":\"{:?}\",", d.verdict));
    s.push_str(&format!("\"severity\":\"{}\",", d.severity));
    s.push_str(&format!("\"score\":{},", d.total_score));
    s.push_str("\"detections\":[");
    for (i, det) in d.reasons.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"engine\":\"{}\",\"name\":\"{}\",\"score\":{},\"explanation\":\"{}\"}}",
            json_escape(&det.engine),
            json_escape(&det.name),
            det.score,
            json_escape(&det.explanation),
        ));
    }
    s.push_str("]}");
    s
}

/// Échappement JSON minimal (guillemets, antislash, contrôles).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::io::Write;
    #[cfg(windows)]
    use std::os::windows::fs::OpenOptionsExt;

    #[cfg(windows)]
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    #[cfg(windows)]
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;

    /// Garde le fichier ouvert sans partage de suppression : Defender retire
    /// sinon l'échantillon EICAR avant le scan.
    fn tmp(data: &[u8], ext: &str) -> (std::path::PathBuf, std::fs::File) {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let uid = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("oc_ffi_{}_{}.{ext}", std::process::id(), uid));
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).truncate(true).read(true).write(true);
        #[cfg(windows)]
        opts.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        let mut file = opts.open(&p).unwrap();
        file.write_all(data).unwrap();
        file.flush().unwrap();
        (p, file)
    }

    #[test]
    fn scan_path_eicar_malicious() {
        let (p, hold) = tmp(
            br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
            "com",
        );
        let c = CString::new(p.to_str().unwrap()).unwrap();
        let code = unsafe { opticombat_scan_path(c.as_ptr()) };
        assert_eq!(code, OC_MALICIOUS);
        drop(hold);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn scan_path_null_is_error() {
        let code = unsafe { opticombat_scan_path(std::ptr::null()) };
        assert_eq!(code, OC_ERROR);
    }

    fn ffi_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!(
            "oc_ffi_ti_{tag}_{}_{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn take_string(raw: *mut c_char) -> String {
        assert!(!raw.is_null());
        let s = unsafe { CStr::from_ptr(raw).to_str().unwrap().to_string() };
        unsafe { opticombat_string_free(raw) };
        s
    }

    #[test]
    fn load_threat_intel_refuse_les_entrees_invalides() {
        assert_eq!(
            unsafe { opticombat_load_threat_intel(std::ptr::null()) },
            -1
        );
        let missing = CString::new("/oc/dossier/inexistant").unwrap();
        assert_eq!(
            unsafe { opticombat_load_threat_intel(missing.as_ptr()) },
            -1
        );
        let bad = [0xffu8, 0xfe, 0x00];
        assert_eq!(
            unsafe { opticombat_load_threat_intel(bad.as_ptr() as *const c_char) },
            -1
        );
    }

    #[test]
    fn load_threat_intel_detecte_un_hash_malwarebazaar() {
        let payload = b"echantillon ffi malwarebazaar opticombat";
        let sha = reputation_sha256(payload);
        let dir = ffi_dir("mb");
        std::fs::write(dir.join("malwarebazaar_sha256.txt"), format!("{sha}\n")).unwrap();
        let c = CString::new(dir.to_str().unwrap()).unwrap();
        let total = unsafe { opticombat_load_threat_intel(c.as_ptr()) };
        assert!(total >= 1, "total = {total}");

        let stats = take_string(opticombat_threat_intel_stats());
        assert!(stats.starts_with("{\"malwarebazaar\":"), "{stats}");

        let (p, hold) = tmp(payload, "bin");
        let cp = CString::new(p.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { opticombat_scan_path(cp.as_ptr()) }, OC_MALICIOUS);
        let json = take_string(unsafe { opticombat_scan_json(cp.as_ptr()) });
        assert!(json.contains("MalwareBazaar:Malware"), "{json}");
        drop(hold);
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn load_threat_intel_dossier_vide_renvoie_zero() {
        let dir = ffi_dir("empty");
        let c = CString::new(dir.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { opticombat_load_threat_intel(c.as_ptr()) }, 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn version_et_json_escape() {
        let v = unsafe { CStr::from_ptr(opticombat_version()) }
            .to_str()
            .unwrap();
        assert_eq!(v, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            json_escape("a\"b\\c\n\r\t\u{1}"),
            "a\\\"b\\\\c\\n\\r\\t\\u0001"
        );
        unsafe { opticombat_string_free(std::ptr::null_mut()) };
    }

    #[test]
    fn scan_json_null_et_chemin_absent() {
        assert!(unsafe { opticombat_scan_json(std::ptr::null()) }.is_null());
        let missing = CString::new("/oc/fichier/absent.bin").unwrap();
        assert!(unsafe { opticombat_scan_json(missing.as_ptr()) }.is_null());
        assert_eq!(unsafe { opticombat_scan_path(missing.as_ptr()) }, OC_ERROR);
    }

    #[test]
    fn verdict_code_couvre_tous_les_verdicts() {
        assert_eq!(verdict_code(Verdict::Clean), OC_CLEAN);
        assert_eq!(verdict_code(Verdict::Inconclusive), OC_CLEAN);
        assert_eq!(verdict_code(Verdict::Suspicious), OC_SUSPICIOUS);
        assert_eq!(verdict_code(Verdict::Malicious), OC_MALICIOUS);
    }

    fn reputation_sha256(data: &[u8]) -> String {
        reputation::ReputationEngine::sha256_hex(data)
    }

    #[test]
    fn scan_json_contient_verdict() {
        let (p, hold) = tmp(b"document parfaitement normal", "txt");
        let c = CString::new(p.to_str().unwrap()).unwrap();
        let raw = unsafe { opticombat_scan_json(c.as_ptr()) };
        assert!(!raw.is_null());
        let json = unsafe { CStr::from_ptr(raw).to_str().unwrap().to_string() };
        unsafe { opticombat_string_free(raw) };
        assert!(json.contains("\"verdict\":\"Clean\""), "{json}");
        drop(hold);
        let _ = std::fs::remove_file(p);
    }
}
