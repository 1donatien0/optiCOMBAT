//! opticombat-ffi — frontière C ABI du cœur moteur (feuille de route : Antivirus API).
//!
//! Expose une API C stable que `optiCombat.Service` (C#) consomme via P/Invoke,
//! sans réécrire l'UI WPF. Contrat de propriété mémoire explicite :
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

use dispatcher::Dispatcher;
use engine_core::Verdict;

/// Codes de verdict renvoyés par l'ABI (alignés sur les codes de sortie CLI).
pub const OC_CLEAN: c_int = 0;
pub const OC_SUSPICIOUS: c_int = 1;
pub const OC_MALICIOUS: c_int = 2;
pub const OC_ERROR: c_int = -1;

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
        match Dispatcher::new().scan_path(Path::new(p)) {
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
        let decision = Dispatcher::new().scan_path(Path::new(p)).ok()?;
        Some(decision_to_json(p, &decision))
    });
    match result {
        Ok(Some(json)) => match CString::new(json) {
            Ok(c) => c.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        _ => std::ptr::null_mut(),
    }
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

fn decision_to_json(target: &str, d: &correlator::FinalDecision) -> String {
    let mut s = String::new();
    s.push('{');
    s.push_str(&format!("\"target\":\"{}\",", json_escape(target)));
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

    fn tmp(data: &[u8], ext: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let uid = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("oc_ffi_{}_{}.{ext}", std::process::id(), uid));
        std::fs::File::create(&p).unwrap().write_all(data).unwrap();
        p
    }

    #[test]
    fn scan_path_eicar_malicious() {
        let p = tmp(
            br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
            "com",
        );
        let c = CString::new(p.to_str().unwrap()).unwrap();
        let code = unsafe { opticombat_scan_path(c.as_ptr()) };
        assert_eq!(code, OC_MALICIOUS);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn scan_path_null_is_error() {
        let code = unsafe { opticombat_scan_path(std::ptr::null()) };
        assert_eq!(code, OC_ERROR);
    }

    #[test]
    fn scan_json_contient_verdict() {
        let p = tmp(b"document parfaitement normal", "txt");
        let c = CString::new(p.to_str().unwrap()).unwrap();
        let raw = unsafe { opticombat_scan_json(c.as_ptr()) };
        assert!(!raw.is_null());
        let json = unsafe { CStr::from_ptr(raw).to_str().unwrap().to_string() };
        unsafe { opticombat_string_free(raw) };
        assert!(json.contains("\"verdict\":\"Clean\""), "{json}");
        let _ = std::fs::remove_file(p);
    }
}
