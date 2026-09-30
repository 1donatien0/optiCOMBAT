//! Test d'intégration : reproduit le flux exact qu'exécutera `optiCombat.Service`
//! via P/Invoke — scan_path (verdict), scan_json (détails), string_free.
//! Valide le contrat C ABI côté Rust avant tout déploiement de la DLL.

use std::ffi::{CStr, CString};
use std::io::Write;

use opticombat::{
    opticombat_scan_json, opticombat_scan_path, opticombat_string_free, OC_CLEAN, OC_MALICIOUS,
};

fn write_tmp(name: &str, data: &[u8]) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("oc_svc_{}_{}", std::process::id(), name));
    std::fs::File::create(&p).unwrap().write_all(data).unwrap();
    p
}

/// Imite `OptiCombatNative.ScanPath` + `ScanJson` côté service.
fn service_scan(path: &std::path::Path) -> (i32, String) {
    let c = CString::new(path.to_str().unwrap()).unwrap();
    let code = unsafe { opticombat_scan_path(c.as_ptr()) };
    let raw = unsafe { opticombat_scan_json(c.as_ptr()) };
    let json = if raw.is_null() {
        String::new()
    } else {
        let s = unsafe { CStr::from_ptr(raw).to_str().unwrap().to_string() };
        unsafe { opticombat_string_free(raw) }; // contrat de propriété mémoire
        s
    };
    (code, json)
}

#[test]
fn flux_service_eicar_puis_propre() {
    let eicar = write_tmp(
        "eicar.com",
        br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    );
    let (code, json) = service_scan(&eicar);
    assert_eq!(code, OC_MALICIOUS, "json={json}");
    assert!(json.contains("\"verdict\":\"Malicious\""), "json={json}");
    assert!(json.contains("EICAR"), "json={json}");
    let _ = std::fs::remove_file(eicar);

    let clean = write_tmp("clean.txt", b"rapport interne, rien a signaler");
    let (code, json) = service_scan(&clean);
    assert_eq!(code, OC_CLEAN);
    assert!(json.contains("\"verdict\":\"Clean\""));
    let _ = std::fs::remove_file(clean);
}
