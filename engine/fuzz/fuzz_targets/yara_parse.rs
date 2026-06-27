#![no_main]
//! Fuzz du parseur de règles YARA : aucune entrée ne doit provoquer de panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = yara_engine::parse_rules(text);
    }
});
