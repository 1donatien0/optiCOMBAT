#![no_main]
//! Fuzz du parseur PE : aucune entrée ne doit provoquer de panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pe_analysis::analyze_bytes(data);
});
