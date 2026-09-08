// fuzz/fuzz_targets/parse_pss_parameters.rs
//
// Fuzz the RSASSA-PSS-params parser (RFC 4055 §3.1): the nested
// AlgorithmIdentifiers of the two hashes, the MGF1 OID, and the small
// INTEGER decoding behind saltLength and trailerField. `Ok` or `Err` are
// both fine; a panic is a bug.

#![no_main]

use certinfo::PssParameters;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = PssParameters::parse(Some(data));
});
